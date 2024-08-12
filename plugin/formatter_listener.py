import os
import threading
import time

import sublime
import sublime_plugin

from ..core import (CONFIG, CleanupHandler, ConfigHandler, DotFileHandler,
                    InterfaceHandler, LayoutHandler, OptionHandler,
                    SyntaxHandler, TransformHandler, log, reload_modules)
from ..core.constants import PACKAGE_NAME
from . import DirFormat, FileFormat


class SyncScrollManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.thread = None

    def start_sync_scroll(self, target_type, active_view, target_view):
        with self.lock:
            if not self.running:
                self.running = True
                self.thread = threading.Thread(
                    target=self.sync_scroll, args=(target_type, active_view, target_view)
                )
                self.thread.start()

    def stop_sync_scroll(self):
        with self.lock:
            self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=0.4)
                if self.thread.is_alive():
                    self.thread = None

    def sync_scroll(self, target_type, active_view, target_view):
        while self.running:
            # log.debug('Sync scroll target: %s', target_type)
            target_view.set_viewport_position(active_view.viewport_position(), False)
            time.sleep(0.25)

    def __del__(self):
        self.stop_sync_scroll()


class SavePasteManager:
    def __init__(self, view):
        self.view = view

    def apply_formatting(self, operation):
        file_path = self.view.file_name()
        if file_path and os.path.splitext(file_path)[1] in ['.sublime-settings']:
            return

        if self._on_auto_format(file_path, opkey=operation):
            return

        self._on_paste_or_save(opkey=operation)

    def _on_auto_format(self, file_path, opkey=None):
        get_auto_format_args = DotFileHandler(view=self.view).get_auto_format_args(active_file_path=file_path)
        x = get_auto_format_args['auto_format_config']
        config = x.get('config', {})
        if config and not self._should_skip(config.get(opkey, False)):
            config.update(__operation__=opkey)
            CleanupHandler.clear_console()

            log.debug('"%s" (autoformat)', opkey)
            FileFormat(self.view, **get_auto_format_args).run()
            return True

        return False

    def _on_paste_or_save(self, opkey=None):
        if not opkey:
            return None

        unique = OptionHandler.query(CONFIG, {}, 'format_on_priority') or OptionHandler.query(CONFIG, {}, 'format_on_unique')
        if unique and isinstance(unique, dict) and unique.get('enable', False):
            self._on_paste_or_save__unique(unique, opkey)
        else:
            self._on_paste_or_save__regular(opkey)

    def _on_paste_or_save__unique(self, unique, opkey):
        def are_unique_values(unique):
            flat_values = [value for key, values_list in unique.items() if key != 'enable' for value in values_list]
            return (len(flat_values) == len(set(flat_values)))

        formatters = OptionHandler.query(CONFIG, {}, 'formatters')

        if are_unique_values(unique):
            for uid, value in unique.items():
                if uid == 'enable':
                    continue

                v = OptionHandler.query(formatters, None, uid)
                if not self._should_skip_formatter(uid, v, opkey):
                    syntax = self._get_syntax(uid)
                    if self._should_skip_syntaxes(v, opkey, syntax):
                        continue
                    if syntax in value:
                        CleanupHandler.clear_console()

                        log.debug('"%s" (priority)', opkey)
                        FileFormat(view=self.view, uid=uid, type=value.get('type', None)).run()
                        break
        else:
            InterfaceHandler.popup_message('There are duplicate syntaxes in your "format_on_priority" option. Please sort them out.', 'ERROR')

    def _on_paste_or_save__regular(self, opkey):
        seen = set()
        formatters = OptionHandler.query(CONFIG, {}, 'formatters')

        for uid, value in formatters.items():
            if not self._should_skip_formatter(uid, value, opkey):
                syntax = self._get_syntax(uid)
                if self._should_skip_syntaxes(value, opkey, syntax):
                    continue
                if syntax in value.get('syntaxes', []) and syntax not in seen:
                    CleanupHandler.clear_console()

                    log.debug('"%s" (regular)', opkey)
                    FileFormat(view=self.view, uid=uid, type=value.get('type', None)).run()
                    seen.add(syntax)

    def _should_skip_syntaxes(self, value, opkey, syntax):
        opkey_value = value.get(opkey, None)
        if isinstance(opkey_value, dict):
            return syntax in opkey_value.get('exclude_syntaxes', [])
        return False

    def _should_skip_formatter(self, uid, value, opkey):
        if not isinstance(value, dict):
            return True

        if ('disable' in value and value.get('disable', True)) or ('enable' in value and not value.get('enable', False)):
            return True

        is_qo_mode = ConfigHandler.is_quick_options_mode()
        is_rff_on = OptionHandler.query(CONFIG, False, 'quick_options', 'dir_format')

        if is_qo_mode:
            if uid not in OptionHandler.query(CONFIG, [], 'quick_options', opkey):
                return True

            if is_rff_on:
                log.info('Quick Options mode: %s has the "%s" option enabled, which is incompatible with "dir_format" mode.', uid, opkey)
                return True
        else:
            if self._should_skip(value.get(opkey, False)):
                return True

            if OptionHandler.query(value, False, 'dir_format', 'enable'):
                log.info('User Settings mode: %s has the "%s" option enabled, which is incompatible with "dir_format" mode.', uid, opkey)
                return True

        return False

    def _should_skip(self, value):
        if isinstance(value, bool):
            return not value

        if isinstance(value, dict):
            return self._should_exclude(value)

        return False

    def _should_exclude(self, value):
        file_path = self.view.file_name()

        if file_path:
            dir_path = os.path.dirname(file_path)
            extension = os.path.splitext(os.path.basename(file_path))[1].lstrip('.').lower()

            exclude_dirs_regex_compiled = TransformHandler.compile_regex_patterns(value.get('exclude_dirs_regex', []))
            exclude_files_regex_compiled = TransformHandler.compile_regex_patterns(value.get('exclude_files_regex', []))
            exclude_extensions_regex_compiled = TransformHandler.compile_regex_patterns(value.get('exclude_extensions_regex', []))

            if any(pattern.match(dir_path) for pattern in exclude_dirs_regex_compiled):
                return True

            if any(pattern.match(file_path) for pattern in exclude_files_regex_compiled):
                return True

            if any(pattern.match(extension) for pattern in exclude_extensions_regex_compiled):
                return True

        return False

    def _get_syntax(self, uid):
        is_selected = any(not sel.empty() for sel in self.view.sel())

        if is_selected:
            # Selections: find the first non-empty region or use the first region if all are empty
            region = next((region for region in self.view.sel() if not region.empty()), self.view.sel()[0])
        else:
            # Entire file
            region = sublime.Region(0, self.view.size())

        uid, syntax = SyntaxHandler(view=self.view, uid=uid, region=region, auto_format_config=None).get_assigned_syntax(view=self.view, uid=uid, region=region)
        return syntax


class FormatterListener(sublime_plugin.EventListener):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sync_scroll_manager = SyncScrollManager()

    def on_load(self, view):
        if view == DirFormat.CONTEXT['new_view']:
            DirFormat(view).format_next_file(view, is_ready=False)

        if view.file_name() and view.file_name().endswith(PACKAGE_NAME + '.sublime-settings'):
            view.run_command('collapse_setting_sections')

    def on_activated(self, view):
        ConfigHandler.project_config_overwrites_config()

        if OptionHandler.query(CONFIG, False, 'layout', 'sync_scroll') and LayoutHandler.want_layout():
            self.sync_scroll_manager.stop_sync_scroll()

            src_view = self._find_src_view_by_dst_view(view)
            if src_view:
                self.sync_scroll_manager.start_sync_scroll('src', view, src_view)
            else:
                dst_view = self._find_dst_view_by_src_view(view)
                if dst_view:
                    self.sync_scroll_manager.start_sync_scroll('dst', view, dst_view)

    def _find_src_view_by_dst_view(self, dst_view):
        src_view_id = dst_view.settings().get('txt_vref')
        if src_view_id:
            for window in sublime.windows():
                for view in window.views():
                    if view.id() == src_view_id:
                        return view
        return None

    def _find_dst_view_by_src_view(self, src_view):
        src_view_id = src_view.id()
        for window in sublime.windows():
            for view in window.views():
                if view.settings().get('txt_vref') == src_view_id:
                    return view
        return None

    def on_pre_close(self, view):
        def _set_single_layout(window, view):
            # Auto-switch to single layout upon closing the latest view
            group, _ = window.get_view_index(view)
            if len(window.views_in_group(group)) == 1:
                sublime.set_timeout(lambda: window.set_layout(LayoutHandler.assign_layout('single')), 0)

        window = view.window()
        if window and LayoutHandler.want_layout() and window.num_groups() == 2:
            _set_single_layout(window, view)

    def on_post_text_command(self, view, command_name, args):
        # Stop action triggered by the arrow keys on the keyboard (up, down, left, right)
        if command_name == 'move' and args.get('by', None) in ['characters', 'lines']:
            DirFormat(view).stop()

        if command_name in ['paste', 'paste_and_indent']:
            SavePasteManager(view).apply_formatting('format_on_paste')
            return None

    def on_pre_save(self, view):
        SavePasteManager(view).apply_formatting('format_on_save')

    def on_post_save(self, view):
        if OptionHandler.query(CONFIG, False, 'debug') and OptionHandler.query(CONFIG, False, 'dev'):
            # For development only
            self.sync_scroll_manager.stop_sync_scroll()
            reload_modules(print_tree=False)
