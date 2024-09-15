import os
import threading
import time

import sublime
import sublime_plugin

from ..core import (AUTO_FORMAT_ACTION_KEY, CONFIG, PACKAGE_NAME,
                    CleanupHandler, ConfigHandler, DotFileHandler,
                    InterfaceHandler, LayoutHandler, OptionHandler,
                    SyntaxHandler, TransformHandler, log, reload_modules)
from . import DirFormat, FileFormat


class SyncScrollManager:
    def __init__(self):
        self.running = False
        self.thread = None
        self.lock = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_sync_scroll()

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
        try:
            while self.running:
                # log.debug('Sync scroll target: %s', target_type)
                target_view.set_viewport_position(active_view.viewport_position(), False)
                time.sleep(0.25)
        except Exception as e:
            log.error('Error during sync_scroll: %s', e)
        finally:
            self.stop_sync_scroll()


sync_scroll_manager = SyncScrollManager()


class SavePasteManager:
    @classmethod
    def apply_formatting(cls, view=None, action=None):
        file_path = view.file_name()
        if file_path and os.path.splitext(file_path)[1] in ['.sublime-settings']:
            return

        if cls._on_auto_format(view=view, file_path=file_path, actkey=action):
            return

        cls._on_paste_or_save(view=view, actkey=action)

    @classmethod
    def _on_auto_format(cls, view=None, file_path=None, actkey=None):
        get_auto_format_args = DotFileHandler.get_auto_format_args(view=view, active_file_path=file_path)
        x = get_auto_format_args['auto_format_config']
        config = x.get('config', {})
        if config and not cls._should_skip(config.get(actkey, False)):
            config.update({AUTO_FORMAT_ACTION_KEY: actkey})
            CleanupHandler.clear_console()

            log.debug('"%s" (autoformat)', actkey)
            try:
                with FileFormat(view=view, **get_auto_format_args) as file_format:
                    file_format.run()
                return True
            except Exception as e:
                log.error('Error occurred while auto formatting: %s', e)

        return False

    @classmethod
    def _on_paste_or_save(cls, view=None, actkey=None):
        if not actkey:
            return None

        unique = OptionHandler.query(CONFIG, {}, 'format_on_priority') or OptionHandler.query(CONFIG, {}, 'format_on_unique')
        if unique and isinstance(unique, dict) and unique.get('enable', False):
            cls._on_paste_or_save__unique(view=view, unique=unique, actkey=actkey)
        else:
            cls._on_paste_or_save__regular(view=view, actkey=actkey)

    @classmethod
    def _on_paste_or_save__unique(cls, view=None, unique=None, actkey=None):
        def are_unique_values(unique=None):
            flat_values = [value for key, values_list in unique.items() if key != 'enable' for value in values_list]
            return (len(flat_values) == len(set(flat_values)))

        formatters = OptionHandler.query(CONFIG, {}, 'formatters')

        if are_unique_values(unique=unique):
            for uid, value in unique.items():
                if uid == 'enable':
                    continue

                val = OptionHandler.query(formatters, None, uid)
                if not cls._should_skip_formatter(view=view, uid=uid, value=val, actkey=actkey):
                    syntax = cls._get_syntax(view=view, uid=uid)
                    if cls._should_skip_syntaxes(value=val, syntax=syntax, actkey=actkey):
                        continue
                    if syntax in value:
                        CleanupHandler.clear_console()

                        log.debug('"%s" (priority)', actkey)
                        try:
                            with FileFormat(view=view, uid=uid, type=value.get('type', None)) as file_format:
                                file_format.run()
                        except Exception as e:
                            log.error('Error occurred while priority formatting: %s', e)
                        finally:
                            break
        else:
            InterfaceHandler.popup_message('There are duplicate syntaxes in your "format_on_priority" option. Please sort them out.', 'ERROR')

    @classmethod
    def _on_paste_or_save__regular(cls, view=None, actkey=None):
        seen = set()
        formatters = OptionHandler.query(CONFIG, {}, 'formatters')

        for uid, value in formatters.items():
            if not cls._should_skip_formatter(view=view, uid=uid, value=value, actkey=actkey):
                syntax = cls._get_syntax(view=view, uid=uid)
                if cls._should_skip_syntaxes(value=value, syntax=syntax, actkey=actkey):
                    continue
                if syntax in value.get('syntaxes', []) and syntax not in seen:
                    CleanupHandler.clear_console()

                    log.debug('"%s" (regular)', actkey)
                    try:
                        with FileFormat(view=view, uid=uid, type=value.get('type', None)) as file_format:
                            file_format.run()
                    except Exception as e:
                        log.error('Error occurred while regular formatting: %s', e)
                    finally:
                        seen.add(syntax)

    @staticmethod
    def _should_skip_syntaxes(value=None, syntax=None, actkey=None):
        actkey_value = value.get(actkey, None)
        if isinstance(actkey_value, dict):
            return syntax in actkey_value.get('exclude_syntaxes', [])
        return False

    @classmethod
    def _should_skip_formatter(cls, view=None, uid=None, value=None, actkey=None):
        if not isinstance(value, dict):
            return True

        if ('disable' in value and value.get('disable', True)) or ('enable' in value and not value.get('enable', False)):
            return True

        is_qo_mode = ConfigHandler.is_quick_options_mode()
        is_rff_on = OptionHandler.query(CONFIG, False, 'quick_options', 'dir_format')

        if is_qo_mode:
            if uid not in OptionHandler.query(CONFIG, [], 'quick_options', actkey):
                return True

            if is_rff_on:
                log.info('Quick Options mode: %s has the "%s" option enabled, which is incompatible with "dir_format" mode.', uid, actkey)
                return True
        else:
            if cls._should_skip(view=view, value=value.get(actkey, False)):
                return True

            if OptionHandler.query(value, False, 'dir_format', 'enable'):
                log.info('User Settings mode: %s has the "%s" option enabled, which is incompatible with "dir_format" mode.', uid, actkey)
                return True

        return False

    @classmethod
    def _should_skip(cls, view=None, value=None):
        if isinstance(value, bool):
            return not value

        if isinstance(value, dict):
            return cls._should_exclude(view=view, value=value)

        return False

    @staticmethod
    def _should_exclude(view=None, value=None):
        file_path = view.file_name()

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

    @staticmethod
    def _get_syntax(view=None, uid=None):
        is_selected = any(not sel.empty() for sel in view.sel())

        if is_selected:
            # Selections: find the first non-empty region or use the first region if all are empty
            region = next((region for region in view.sel() if not region.empty()), view.sel()[0])
        else:
            # Entire view
            region = sublime.Region(0, view.size())

        uid, syntax = SyntaxHandler.get_assigned_syntax(view=view, uid=uid, region=region, auto_format_config=None)
        return syntax


class FormatterListener(sublime_plugin.EventListener):
    def on_load(self, view):
        if view == DirFormat.CONTEXT['new_view']:
            try:
                with DirFormat(view=view) as dir_format:
                    dir_format.format_next_file(view, is_ready=False)
            except Exception as e:
                log.error('Error occurred while dir formatting: %s', e)

        file_path = view.file_name()
        if file_path and file_path.endswith(PACKAGE_NAME + '.sublime-settings'):
            view.run_command('collapse_setting_sections')

    def on_activated(self, view):
        ConfigHandler.project_config_overwrites_config()

        if OptionHandler.query(CONFIG, False, 'layout', 'sync_scroll') and LayoutHandler.want_layout():
            sync_scroll_manager.stop_sync_scroll()

            src_view = self._find_src_view_by_dst_view(view)
            if src_view:
                sync_scroll_manager.start_sync_scroll('src', view, src_view)
            else:
                dst_view = self._find_dst_view_by_src_view(view)
                if dst_view:
                    sync_scroll_manager.start_sync_scroll('dst', view, dst_view)

    @staticmethod
    def _find_src_view_by_dst_view(dst_view):
        src_view_id = dst_view.settings().get('txt_vref')
        if src_view_id:
            for window in sublime.windows():
                for view in window.views():
                    if view.id() == src_view_id:
                        return view
        return None

    @staticmethod
    def _find_dst_view_by_src_view(src_view):
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
        # Stop action with arrow keys (up, down, left, right)
        if command_name == 'move' and args.get('by', None) in ['characters', 'lines']:
            DirFormat.stop()

        if command_name in ['paste', 'paste_and_indent']:
            SavePasteManager.apply_formatting(view=view, action='format_on_paste')
            return None

    def on_pre_save(self, view):
        SavePasteManager.apply_formatting(view=view, action='format_on_save')

    def on_post_save(self, view):
        if OptionHandler.query(CONFIG, False, 'debug') and OptionHandler.query(CONFIG, False, 'dev'):
            # For development only
            sync_scroll_manager.stop_sync_scroll()
            reload_modules(print_tree=False)
