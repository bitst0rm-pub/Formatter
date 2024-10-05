import sublime
import sublime_plugin

from ..core import (CONFIG, PACKAGE_NAME, ConfigHandler, LayoutHandler,
                    OptionHandler, log, reload_modules)
from . import DirFormat, SavePasteManager, sync_scroll_manager


class FormatterListener(sublime_plugin.EventListener):
    def on_load(self, view):
        if view == DirFormat.CONTEXT['new_view']:
            try:
                with DirFormat(view=view) as dir_format:
                    dir_format.format_next_file(view, is_ready=False)
            except Exception as e:
                log.error('Error during dir formatting: %s', e)

        file_path = view.file_name()
        if file_path and file_path.endswith(PACKAGE_NAME + '.sublime-settings'):
            view.run_command('collapse_setting_sections')

    def on_activated(self, view):
        ConfigHandler.project_config_overwrites_config()

        if OptionHandler.query(CONFIG, False, 'layout', 'sync_scroll') and LayoutHandler.want_layout():
            sync_scroll_manager.stop_sync_scroll()

            src_view = self._find_view_by_reference(view, lookup_src=False)
            if src_view:
                sync_scroll_manager.start_sync_scroll('src', view, src_view)
            else:
                dst_view = self._find_view_by_reference(view, lookup_src=True)
                if dst_view:
                    sync_scroll_manager.start_sync_scroll('dst', view, dst_view)

    @staticmethod
    def _find_view_by_reference(view, lookup_src=True):
        view_id = view.id() if lookup_src else view.settings().get('txt_vref')

        if view_id:
            for window in sublime.windows():
                for v in window.views():
                    if (v.settings().get('txt_vref') == view_id) if lookup_src else (v.id() == view_id):
                        return v
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
