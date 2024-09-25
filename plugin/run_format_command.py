import threading

import sublime_plugin

from ..core import (CONFIG, CleanupHandler, ConfigHandler, InterfaceHandler,
                    OptionHandler, ViewHandler, log)
from .dir_format import DirFormat
from .file_format import FileFormat


class RunFormatCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        CleanupHandler.clear_console()

        is_df_enabled = self.is_dir_format_enabled(kwargs.get('uid', None))
        if is_df_enabled:
            if kwargs.get('type', None) == 'graphic':
                log.info('Dir formatting is not supported for plugins of type: graphic')
            else:
                self.run_dir_format_thread(**kwargs)
        else:
            self.run_file_format_thread(**kwargs)

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self, **kwargs):
        ConfigHandler.set_debug_mode()
        return self.is_plugin_enabled(kwargs.get('uid', None))

    def is_plugin_enabled(self, uid):
        if not ViewHandler.is_view_formattable(view=self.view):
            return False

        formatter = OptionHandler.query(CONFIG, {}, 'formatters', uid)
        if 'disable' in formatter and not formatter.get('disable', True):
            return True
        elif 'enable' in formatter and formatter.get('enable', False):
            return True
        else:
            return False

    @staticmethod
    def is_dir_format_enabled(uid):
        value = OptionHandler.query(CONFIG, False, 'formatters', uid, 'dir_format')
        if ConfigHandler.is_quick_options_mode():
            qo_value = OptionHandler.query(CONFIG, False, 'quick_options', 'dir_format')
            if qo_value and isinstance(value, dict):
                return any(value.values())
            else:
                return qo_value
        else:
            if isinstance(value, bool):
                return value

            if isinstance(value, dict):
                return any(value.values())

    def run_dir_format_thread(self, **kwargs):
        if self.view.file_name():
            log.debug('Starting dir formatting ...')
            threading.Thread(target=self._run_dir_format, args=(kwargs,)).start()
        else:
            InterfaceHandler.popup_message('Please save the file first. Dir formatting requires an existing file, which must be opened as the starting point.', 'ERROR')

    def _run_dir_format(self, kwargs):
        try:
            with DirFormat(view=self.view, **kwargs) as dir_format:
                dir_format.run()
        except Exception as e:
            log.error('Error during dir formatting: %s', e)

    def run_file_format_thread(self, **kwargs):
        log.debug('Starting file formatting ...')
        threading.Thread(target=self._run_file_format, args=(kwargs,)).start()

    def _run_file_format(self, kwargs):
        try:
            with FileFormat(view=self.view, **kwargs) as file_format:
                file_format.run()
        except Exception as e:
            log.error('Error during file formatting: %s', e)
