import threading

import sublime_plugin

from ..core import (CONFIG, CleanupHandler, ConfigHandler, InterfaceHandler,
                    OptionHandler, ViewHandler, log)
from .dir_format import DirFormat
from .file_format import FileFormat


class RunFormatCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        CleanupHandler.clear_console()

        is_recursive = self.is_dir_format_enabled(kwargs.get('uid', None))
        if is_recursive:
            if kwargs.get('type', None) == 'graphic':
                log.info('Recursive formatting is not supported for plugins of type: graphic')
            else:
                self.run_dir_format(**kwargs)
        else:
            self.run_file_format(**kwargs)

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self, **kwargs):
        ConfigHandler.set_debug_mode()
        return self.is_plugin_enabled(kwargs.get('uid', None))

    def is_plugin_enabled(self, uid):
        if not ViewHandler(view=self.view).is_view_formattable():
            return False

        formatter = OptionHandler.query(CONFIG, {}, 'formatters', uid)
        if 'disable' in formatter and not formatter.get('disable', True):
            return True
        elif 'enable' in formatter and formatter.get('enable', False):
            return True
        else:
            return False

    def is_dir_format_enabled(self, uid):
        if ConfigHandler.is_quick_options_mode():
            return OptionHandler.query(CONFIG, False, 'quick_options', 'recursive_folder_format')
        else:
            return OptionHandler.query(CONFIG, False, 'formatters', uid, 'recursive_folder_format', 'enable')

    def run_dir_format(self, **kwargs):
        if self.view.file_name():
            with threading.Lock():
                log.debug('Starting dir formatting ...')
                dir_format = DirFormat(self.view, **kwargs)
                dir_format_thread = threading.Thread(target=dir_format.run)
                dir_format_thread.start()
        else:
            InterfaceHandler.popup_message('Please save the file first. Recursive folder formatting requires an existing file on disk, which must be opened as the starting point.', 'ERROR')

    def run_file_format(self, **kwargs):
        with threading.Lock():
            log.debug('Starting file formatting ...')
            file_format = FileFormat(self.view, **kwargs)
            file_format_thread = threading.Thread(target=file_format.run)
            file_format_thread.start()
