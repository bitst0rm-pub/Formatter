import threading

import sublime_plugin

from ..core import (CONFIG, CleanupHandler, ConfigHandler, DotFileHandler,
                    OptionHandler, log)
from .file_format import FileFormat


class AutoFormatFileCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        CleanupHandler.clear_console()

        auto_format_args = DotFileHandler.get_auto_format_args(view=self.view)
        if auto_format_args:
            log.debug('Starting auto formatting ...')
            file_format_thread = threading.Thread(target=self._run_file_format, args=(auto_format_args,))
            file_format_thread.start()

    def _run_file_format(self, auto_format_args):
        try:
            with FileFormat(view=self.view, **auto_format_args) as file_format:
                file_format.run()
        except Exception as e:
            log.error('Error occurred in formatting thread: %s', e)

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self):
        ConfigHandler.set_debug_mode()
        auto_format = OptionHandler.query(CONFIG, {}, 'auto_format').copy()
        auto_format.pop('config', None)
        return bool(auto_format) or bool(DotFileHandler.get_auto_format_config(view=self.view))
