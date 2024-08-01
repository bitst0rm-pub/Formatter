import threading

import sublime_plugin

from ..core import (CONFIG, CleanupHandler, ConfigHandler, DotFileHandler,
                    OptionHandler, log)
from .file_format import FileFormat


class AutoFormatFileCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        CleanupHandler.clear_console()

        auto_format_args = DotFileHandler(view=self.view).get_auto_format_args()
        if auto_format_args:
            with threading.Lock():
                log.debug('Starting auto formatting ...')
                file_format = FileFormat(self.view, **auto_format_args)
                file_format_thread = threading.Thread(target=file_format.run)
                file_format_thread.start()

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self):
        ConfigHandler.set_debug_mode()
        return bool(DotFileHandler(view=self.view).get_auto_format_config()) or bool(OptionHandler.query(CONFIG, {}, 'auto_format'))
