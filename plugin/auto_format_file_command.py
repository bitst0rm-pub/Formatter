import threading

import sublime_plugin

from ..core import (CONFIG, CleanupHandler, ConfigHandler, DotFileHandler,
                    OptionHandler, log)
from .single_format import SingleFormat


class AutoFormatFileCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        CleanupHandler.clear_console()

        auto_format_args = DotFileHandler(view=self.view).get_auto_format_args()
        if auto_format_args:
            with threading.Lock():
                log.debug('Starting auto formatting ...')
                single_format = SingleFormat(self.view, **auto_format_args)
                single_format_thread = threading.Thread(target=single_format.run)
                single_format_thread.start()

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self):
        ConfigHandler.set_debug_mode()
        return bool(DotFileHandler(view=self.view).get_auto_format_config()) or bool(OptionHandler.query(CONFIG, {}, 'auto_format'))
