import threading

import sublime_plugin

from ..core import (CONFIG, MAX_CHAIN_PLUGINS, CleanupHandler, ConfigHandler,
                    DataHandler, DotFileHandler, OptionHandler, log)
from .file_format import FileFormat


class AutoFormatFileCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        CleanupHandler.clear_console()

        auto_format_args = DotFileHandler.get_auto_format_args(view=self.view)
        if auto_format_args:
            log.debug('Starting auto formatting ...')
            threading.Thread(target=self._run_file_format, args=(auto_format_args,)).start()

    def _run_file_format(self, auto_format_args):
        FileFormat.reset_status()
        try:
            afc = auto_format_args['auto_format_config']

            for i in range(MAX_CHAIN_PLUGINS):
                is_non_empty = self._process_plugin_chain(afc)

                if not is_non_empty:
                    # For handle_text_formatting() in new_file_on_format mode
                    FileFormat.set_auto_format_finished()

                if i > 0 and not is_non_empty:  # > 0 for "plugin" or ["plugin"]
                    break  # finished

                with FileFormat(view=self.view, **auto_format_args) as file_format:
                    file_format.run()

            DataHandler.reset('__auto_format_chain_item__')
        except Exception as e:
            log.error('Error during auto formatting: %s', e)

    @staticmethod
    def _process_plugin_chain(afc):
        syntax, uid = DataHandler.get('__auto_format_chain_item__')
        if not (syntax and uid):  # De Morgan's laws
            return False  # no match found

        if not isinstance(afc.get(syntax), list):
            return False  # not type chain

        # Remove the consumed uid until the chain list is empty
        afc[syntax] = [item for item in afc[syntax] if item != uid]

        return bool(afc[syntax])  # the chain list is now empty

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self):
        ConfigHandler.set_debug_mode()
        auto_format = OptionHandler.query(CONFIG, {}, 'auto_format')
        is_non_empty = len(auto_format) > (1 if 'config' in auto_format else 0)
        return is_non_empty or bool(DotFileHandler.get_auto_format_config(view=self.view))
