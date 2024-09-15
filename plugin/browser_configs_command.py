import os

import sublime
import sublime_plugin

from ..core import ASSETS_DIRECTORY, CONFIG


class BrowserConfigsCommand(sublime_plugin.WindowCommand):
    def run(self):
        seen = set()

        config_dir = os.path.join(sublime.packages_path(), 'User', ASSETS_DIRECTORY, 'config')
        if os.path.isdir(config_dir):
            self.window.run_command('open_dir', {'dir': config_dir})
            seen.add(config_dir)

        for formatter in CONFIG.get('formatters', {}).values():
            for path in formatter.get('config_path', {}).values():
                if path and isinstance(path, str):
                    dir_path = os.path.dirname(path)
                    if os.path.isdir(dir_path) and dir_path not in seen:
                        self.window.run_command('open_dir', {'dir': dir_path})
                        seen.add(dir_path)
