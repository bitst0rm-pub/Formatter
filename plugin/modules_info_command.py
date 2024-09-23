import os

import sublime
import sublime_plugin

from ..core import PACKAGE_NAME, log


class ModulesInfoCommand(sublime_plugin.WindowCommand):
    @staticmethod
    def get_file_path():
        return os.path.join(sublime.packages_path(), PACKAGE_NAME, 'modules', '_summary.txt')

    def is_enabled(self):
        return os.path.exists(self.get_file_path())

    def is_visible(self):
        return self.is_enabled()

    def run(self):
        file_path = self.get_file_path()
        if os.path.exists(file_path):
            view = sublime.active_window().open_file(file_path)
            view.settings().set('word_wrap', False)
        else:
            log.error('File does not exist: %s', file_path)
