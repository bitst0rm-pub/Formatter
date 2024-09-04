import os

import sublime
import sublime_plugin

from ..core import log
from ..core.constants import PACKAGE_NAME


class ModulesInfoCommand(sublime_plugin.WindowCommand):
    def __init__(self, window):
        self.file_path = self.get_file_path()

    @staticmethod
    def get_file_path():
        return os.path.join(sublime.packages_path(), PACKAGE_NAME, 'modules', '_summary.txt')

    def is_enabled(self):
        return os.path.exists(self.file_path)

    def is_visible(self):
        return self.is_enabled()

    def run(self):
        if os.path.exists(self.file_path):
            view = sublime.active_window().open_file(self.file_path)
            view.settings().set('word_wrap', False)
        else:
            log.error('File does not exist: %s', self.file_path)
