import os

import sublime
import sublime_plugin

from ..core import log
from ..core.constants import PACKAGE_NAME


class ModulesInfoCommand(sublime_plugin.WindowCommand):
    def __init__(self, *args, **kwargs):
        self.FILE_PATH = self.get_file_path()

    def get_file_path(self):
        return os.path.join(sublime.packages_path(), PACKAGE_NAME, 'modules', '_summary.txt')

    def is_enabled(self):
        return os.path.exists(self.FILE_PATH)

    def is_visible(self):
        return self.is_enabled()

    def run(self):
        if os.path.exists(self.FILE_PATH):
            view = sublime.active_window().open_file(self.FILE_PATH)
            view.settings().set('word_wrap', False)
        else:
            log.error('File does not exist: %s', self.FILE_PATH)
