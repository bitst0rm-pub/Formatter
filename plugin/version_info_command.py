import sublime
import sublime_plugin

from ..core import PACKAGE_NAME
from . import __version__


class VersionInfoCommand(sublime_plugin.WindowCommand):
    def run(self):
        sublime.message_dialog('🧜‍♀️ ' + PACKAGE_NAME + '\nVersion: ' + __version__)
