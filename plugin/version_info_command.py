import sublime
import sublime_plugin

from ..version import __version__
from ..core.constants import PACKAGE_NAME


class VersionInfoCommand(sublime_plugin.WindowCommand):
    def run(self):
        sublime.message_dialog('🧜‍♀️ ' + PACKAGE_NAME + '\nVersion: ' + __version__)
