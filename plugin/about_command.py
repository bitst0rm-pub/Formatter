import sublime
import sublime_plugin

from ..core import PACKAGE_NAME
from . import __author__, __version__


class AboutCommand(sublime_plugin.WindowCommand):
    def run(self):
        sublime.message_dialog('🧜‍♀️ ' + PACKAGE_NAME + '\nVersion: ' + __version__ + '\nAuthor: ' + __author__)
