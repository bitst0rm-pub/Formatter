import sublime
import sublime_plugin

from ..core import LayoutHandler
from ..core.constants import PACKAGE_NAME


class KeyBindingsCommand(sublime_plugin.WindowCommand):
    def run(self):
        sublime.run_command('new_window')
        window = sublime.active_window()
        window.set_layout(LayoutHandler.assign_layout('2cols'))
        window.focus_group(0)
        window.run_command('open_file', {'file': '${packages}/' + PACKAGE_NAME + '/Example.sublime-keymap'})
        window.focus_group(1)
        window.run_command('open_file', {'file': '${packages}/User/Default (${platform}).sublime-keymap'})
