import sublime
import sublime_plugin


class ReplaceViewContentCommand(sublime_plugin.TextCommand):
    def run(self, edit, result, region):
        self.view.replace(edit, sublime.Region(region[0], region[1]), result)
