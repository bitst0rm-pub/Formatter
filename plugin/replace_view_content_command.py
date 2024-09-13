import sublime
import sublime_plugin


class ReplaceViewContentCommand(sublime_plugin.TextCommand):
    def run(self, edit, result, region):
        target_region = sublime.Region(region[0], region[1])
        size = sublime.Region(region[0], self.view.size())

        if target_region == size and self.view.settings().get('ensure_newline_at_eof_on_save', False):
            line_endings = self.view.settings().get('default_line_ending', 'system')
            # Windows \r\n (2 chars), Unix \n (1 char)
            line_ending_length = 2 if line_endings == 'windows' or (line_endings == 'system' and sublime.platform() == 'windows') else 1
            target_region = sublime.Region(region[0], region[1] - line_ending_length)

        self.view.replace(edit, target_region, result)
