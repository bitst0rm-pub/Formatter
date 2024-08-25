import sublime
import sublime_plugin

from . import CONFIG, OptionHandler, debounce
from .constants import STATUS_KEY

CHUNK_SIZE = 1024 * 1024  # ≈ 1048576 chars (1MB)


class WordsCounter:
    def __init__(self, view, ignore_whitespace_char=True, use_short_label=False):
        self.view = view
        self.size = self.view.size()
        self.selections = self.view.sel()
        self.total_lines = 0
        self.total_words = 0
        self.total_chars = 0
        self.total_chars_with_spaces = 0
        self.ignore_whitespace_char = ignore_whitespace_char
        self.use_short_label = use_short_label

    def thousands_separator(self, number):
        return '{:,}'.format(number).replace(',', '.')

    def count_characters(self, text):
        if self.ignore_whitespace_char:
            return sum(1 for char in text if not char.isspace())
        else:
            return len(text)

    def count_text(self, text):
        self.total_chars += self.count_characters(text)
        self.total_chars_with_spaces += len(text)
        self.total_words += len(text.split())
        self.total_lines += text.count('\n') + 1

    def run_on_selection_modified(self):
        try:
            if self.selections and self.view.substr(self.selections[0]):
                # Selections: words count
                for selection in self.selections:
                    selected_text = self.view.substr(selection)
                    self.count_text(selected_text)

                if self.use_short_label:
                    label = 'Sel: {} | L: {} | W: {} | C: {}'
                else:
                    label = 'Selections: {} | Lines: {} | Words: {} | Chars: {}'

                status_text = label.format(
                    self.thousands_separator(len(self.selections)),
                    self.thousands_separator(self.total_lines),
                    self.thousands_separator(self.total_words),
                    self.thousands_separator(self.total_chars)
                )

                if self.ignore_whitespace_char:
                    if self.use_short_label:
                        label = ' | C (w/sp): {}'
                    else:
                        label = ' | Chars (with spaces): {}'
                    status_text += label.format(self.thousands_separator(self.total_chars_with_spaces))
            else:
                # Entire view: words count
                for start in range(0, self.size, CHUNK_SIZE):
                    end = min(start + CHUNK_SIZE, self.size)
                    chunk_text = self.view.substr(sublime.Region(start, end))
                    self.count_text(chunk_text)

                current_line, current_column = self.view.rowcol(self.selections[0].begin())

                if self.use_short_label:
                    label = 'Lines: {} | W: {} | C: {} | L: {}, Col: {}'
                else:
                    label = 'Total Lines: {} | Words: {} | Chars: {} | Line: {}, Col: {}'

                status_text = label.format(
                    self.thousands_separator(self.total_lines),
                    self.thousands_separator(self.total_words),
                    self.thousands_separator(self.total_chars),
                    self.thousands_separator(current_line + 1),
                    self.thousands_separator(current_column + 1)
                )

            self.view.set_status(STATUS_KEY + '_wc', status_text)
        except Exception:
            pass


class WordsCounterListener(sublime_plugin.EventListener):
    @debounce(delay_in_ms=500)
    def on_selection_modified_async(self, view):
        x = OptionHandler.query(CONFIG, {}, 'show_words_count')
        if x.get('enable', True) and CONFIG.get('STOP', True):
            ignore_whitespace_char = x.get('ignore_whitespace_char', True)
            use_short_label = x.get('use_short_label', False)
            view.settings().set('show_line_column', 'disabled')
            WordsCounter(view, ignore_whitespace_char, use_short_label).run_on_selection_modified()
