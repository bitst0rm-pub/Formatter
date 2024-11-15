import sublime
import sublime_plugin

from . import (CONFIG, STATUS_KEY, DataHandler, OptionHandler,
               bulk_operation_detector, debounce, skip_word_counter)

CHUNK_SIZE = 1024 * 1024  # ≈ 1048576 chars (1MB)


class WordCounter:
    def __init__(self):
        self.view = None
        self.ignore_whitespace_char = True
        self.use_short_label = False

    def reset(self):
        self.size = self.view.size()
        self.selections = self.view.sel()
        self.total_lines = 0
        self.total_words = 0
        self.total_chars = 0
        self.total_chars_with_spaces = 0

    @staticmethod
    def thousands_separator(number):
        return '{:,}'.format(number).replace(',', '.')

    def count_characters(self, text):
        if self.ignore_whitespace_char:
            return sum(1 for char in text if not char.isspace())
        return len(text)

    def count_text(self, text):
        self.total_chars += self.count_characters(text)
        self.total_chars_with_spaces += len(text)
        self.total_words += len(text.split())
        self.total_lines += text.count('\n') + 1

    def calculate_for_selection(self):
        for selection in self.selections:
            selected_text = self.view.substr(selection)
            self.count_text(selected_text)

    def calculate_for_view(self):
        for start in range(0, self.size, CHUNK_SIZE):
            end = min(start + CHUNK_SIZE, self.size)
            chunk_text = self.view.substr(sublime.Region(start, end))
            self.count_text(chunk_text)

    def update_status(self):
        if self.selections and self.view.substr(self.selections[0]):
            self.calculate_for_selection()
            label = 'Sel: {} | L: {} | W: {} | C: {}' if self.use_short_label else 'Selections: {} | Lines: {} | Words: {} | Chars: {}'
            status_text = label.format(
                self.thousands_separator(len(self.selections)),
                self.thousands_separator(self.total_lines),
                self.thousands_separator(self.total_words),
                self.thousands_separator(self.total_chars)
            )
            if self.ignore_whitespace_char:
                label = ' | C (w/sp): {}' if self.use_short_label else ' | Chars (with spaces): {}'
                status_text += label.format(self.thousands_separator(self.total_chars_with_spaces))
        else:
            self.calculate_for_view()
            current_line, current_column = self.view.rowcol(self.selections[0].begin())
            label = 'Lines: {} | W: {} | C: {} | L: {}, Col: {}' if self.use_short_label else 'Total Lines: {} | Words: {} | Chars: {} | Line: {}, Col: {}'
            status_text = label.format(
                self.thousands_separator(self.total_lines),
                self.thousands_separator(self.total_words),
                self.thousands_separator(self.total_chars),
                self.thousands_separator(current_line + 1),
                self.thousands_separator(current_column + 1)
            )

        self.view.set_status(STATUS_KEY + '_c', status_text)

    def run(self, view, ignore_whitespace_char, use_short_label):
        try:
            self.view = view
            self.ignore_whitespace_char = ignore_whitespace_char
            self.use_short_label = use_short_label
            self.reset()
            self.update_status()
        except Exception:
            pass


word_counter = WordCounter()


class WordCounterListener(sublime_plugin.EventListener):
    @bulk_operation_detector.bulk_operation_guard(register=False)
    @skip_word_counter(max_size=6000000)
    @debounce(delay_in_ms=300)
    def on_selection_modified_async(self, view):
        x = OptionHandler.query(CONFIG, {}, 'show_words_count')
        dir_format_stop = DataHandler.get('__dir_format_stop__')[1]
        if x.get('enable', True) and (dir_format_stop is True or dir_format_stop is None):
            ignore_whitespace_char = x.get('ignore_whitespace_char', True)
            use_short_label = x.get('use_short_label', False)
            view.settings().set('show_line_column', 'disabled')
            word_counter.run(view, ignore_whitespace_char, use_short_label)
