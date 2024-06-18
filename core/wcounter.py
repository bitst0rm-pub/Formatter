import logging

import sublime
import sublime_plugin

from . import common

log = logging.getLogger(__name__)


class WordsCounter:
    def __init__(self, view, ignore_whitespace_char=True, use_short_label=False):
        self.view = view
        self.selections = view.sel()
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
            return len(common.re.sub(r'\s', '', text))
        else:
            return len(text)

    def run_on_selection_modified(self):
        try:
            if self.selections and self.view.substr(self.selections[0]):
                # Selections: words count
                for selection in self.selections:
                    selected_text = self.view.substr(selection)
                    char_count_with_spaces = len(selected_text)
                    char_count = self.count_characters(selected_text)

                    self.total_chars += char_count
                    self.total_chars_with_spaces += char_count_with_spaces

                    word_count = len(selected_text.split())
                    self.total_words += word_count

                    selected_lines = selected_text.split('\n')
                    self.total_lines += len(selected_lines)

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
                self.total_lines = self.view.rowcol(self.view.size())[0] + 1
                total_text = self.view.substr(sublime.Region(0, self.view.size()))

                self.total_chars = self.count_characters(total_text)
                current_line = self.view.rowcol(self.selections[0].begin())[0] + 1
                current_column = self.view.rowcol(self.selections[0].begin())[1] + 1
                self.total_words = len(total_text.split())

                if self.use_short_label:
                    label = 'Lines: {} | W: {} | C: {} | L: {}, Col: {}'
                else:
                    label = 'Total Lines: {} | Words: {} | Chars: {} | Line: {}, Col: {}'

                status_text = label.format(
                    self.thousands_separator(self.total_lines),
                    self.thousands_separator(self.total_words),
                    self.thousands_separator(self.total_chars),
                    self.thousands_separator(current_line),
                    self.thousands_separator(current_column)
                )

            self.view.set_status(common.STATUS_KEY + '_words_count', status_text)
        except:
            pass


class WordsCounterListener(sublime_plugin.EventListener, common.Base):
    def on_selection_modified_async(self, view):
        if self.query(common.config, False, 'show_words_count', 'enable'):
            ignore_whitespace_char = self.query(common.config, True, 'show_words_count', 'ignore_whitespace_char')
            use_short_label = self.query(common.config, False, 'show_words_count', 'use_short_label')
            view.settings().set('show_line_column', 'disabled')
            WordsCounter(view, ignore_whitespace_char, use_short_label).run_on_selection_modified()
