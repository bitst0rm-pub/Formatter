#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @rev          $Format:%H$ ($Format:%h$)
# @tree         $Format:%T$ ($Format:%t$)
# @date         $Format:%ci$
# @author       $Format:%an$ <$Format:%ae$>
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import os
import json
import logging
import threading
import sublime
from datetime import datetime, timedelta
from . import common

log = logging.getLogger(__name__)

SESSION_FILE = common.join(sublime.packages_path(), '..', 'Local', 'Session.formatter_session')
MAX_AGE_DAYS = 180
MAX_DATABASE_RECORDS = 600


class WordsCounter:
    def __init__(self, view, ignore_whitespace_char=True):
        self.view = view
        self.selections = view.sel()
        self.total_lines = 0
        self.total_words = 0
        self.total_chars = 0
        self.total_chars_with_spaces = 0
        self.ignore_whitespace_char = ignore_whitespace_char

    def thousands_separator(self, number):
        return '{:,}'.format(number).replace(',', '.')

    def count_characters(self, text):
        if self.ignore_whitespace_char:
            return len(common.re.sub(r'\s', '', text))
        else:
            return len(text)

    def run_on_selection_modified(self):
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

            status_text = 'Selections: {} | Lines: {} | Words: {} | Chars: {}'.format(
                self.thousands_separator(len(self.selections)),
                self.thousands_separator(self.total_lines),
                self.thousands_separator(self.total_words),
                self.thousands_separator(self.total_chars)
            )

            if self.ignore_whitespace_char:
                status_text += ' | Chars (with spaces): {}'.format(self.thousands_separator(self.total_chars_with_spaces))
        else:
            # Entire view: words count
            self.total_lines = self.view.rowcol(self.view.size())[0] + 1
            total_text = self.view.substr(sublime.Region(0, self.view.size()))

            self.total_chars = self.count_characters(total_text)
            current_line = self.view.rowcol(self.selections[0].begin())[0] + 1
            current_column = self.view.rowcol(self.selections[0].begin())[1] + 1
            self.total_words = len(total_text.split())

            status_text = 'Total Lines: {} | Words: {} | Chars: {} | Line: {}, Col: {}'.format(
                self.thousands_separator(self.total_lines),
                self.thousands_separator(self.total_words),
                self.thousands_separator(self.total_chars),
                self.thousands_separator(current_line),
                self.thousands_separator(current_column)
            )

        self.view.set_status(common.STATUS_KEY + '_words_count', status_text)


class SessionManager:
    def __init__(self, max_database_records=MAX_DATABASE_RECORDS):
        os.makedirs(common.dirname(SESSION_FILE), exist_ok=True)
        self.lock = threading.Lock()
        self.max_database_records = max_database_records
        self.cleanup_session_file()

    def read_session_file(self):
        try:
            with open(SESSION_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def write_session_file(self, data):
        with open(SESSION_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4, sort_keys=True)

    def remove_old_entries(self):
        data = self.read_session_file()
        current_time = datetime.now()
        keys_to_remove = [file_path for file_path, entry in data.items() if self.is_entry_old(entry, current_time)]

        if keys_to_remove:
            for key in keys_to_remove:
                del data[key]
            self.write_session_file(data)

    def is_entry_old(self, entry, current_time):
        last_update = datetime.strptime(entry.get('last_update', ''), '%Y-%m-%d %H:%M:%S.%f')
        return current_time - last_update > timedelta(days=MAX_AGE_DAYS)

    def add_entry(self, file_path, cursor_x, cursor_y):
        data = self.read_session_file()
        data[file_path] = {
            'last_update': str(datetime.now()),
            'x': cursor_x,
            'y': cursor_y
        }
        self.trim_database(data)
        self.write_session_file(data)

    def trim_database(self, data):
        if len(data) > self.max_database_records:
            # Sort the data by last_update timestamp and remove excess entries
            sorted_data = dict(sorted(data.items(), key=lambda x: x[1]['last_update']))
            keys_to_remove = list(sorted_data.keys())[:-self.max_database_records]
            for key in keys_to_remove:
                del data[key]

    def load_entry(self, file_path):
        data = self.read_session_file()
        return data.get(file_path, None)

    def cleanup_session_file(self):
        with self.lock:
            self.remove_old_entries()

    def add_selections(self, file_path, selections):
        data = self.read_session_file()
        entry = data.get(file_path, {})
        entry['last_update'] = str(datetime.now())
        entry['selections'] = selections
        self.write_session_file(data)

    def restore_selections(self, view, file_path):
        data = self.read_session_file()
        entry = data.get(file_path, {})
        selections = entry.get('selections', [])

        if selections:
            view.sel().clear()
            for region_data in selections:
                region = sublime.Region(region_data['start'], region_data['end'])
                view.sel().add(region)

    def add_syntax(self, file_path, syntax):
        data = self.read_session_file()
        entry = data.get(file_path, {})
        entry['last_update'] = str(datetime.now())
        entry['syntax'] = syntax
        self.write_session_file(data)

    def restore_syntax(self, view, file_path):
        data = self.read_session_file()
        entry = data.get(file_path, {})
        syntax = entry.get('syntax', None)

        if syntax:
            view.set_syntax_file(syntax)

    def add_bookmarks(self, file_path, bookmarks):
        data = self.read_session_file()
        entry = data.get(file_path, {})
        entry['last_update'] = str(datetime.now())
        entry['bookmarks'] = bookmarks
        self.write_session_file(data)

    def restore_bookmarks(self, view, file_path):
        data = self.read_session_file()
        entry = data.get(file_path, {})
        bookmarks = entry.get('bookmarks', [])

        if bookmarks:
            view.erase_regions('bookmarks')
            bookmark_regions = []
            for bookmark_data in bookmarks:
                start = view.text_point(bookmark_data['line'], 0)
                end = view.text_point(bookmark_data['line'], 0)
                bookmark_regions.append(sublime.Region(start, end))

            view.add_regions('bookmarks', bookmark_regions, 'bookmarks', 'bookmark', sublime.DRAW_OUTLINED)

    def get_bookmarks(self, view):
        bookmarks = []
        for region in view.get_regions('bookmarks'):
            row, _ = view.rowcol(region.begin())
            bookmarks.append({'line': row})
        return bookmarks

    def run_on_pre_close(self, view):
        file_path = view.file_name()
        if file_path:
            cursor_position = view.sel()[0].begin()
            cursor_x, cursor_y = view.rowcol(cursor_position)

            # Get selections, syntax, and bookmarks and store them
            selections = [{'start': region.begin(), 'end': region.end()} for region in view.sel()]
            syntax = view.settings().get('syntax')
            bookmarks = self.get_bookmarks(view)

            with self.lock:
                self.add_entry(file_path, cursor_x, cursor_y)
                self.add_selections(file_path, selections)
                self.add_syntax(file_path, syntax)
                self.add_bookmarks(file_path, bookmarks)

    def run_on_load(self, view):
        file_path = view.file_name()
        if file_path:
            with self.lock:
                entry = self.load_entry(file_path)
                if entry:
                    cursor_x = entry.get('x', 0)
                    cursor_y = entry.get('y', 0)
                    total_lines = view.rowcol(view.size())[0]
                    cursor_x = min(cursor_x, total_lines)
                    cursor_y = max(cursor_y, 0)
                    cursor_position = view.text_point(cursor_x, cursor_y)
                    view.sel().clear()
                    view.sel().add(sublime.Region(cursor_position))
                    view.show_at_center(cursor_position, animate=False)

                    # Restore selections, syntax, and bookmarks
                    self.restore_selections(view, file_path)
                    self.restore_syntax(view, file_path)
                    self.restore_bookmarks(view, file_path)
