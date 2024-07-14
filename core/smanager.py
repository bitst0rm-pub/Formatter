import json
import threading
from os import makedirs
from os.path import (join, dirname)
from datetime import (datetime, timedelta)

import sublime
import sublime_plugin

from . import (log, CONFIG, OptionHandler)


SESSION_FILE = join(sublime.packages_path(), '..', 'Local', 'Session.formatter_session')
MAX_AGE_DAYS = 180
MAX_DATABASE_RECORDS = 600


class SessionManager:
    def __init__(self, max_database_records=MAX_DATABASE_RECORDS):
        makedirs(dirname(SESSION_FILE), exist_ok=True)
        self.lock = threading.Lock()
        self.max_database_records = max_database_records
        self.cleanup_session_file()

    def read_session_file(self):
        try:
            with open(SESSION_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except UnicodeDecodeError as e:
            log.error('Unicode decoding error occurred: %s', e)
            return {}
        except Exception as e:
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

            # Store selections and bookmarks
            selections = [{'start': region.begin(), 'end': region.end()} for region in view.sel()]
            bookmarks = self.get_bookmarks(view)

            with self.lock:
                self.add_entry(file_path, cursor_x, cursor_y)
                self.add_selections(file_path, selections)
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
                    try:
                        view.show_at_center(cursor_position, animate=False)  # ST4
                    except Exception as e:
                        view.show_at_center(cursor_position)  # ST3

                    # Restore selections and bookmarks
                    self.restore_selections(view, file_path)
                    self.restore_bookmarks(view, file_path)


class SessionManagerListener(sublime_plugin.EventListener):
    def __init__(self, *args, **kwargs):
        self.session_manager = SessionManager(max_database_records=600)

    def on_load(self, view):
        if OptionHandler().query(CONFIG, True, 'remember_session'):
            self.session_manager.run_on_load(view)

    def on_pre_close(self, view):
        if OptionHandler().query(CONFIG, True, 'remember_session'):
            self.session_manager.run_on_pre_close(view)
