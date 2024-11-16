import json
import threading
from datetime import datetime, timedelta
from os import makedirs
from os.path import dirname, join

import sublime
import sublime_plugin

from . import (CONFIG, PACKAGE_NAME, DataHandler, OptionHandler,
               bulk_operation_detector, log)

SESSION_FILE = join(sublime.packages_path(), '..', 'Local', 'Session.formatter_session')
MAX_AGE_DAYS = 180
MAX_DATABASE_RECORDS = 600
EXCLUDED_FILES = [PACKAGE_NAME + '.sublime-settings']


class SessionManager:
    def __init__(self, max_records=MAX_DATABASE_RECORDS):
        makedirs(dirname(SESSION_FILE), exist_ok=True)
        self.lock = threading.Lock()
        self.max_records = max_records
        self._remove_expired_entries()

    @staticmethod
    def _is_excluded(file_path):
        return any(file_path.endswith(excluded) for excluded in EXCLUDED_FILES)

    @staticmethod
    def _read_file():
        try:
            with open(SESSION_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except UnicodeDecodeError as e:
            log.error('Unicode decoding error: %s', e)
            return {}
        except Exception:
            return {}

    @staticmethod
    def _write_file(data):
        try:
            with open(SESSION_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, separators=(',', ':'), indent=None)
        except Exception as e:
            log.error('Error writing session file: %s', e)

    def _remove_expired_entries(self):
        with self.lock:
            data = self._read_file()
            current_time = datetime.now()
            updated_data = {k: v for k, v in data.items() if not self._is_entry_expired(v, current_time)}
            if len(updated_data) < len(data):
                self._write_file(updated_data)

    @staticmethod
    def _is_entry_expired(entry, current_time):
        try:
            last_update = datetime.strptime(entry.get('last_update', ''), '%Y-%m-%d %H:%M:%S.%f')
            return current_time - last_update > timedelta(days=MAX_AGE_DAYS)
        except ValueError:
            return True  # treat invalid dates as old entries

    def _trim_database(self, data):
        if len(data) > self.max_records:
            # Sort the data by last_update timestamp and remove excess entries
            sorted_data = dict(sorted(data.items(), key=lambda x: x[1]['last_update']))
            keys_to_remove = list(sorted_data.keys())[:-self.max_records]
            for key in keys_to_remove:
                del data[key]

    @staticmethod
    def _get_selections(view):
        return [{'start': region.begin(), 'end': region.end()} for region in view.sel()]

    @staticmethod
    def _restore_selections(view, selections):
        if selections:
            view.sel().clear()
            view.sel().add_all([sublime.Region(s['start'], s['end']) for s in selections])

    @staticmethod
    def _get_bookmarks(view):
        return [{'line': view.rowcol(region.begin())[0]} for region in view.get_regions('bookmarks')]

    @staticmethod
    def _restore_bookmarks(view, bookmarks):
        if bookmarks:
            bookmark_regions = [sublime.Region(view.text_point(bm['line'], 0)) for bm in bookmarks]
            view.erase_regions('bookmarks')
            view.add_regions('bookmarks', bookmark_regions, 'bookmarks', 'bookmark', sublime.DRAW_OUTLINED)

    @staticmethod
    def _get_foldings(view):
        return [{'start': region.begin(), 'end': region.end()} for region in view.folded_regions()]

    @staticmethod
    def _restore_foldings(view, foldings):
        if foldings:
            view.unfold(sublime.Region(0, view.size()))  # clear existing folds
            view.fold([sublime.Region(f['start'], f['end']) for f in foldings])

    def save_view_state(self, view):
        file_path = view.file_name()
        if file_path and not self._is_excluded(file_path):
            # Save selections, bookmarks, and foldings
            data = {
                'last_update': str(datetime.now()),
                'x': view.rowcol(view.sel()[0].begin())[0],
                'y': view.rowcol(view.sel()[0].begin())[1],
                'selections': self._get_selections(view),
                'bookmarks': self._get_bookmarks(view),
                'foldings': self._get_foldings(view)
            }

            with self.lock:
                session_data = self._read_file()
                session_data[file_path] = data
                self._trim_database(session_data)
                self._write_file(session_data)

    def restore_view_state(self, view, is_on_startup=False):
        file_path = view.file_name()
        if file_path and not self._is_excluded(file_path):
            with self.lock:
                data = self._read_file().get(file_path, None)
                if data:
                    total_lines = view.rowcol(view.size())[0]
                    cursor_x = min(data.get('x', 0), total_lines)
                    cursor_y = max(data.get('y', 0), 0)
                    cursor_position = view.text_point(cursor_x, cursor_y)

                    # Restore cursor position
                    view.sel().clear()
                    view.sel().add(sublime.Region(cursor_position))

                    if not is_on_startup:
                        try:
                            view.show_at_center(cursor_position, animate=False)  # ST4
                        except Exception:
                            view.show_at_center(cursor_position)  # ST3

                    # Restore selections, bookmarks, and foldings
                    self._restore_selections(view, data.get('selections', []))
                    self._restore_bookmarks(view, data.get('bookmarks', []))
                    self._restore_foldings(view, data.get('foldings', []))


session_manager = SessionManager(max_records=600)


class SessionManagerListener(sublime_plugin.EventListener):
    is_startup = True

    def should_remember_session(self):
        dir_format_stop = DataHandler.get('__dir_format_stop__')[1]
        return OptionHandler.query(CONFIG, True, 'remember_session') and (dir_format_stop is True or dir_format_stop is None)

    @bulk_operation_detector.bulk_operation_guard(register=True)
    def on_load(self, view):
        if self.should_remember_session():
            session_manager.restore_view_state(view)

    def on_activated(self, view):
        if self.is_startup:
            self.is_startup = False
            if self.should_remember_session():
                for window in sublime.windows():
                    for wview in window.views():
                        session_manager.restore_view_state(wview, is_on_startup=True)

    @bulk_operation_detector.bulk_operation_guard(register=True)
    def on_pre_close(self, view):
        if self.should_remember_session():
            session_manager.save_view_state(view)
