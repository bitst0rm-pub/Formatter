import os
import time
import traceback
from functools import partial

import sublime

from ..core import (CONFIG, ConfigHandler, InterfaceHandler, OptionHandler,
                    PathHandler, SyntaxHandler, TextHandler, TransformHandler,
                    check_stop, log)
from ..core.constants import (PACKAGE_NAME, RECURSIVE_FAILURE_DIRECTORY,
                              RECURSIVE_SUCCESS_DIRECTORY, STATUS_KEY)
from ..core.formatter import Formatter
from . import ActivityIndicator

STOP = False
START_TIME = None


def get_stop_status():
    return STOP


class DirFormat:
    CONTEXT = {
        'entry_view': None,
        'new_view': None,
        'kwargs': None,
        'cwd': None,
        'filelist': [],
        'filelist_length': 0,
        'current_index': 0,
        'success_count': 0,
        'failure_count': 0,
        'mode_description': None
    }

    def __init__(self, view=None, **kwargs):
        self.view = view
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type:
            class_name = self.__class__.__name__
            log.error('Error occurred in %s while exiting: %s\n%s', class_name, exc_value, ''.join(traceback.format_tb(exc_traceback)))
        return False  # return True to suppress exceptions

    def run(self):
        self.start_timer()

        try:
            global STOP
            STOP = False
            CONFIG['STOP'] = False  # pause smanager and wcounter

            # Show progress indicator if formatting takes longer than 1s
            with ActivityIndicator(view=self.view, label='In Progress...', delay=1000):
                try:
                    cwd = self.get_current_working_directory()
                    filelist = self.get_recursive_files(cwd)

                    self.prepare_context(cwd, filelist)
                    self.process_files()
                except Exception as e:
                    self.handle_error(e)
        except Exception as e:
            log.error('Error occurred during dir formatting: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))

    @staticmethod
    def stop():
        global STOP
        STOP = True
        CONFIG['STOP'] = True

    @staticmethod
    def format_elapsed_time(seconds):
        if seconds < 60:
            return '{:.2f} sec'.format(seconds)
        elif seconds < 3600:
            return '{:.2f} min'.format(seconds / 60)
        elif seconds < 86400:
            return '{:.2f} hrs'.format(seconds / 3600)
        else:
            return '{:.2f} day'.format(seconds / 86400)

    @staticmethod
    def start_timer():
        global START_TIME
        START_TIME = time.perf_counter()

    def end_timer(self):
        global START_TIME
        if START_TIME is None:
            log.warning('Timer was not started.')
            return 'N/A'

        end_time = time.perf_counter()
        elapsed_time = end_time - START_TIME
        formatted_time = self.format_elapsed_time(elapsed_time)
        START_TIME = None
        return '{}'.format(formatted_time)

    def get_current_working_directory(self):
        return PathHandler.get_pathinfo(view=self.view, path=self.view.file_name())['cwd']

    def get_recursive_files(self, cwd):
        items = self.get_dir_format_items()
        return TransformHandler.get_recursive_filelist(
            cwd,
            items.get('exclude_dirs_regex', []),
            items.get('exclude_files_regex', []),
            items.get('exclude_extensions_regex', [])
        )

    def get_dir_format_items(self):
        uid = self.kwargs.get('uid', None)
        return OptionHandler.query(CONFIG, {}, 'formatters', uid, 'dir_format')

    def prepare_context(self, cwd, filelist):
        self.CONTEXT.update({
            'entry_view': self.view,
            'new_view': None,
            'kwargs': self.kwargs,
            'cwd': cwd,
            'filelist': filelist,
            'filelist_length': len(filelist),
            'current_index': 0,
            'success_count': 0,
            'failure_count': 0,
            'mode_description': ConfigHandler.get_mode_description(short=True)
        })

    def process_files(self):
        self.open_next_file()

    @check_stop(get_stop_status)
    def open_next_file(self):
        # Loop files serially
        if self.CONTEXT['current_index'] < self.CONTEXT['filelist_length']:
            file_path = self.CONTEXT['filelist'][self.CONTEXT['current_index']]
            new_view = self.CONTEXT['entry_view'].window().open_file(file_path)
            self.CONTEXT['current_index'] += 1

            if new_view.is_loading():
                self.CONTEXT['new_view'] = new_view
            else:
                self.format_next_file(new_view, is_ready=True)

    @check_stop(get_stop_status)
    def format_next_file(self, new_view, is_ready=False):
        callback = partial(self._on_format_completed, new_view, is_ready)
        SerialFormat.run(view=new_view, callback=callback, **self.CONTEXT['kwargs'])

    def _on_format_completed(self, new_view, is_ready, is_success):
        self.post_dir_format(new_view, is_success)
        if is_ready and is_success:
            new_view.run_command('undo')  # entry_view
        elif self.CONTEXT['entry_view'] != new_view:
            new_view.set_scratch(True)
            new_view.close()

        if self.CONTEXT['current_index'] == self.CONTEXT['filelist_length']:
            # Handle the last file
            self.handle_formatting_completion()

        self.open_next_file()

    def post_dir_format(self, new_view, is_success):
        new_cwd = self.get_post_format_cwd(is_success)
        self.show_result(is_success)
        self.save_formatted_file(new_view, new_cwd, is_success)

    def get_post_format_cwd(self, is_success):
        base_directory = self.CONTEXT['cwd']
        sub_directory = RECURSIVE_SUCCESS_DIRECTORY if is_success else RECURSIVE_FAILURE_DIRECTORY
        return os.path.join(base_directory, sub_directory)

    def show_result(self, is_success):
        if is_success:
            self.CONTEXT['success_count'] += 1
            log.status('🎉 Formatting successful. 🥳✨\n')
        else:
            self.CONTEXT['failure_count'] += 1
            log.status('❌ Formatting failed. 😢💔\n')

    def save_formatted_file(self, new_view, new_cwd, is_success):
        file_path = new_view.file_name()
        new_file_path = self.generate_new_file_path(file_path, new_cwd, is_success)
        cwd = PathHandler.get_pathinfo(view=new_view, path=new_file_path)['cwd']

        try:
            os.makedirs(cwd, exist_ok=True)
            text = new_view.substr(sublime.Region(0, new_view.size()))
            with open(new_file_path, 'w', encoding='utf-8') as f:
                f.write(text)
        except Exception as e:
            self.handle_error(e, cwd, new_file_path)

    def generate_new_file_path(self, file_path, new_cwd, is_success):
        new_file_path = file_path.replace(self.CONTEXT['cwd'], new_cwd, 1)
        if is_success:
            suffix = self.get_new_file_suffix()
            if suffix and isinstance(suffix, str):
                new_file_path = '{0}.{2}{1}'.format(*os.path.splitext(new_file_path) + (suffix,))
        return new_file_path

    def get_new_file_suffix(self):
        if ConfigHandler.is_quick_options_mode():
            return OptionHandler.query(CONFIG, False, 'quick_options', 'new_file_on_format')
        else:
            uid = self.CONTEXT['kwargs'].get('uid', None)
            return OptionHandler.query(CONFIG, False, 'formatters', uid, 'new_file_on_format')

    def handle_formatting_completion(self):
        self.update_status_bar()
        self.open_console_on_failure()
        self.show_completion_message()
        self.reset_context()

    def update_status_bar(self):
        if OptionHandler.query(CONFIG, True, 'show_statusbar'):
            current_view = self.get_current_view()
            current_view.window().set_status_bar_visible(True)
            status_text = self.generate_status_text()
            current_view.set_status(STATUS_KEY, status_text)

    @staticmethod
    def get_current_view():
        return sublime.active_window().active_view()

    def generate_status_text(self):
        return '{}({}) [total:{}|ok:{}|ko:{}]'.format(
            PACKAGE_NAME[0], self.CONTEXT['mode_description'],
            self.CONTEXT['filelist_length'],
            self.CONTEXT['success_count'],
            self.CONTEXT['failure_count']
        )

    def open_console_on_failure(self):
        if OptionHandler.query(CONFIG, False, 'open_console_on_failure') and self.CONTEXT['failure_count'] > 0:
            current_view = self.get_current_view()
            current_view.window().run_command('show_panel', {'panel': 'console', 'toggle': True})

    def show_completion_message(self):
        ok = self.CONTEXT['success_count']
        ko = self.CONTEXT['failure_count']
        total = self.CONTEXT['filelist_length']
        etime = self.end_timer() or 'N/A'
        cwd = self.CONTEXT['cwd']

        message = (
            'Formatting {}!\n\n'
            'OK:  {}\n'
            'KO:  {}\n'
            'Total:  {}\n'
            'Time:  {}\n\n'
            'Please check the result in:\n{}'
        ).format(
            'COMPLETED' if STOP is False else 'ABORTED',
            ok, ko, total, etime, cwd
        )

        InterfaceHandler.popup_message(message, 'INFO', dialog=True)

    def reset_context(self):
        for key, value in self.CONTEXT.items():
            if isinstance(value, list):
                self.CONTEXT[key] = []
            elif isinstance(value, int):
                self.CONTEXT[key] = 0
            else:
                self.CONTEXT[key] = None
        # Reset and end
        CONFIG['STOP'] = True

    @staticmethod
    def handle_error(error, cwd=None, file_path=None):
        log.error('Error occurred: %s\n%s', error, ''.join(traceback.format_tb(error.__traceback__)))
        if cwd and (error.errno != os.errno.EEXIST):
            log.error('Could not create directory: %s', cwd)
            InterfaceHandler.popup_message('Could not create directory: %s\nError mainly appears due to a lack of necessary permissions.' % cwd, 'ERROR')
        if file_path:
            log.error('Could not save file: %s', file_path)
            InterfaceHandler.popup_message('Could not save file: %s\nError mainly appears due to a lack of necessary permissions.' % file_path, 'ERROR')


class SerialFormat:
    @staticmethod
    def run(view=None, callback=None, **kwargs):
        is_success = False
        try:
            region = sublime.Region(0, view.size())
            uid = kwargs.get('uid', None)
            uid, syntax = SyntaxHandler.get_assigned_syntax(view=view, uid=uid, region=region, auto_format_config=None)
            exclude_syntaxes = OptionHandler.query(CONFIG, [], 'formatters', uid, 'dir_format', 'exclude_syntaxes')
            if TextHandler.is_chars_limit_exceeded(view):
                callback(False)
            elif not syntax or syntax in exclude_syntaxes:
                if not syntax:
                    scope = OptionHandler.query(CONFIG, [], 'formatters', uid, 'syntaxes')
                    log.warning('Syntax out of the scope. Plugin scope: %s, UID: %s, File syntax: %s, File: %s', scope, uid, syntax, view.file_name())
                callback(False)
            else:
                kwargs.update({
                    'view': view,
                    'region': region
                })
                is_success = Formatter(**kwargs).run()
                callback(is_success)
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))
