import datetime
import os
from collections import deque
from functools import partial, wraps
from os.path import basename, dirname, join, normpath
from threading import Timer
from time import perf_counter, sleep

import sublime

from . import IS_WINDOWS, STATUS_KEY, log

# Constants for bulk operation guard
BULK_OPERATION_THRESHOLD = 20  # number of file events to trigger bulk mode
BULK_OPERATION_TIME_WINDOW = 2.0  # time window in seconds to detect bulk operation
IDLE_RESET_TIME = 5.0  # seconds to wait before resetting bulk operation flag when idle

# List of deprecated options, categorized by their status
DEPRECATED_OPTIONS = {
    'renamed': {
        'disable': 'enable',
        'format_on_unique': 'format_on_priority',
        'recursive_folder_format': 'dir_format',
        'exclude_folders_regex': 'exclude_dirs_regex',
        'exclude_extensions': 'exclude_extensions_regex'
    },
    'deprecated': ['custom_modules']
}


class BulkOperationDetector:
    def __init__(self, threshold=BULK_OPERATION_THRESHOLD, time_window=BULK_OPERATION_TIME_WINDOW, idle_reset_time=IDLE_RESET_TIME):
        self.threshold = threshold
        self.time_window = time_window
        self.idle_reset_time = idle_reset_time
        self.file_events = deque()
        self.bulk_operation_in_progress = False
        self.reset_timer = None

    def record_file_event(self):
        current_time = perf_counter()
        self.file_events.append(current_time)

        # Clean up old events outside the time window
        while self.file_events and (current_time - self.file_events[0]) > self.time_window:
            self.file_events.popleft()

        # Check if we are in a bulk operation
        if len(self.file_events) >= self.threshold:
            if not self.bulk_operation_in_progress:
                self.start_bulk_operation()
        else:
            # If a new event is detected within the idle time window, reset bulk mode
            if self.bulk_operation_in_progress:
                self.end_bulk_operation()  # reset bulk mode immediately
            self.reset_idle_timer()  # start/reset the idle timer

    def start_bulk_operation(self):
        self.bulk_operation_in_progress = True
        if self.reset_timer:
            self.reset_timer.cancel()
        self.reset_timer = Timer(self.idle_reset_time, self.end_bulk_operation)
        self.reset_timer.start()

    def end_bulk_operation(self):
        self.bulk_operation_in_progress = False
        if self.reset_timer:
            self.reset_timer.cancel()
            self.reset_timer = None

    def reset_idle_timer(self):
        if self.reset_timer:
            self.reset_timer.cancel()
        self.reset_timer = Timer(self.idle_reset_time, self.end_bulk_operation)
        self.reset_timer.start()

    # Decorator to disable function execution during bulk operations and auto re-enable it afterward
    def bulk_operation_guard(self, register=False):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if register:
                    self.record_file_event()

                if not self.bulk_operation_in_progress:
                    return func(*args, **kwargs)
                else:
                    return None
            return wrapper
        return decorator


bulk_operation_detector = BulkOperationDetector()


# Decorator to check for deprecated options in settings
def check_deprecated_options(func):
    @wraps(func)
    def wrapper(cls, settings, *args, **kwargs):
        if not hasattr(cls, '_run_once'):
            cls._run_once = True
            _check_nested_settings(settings, DEPRECATED_OPTIONS)
        return func(cls, settings, *args, **kwargs)
    return wrapper


def _check_nested_settings(settings, deprecated_options, current_key=''):
    # Check for renamed options
    renamed_options = deprecated_options.get('renamed', {})
    for old_option, new_option in renamed_options.items():
        if settings.get(old_option) is not None:
            log.warning('The settings option "%s%s" has been renamed to "%s". Please update your settings.', current_key, old_option, new_option)

    # Check for deprecated options
    deprecated_options_list = deprecated_options.get('deprecated', [])
    for option in deprecated_options_list:
        if settings.get(option) is not None:
            log.warning('The settings option "%s%s" is deprecated and will be removed in future versions. Please update your settings.', current_key, option)

    # Check known nested structures
    for key in ['formatters', 'recursive_folder_format']:  # adjust known structure key
        nested_settings = settings.get(key)
        if isinstance(nested_settings, type(settings)):
            _check_nested_settings(nested_settings, deprecated_options, current_key + key + '.')
        elif isinstance(nested_settings, dict):  # fallback if nested setting is a dictionary
            for nested_key, nested_value in nested_settings.items():
                if isinstance(nested_value, dict):
                    _check_nested_settings(nested_value, deprecated_options, current_key + key + '.' + nested_key + '.')
                else:
                    # Handle non-dict values
                    if nested_key in renamed_options:
                        log.warning('The settings option "%s%s.%s" has been renamed to "%s". Please update your settings.', current_key, key, nested_key, renamed_options[nested_key])
                    elif nested_key in deprecated_options_list:
                        log.warning('The settings option "%s%s.%s" is deprecated and will be removed in future versions. Please update your settings.', current_key, key, nested_key)


# Decorator to check if a method is deprecated based on a start date and deactivation period
def check_deprecated_api(start_date, deactivate_after_days=14):
    if isinstance(start_date, str):
        start_date = datetime.datetime.strptime(start_date, '%Y-%m-%d')

    deactivation_date = start_date + datetime.timedelta(days=deactivate_after_days)

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_date = datetime.datetime.now()
            if current_date < deactivation_date:
                days_left = (deactivation_date - current_date).days
                log.warning('The method %s is deprecated and will be removed in %d days.', func.__name__, days_left)
            else:
                log.error('The deprecated method %s has been removed and should not be used.', func.__name__)
                raise RuntimeError('The method %s is no longer available.' % func.__name__)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Decorator to validate the subprocess cmd argument as a list of strings
def validate_cmd_arg(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'cmd' in kwargs:
            cmd = kwargs['cmd']
            if isinstance(cmd, list):
                if _are_all_strings_in_list(cmd):
                    log.debug('Command: %s', cmd)

                    if len(cmd) > 1:
                        appdata = None
                        if IS_WINDOWS:
                            appdata_full = os.getenv('APPDATA')
                            if appdata_full:
                                # Extract the portion "AppData/Roaming"
                                appdata = join(basename(dirname(appdata_full)), basename(appdata_full))

                        normalized_exec_path = normpath(cmd[1])
                        if (  # for runtime_type='node'
                            cmd[0].lower().endswith(('node.exe', 'node')) and
                            normpath('node_modules/.bin') in normalized_exec_path or  # local unix + windows
                            (appdata and normpath(appdata + '/npm') in normalized_exec_path and  # global windows
                             normpath(appdata + '/npm/node_modules') not in normalized_exec_path) or
                            normpath('/usr/local/bin') in normalized_exec_path  # global unix
                        ):
                            raise ValueError('Misconfiguration Error: Node is set redundantly. File in "executable_path" already includes node inside to run as standalone. Please set "interpreter_path" to null or omit it to prevent this error.')
                else:
                    raise ValueError('Validation failed: all elements of the cmd argument must be strings: %s' % cmd)
            else:
                raise TypeError('Validation failed: cmd argument is not of type list: %s' % cmd)
        else:
            raise ValueError('Validation failed: cmd keyword argument is required.')

        return func(*args, **kwargs)
    return wrapper


def _are_all_strings_in_list(lst):
    return all(isinstance(item, str) for item in lst) if lst and isinstance(lst, list) else False


# Decorator to transform cmd argument using provided transformer functions
def transform_cmd_arg(*transformers):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if 'cmd' in kwargs:
                cmd = kwargs['cmd']
                if isinstance(cmd, list):
                    if len(transformers) > 0:
                        kwargs['cmd'] = transformers[0](self, cmd=kwargs['cmd'])

                    new_args = [
                        transformer(self, arg) if transformer is not None else arg
                        for transformer, arg in zip(transformers, args)
                    ]
                    return func(self, *new_args, **kwargs)
                else:
                    raise TypeError('Validation failed: cmd argument is not of type list: %s' % cmd)
            else:
                raise ValueError('Validation failed: cmd keyword argument is required.')
        return wrapper
    return decorator


# Decorator to print parsed args command
def print_parsed_args(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        parsed_args = func(*args, **kwargs)
        log.debug('Args: %s', parsed_args)
        return parsed_args
    return wrapper


# Decorator to retry a function on exception
def retry_on_exception(retries=5, delay=500):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while attempt < retries:
                try:
                    return func(*args, **kwargs)
                except Exception:
                    attempt += 1
                    if attempt == retries:
                        log.error('Function %s failed after %d retries. Execution has been stopped.', func.__name__, retries)
                        raise RuntimeError
                    sleep(delay / 1000)
        return wrapper
    return decorator


# Decorator to stop dir formatting process
def check_stop(get_stop_status_func):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if get_stop_status_func():
                log.status('Formatting operation stopped.')
                # Close any opened views
                if self.CONTEXT['new_view']:
                    self.CONTEXT['new_view'].set_scratch(True)
                    self.CONTEXT['new_view'].close()
                self.handle_formatting_completion()
                return
            return func(self, *args, **kwargs)
        return wrapper
    return decorator


# Decorator to clean up subprocess stderr output
def sanitize_cmd_output(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        returncode, stdout, stderr = func(*args, **kwargs)
        if stderr:
            # Fix '<0x0d>' (\r) due to Popen(shell=True) on Windows
            stderr = stderr.replace('\r\n', '\n').replace('\r', '\n')
        return returncode, stdout, stderr
    return wrapper


# Decorator to disable the word counter based on max chars
def skip_word_counter(max_size=6000000):  # ≈ 1.000.000 words (6MB)
    def decorator(func):
        @wraps(func)
        def wrapper(self, view, *args, **kwargs):
            size = view.size()
            if size > max_size:
                message = 'File too large (> {} chars), word counter disabled.'.format(max_size)
                view.set_status(STATUS_KEY + '_wc', message)
                return
            return func(self, view, *args, **kwargs)
        return wrapper
    return decorator


# Decorator to delay function execution until a specified time has passed since the last call
def debounce(delay_in_ms=500):
    def decorator(func):
        last_event_time = {}

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            view = self.view if hasattr(self, 'view') else args[0]
            if not view.is_valid():
                return

            current_time = perf_counter() * 1000  # milliseconds
            view_id = view.id()
            last_event_time[view_id] = current_time

            # Clean up old entries
            to_remove = [view_id for view_id, timestamp in last_event_time.items() if not view.is_valid()]
            for id in to_remove:
                del last_event_time[id]

            callback = partial(_debounce_callback, func, self, args, kwargs, view, last_event_time, delay_in_ms)
            sublime.set_timeout_async(callback, delay_in_ms)
        return wrapper
    return decorator


def _debounce_callback(func, instance, args, kwargs, view, last_event_time, delay_in_ms):
    view_id = view.id()
    if view.is_valid() and (perf_counter() * 1000 - last_event_time.get(view_id, 0)) >= delay_in_ms:
        func(instance, *args, **kwargs)
        # Optionally remove the entry after execution
        last_event_time.pop(view_id, None)


# Decorator to measure the execution time of a function for test
def measure_time(func):  # @unused
    def wrapper(*args, **kwargs):
        start_time = perf_counter()
        result = func(*args, **kwargs)
        end_time = perf_counter()
        elapsed_time = end_time - start_time
        log.info('Function "{}" took {:.4f} seconds to execute.'.format(func.__name__, elapsed_time))
        return result
    return wrapper


# Decorator to enforce the singleton on a class, ensuring only one instance ever exists
def singleton(cls):  # @unused
    _instances = {}

    @wraps(cls)
    def get_instance(*args, **kwargs):
        key = cls
        instance = _instances.get(key)

        if instance is None:
            # Create a new instance
            instance = cls.__new__(cls)
            instance.__init__(*args, **kwargs)
            _instances[key] = instance
        elif args or kwargs:
            # Reinitialize the instance with updated arguments if provided
            instance.__init__(*args, **kwargs)
        return instance
    return get_instance
