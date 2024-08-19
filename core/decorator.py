import datetime
import time
from functools import wraps

from . import log

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


def check_nested_settings(settings, deprecated_options, current_key=''):
    # Check for renamed options
    renamed_options = deprecated_options.get('renamed', {})
    for old_option, new_option in renamed_options.items():
        if old_option in settings:
            log.warning('The settings option "%s%s" has been renamed to "%s". Please update your settings.', current_key, old_option, new_option)

    # Check for deprecated options
    deprecated_options_list = deprecated_options.get('deprecated', [])
    for option in deprecated_options_list:
        if option in settings:
            log.warning('The settings option "%s%s" is deprecated and will be removed in future versions. Please update your settings.', current_key, option)

    for key in ['formatters', 'recursive_folder_format']:  # adjust known structure key
        if key in settings:
            nested_settings = settings[key]
            if isinstance(nested_settings, dict):
                for nested_key, nested_value in nested_settings.items():
                    if isinstance(nested_value, dict):
                        check_nested_settings(nested_value, deprecated_options, current_key + key + '.')
                    else:
                        # Handle non-dict values
                        if nested_key in renamed_options:
                            log.warning('The settings option "%s%s%s" has been renamed to "%s". Please update your settings.', current_key, key + '.', nested_key, renamed_options[nested_key])
                        elif nested_key in deprecated_options_list:
                            log.warning('The settings option "%s%s%s" is deprecated and will be removed in future versions. Please update your settings.', current_key, key + '.', nested_key)


# Decorator to check for deprecated options in settings
def check_deprecated_options(func):
    @wraps(func)
    def wrapper(cls, settings, *args, **kwargs):
        if not hasattr(cls, '_run_once'):
            cls._run_once = True
            check_nested_settings(settings, DEPRECATED_OPTIONS)
        return func(cls, settings, *args, **kwargs)
    return wrapper


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


# Decorator to validate function arguments using provided validator functions
def validate_args(*validators, check_cmd=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Skip the 'self' argument for methods
            args_to_validate = args[1:] if hasattr(args[0], func.__name__) else args
            for validator, arg in zip(validators, args_to_validate):
                if not validator(arg):
                    raise ValueError('Validation failed for argument %s' % arg)
                if check_cmd:
                    log.debug('Command: %s', arg)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def are_all_strings_in_list(lst):
    return all(isinstance(item, str) for item in lst) if lst and isinstance(lst, list) else False


def is_non_empty_string(s):  # unused
    return isinstance(s, str) and bool(s)


def is_non_empty_string_list(lst):  # unused
    return (isinstance(lst, list) and bool(lst) and all(is_non_empty_string(item) for item in lst))


# Decorator to transform function arguments using provided transformer functions
def transform_args(*transformers):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            new_args = [transformer(self, arg) for transformer, arg in zip(transformers, args)]
            return func(self, *new_args, **kwargs)
        return wrapper
    return decorator


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
                    time.sleep(delay / 1000)
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


# Decorator to clean subprocess output
def clean_output(func):
    def wrapper(*args, **kwargs):
        returncode, stdout, stderr = func(*args, **kwargs)
        if stderr:
            # Fix '<0x0d>' (\r) due to Popen(shell=True) on Windows
            stderr = stderr.replace('\r\n', '\n').replace('\r', '\n')
        return returncode, stdout, stderr
    return wrapper
