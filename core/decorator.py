from functools import wraps

import sublime

from .reloader import reload_modules


def validate_args(*validators):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Skip the 'self' argument for methods
            args_to_validate = args[1:]
            for validator, arg in zip(validators, args_to_validate):
                if not validator(arg):
                    raise ValueError('Validation failed for argument %s' % arg)
            return func(*args, **kwargs)
        return wrapper
    return decorator

def is_non_empty_string(s):
    return isinstance(s, str) and bool(s)

def is_non_empty_string_list(lst):
    return (
        isinstance(lst, list)
        and bool(lst)
        and all(is_non_empty_string(item) for item in lst)
    )

def retry_on_exception(retries=5, delay=100, recovery_steps=None):
    def decorator_retry(func):
        @wraps(func)
        def wrapper_retry(*args, **kwargs):
            attempt = 0
            while attempt < retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    if attempt == retries:
                        recovery_steps(args[0], delay)
                        raise RuntimeError('Function %s failed after %d retries. Execution has been stopped.' % (func.__name__, retries)) from e
        return wrapper_retry
    return decorator_retry

def recovery_steps(cls, delay=100):
    reload_modules(print_tree=False)
    sublime.set_timeout_async(cls.load_config, delay)
