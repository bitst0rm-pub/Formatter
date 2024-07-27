import time
from functools import wraps

import sublime

from . import log


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

def is_non_empty_string(s):
    return isinstance(s, str) and bool(s)

def is_non_empty_string_list(lst):
    return (
        isinstance(lst, list)
        and bool(lst)
        and all(is_non_empty_string(item) for item in lst)
    )

def transform_args(*transformers):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            new_args = [transformer(self, arg) for transformer, arg in zip(transformers, args)]
            return func(self, *new_args, **kwargs)
        return wrapper
    return decorator

def retry_on_exception(retries=5, delay=500):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while attempt < retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    if attempt == retries:
                        log.error('Function %s failed after %d retries. Execution has been stopped.', func.__name__, retries)
                        raise RuntimeError
                    time.sleep(delay / 1000)
        return wrapper
    return decorator
