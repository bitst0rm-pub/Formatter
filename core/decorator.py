from functools import wraps


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
