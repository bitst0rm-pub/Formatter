import os
import sys

try:  # python 3.8+
    import importlib
except ImportError:  # python 3.3
    import imp

import sublime

from ..core import PACKAGE_NAME, log


def read_settings_file(settings_file):
    try:
        with open(settings_file, 'r', encoding='utf-8') as f:
            file_content = f.read()
            return sublime.decode_value(file_content)
    except Exception:
        return {}


def update_sys_path(environ, packages_path):
    pypath = environ.get('PYTHONPATH', [])
    updated_paths = [
        os.path.normpath(os.path.expanduser(os.path.expandvars(path.replace('${packages}', packages_path))))
        for path in pypath if path
    ]
    sys.path = updated_paths + sys.path


def import_formatter_modules():
    formatter_map = {}
    formatter_prefix = 'formatter_'
    formatter_prefix_len = len(formatter_prefix)
    modules_dir = os.path.dirname(__file__)

    original_sys_path = sys.path.copy()
    try:
        packages_path = sublime.packages_path()
        settings_file = os.path.join(packages_path, 'User', PACKAGE_NAME + '.sublime-settings')
        settings = read_settings_file(settings_file)

        environ = settings.get('environ', {})
        update_sys_path(environ, packages_path)

        for filename in os.listdir(modules_dir):
            if filename.startswith(formatter_prefix) and filename.endswith('.py'):
                module_name = filename[:-3]
                module_full_name = PACKAGE_NAME + '.modules.' + module_name
                module_path = os.path.join(modules_dir, filename)

                try:
                    if module_full_name in sys.modules:
                        # Use fresh version instead of cached one
                        del sys.modules[module_full_name]

                    if sys.version_info > (3, 3):
                        module = importlib.import_module(module_full_name, package=__name__)
                    else:
                        module = imp.load_source(module_full_name, module_path)
                except Exception as e:
                    log.error('Error importing module %s from %s: %s', module_name, module_path, e)
                    continue

                formatter_class_name = module_name[formatter_prefix_len:].capitalize() + PACKAGE_NAME
                formatter_class = getattr(module, formatter_class_name, None)
                formatter_specs = {key.lower(): getattr(module, key, None) for key in ['INTERPRETERS', 'EXECUTABLES', 'DOTFILES', 'DF_IDENT']}

                if formatter_class:
                    formatter_uid = module_name[formatter_prefix_len:]
                    formatter_map[formatter_uid] = {
                        'specs': formatter_specs,
                        'class': formatter_class,
                        'module': module
                    }
                else:
                    log.error('Either missing or misspelled formatter class in %s.py', module_name)
                    continue
    finally:
        sys.path = original_sys_path

    return formatter_map


formatter_map = import_formatter_modules()


def update_formatter_modules():
    global formatter_map
    formatter_map.update(import_formatter_modules())
