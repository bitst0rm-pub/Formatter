import os
import sys
import logging
import sublime
if sys.version_info < (3, 4):
    import imp
else:
    import importlib

from ..core import common

log = logging.getLogger(__name__)


def update_sys_path(environ, packages_path):
    pypath = environ.get('PYTHONPATH', [])
    updated_paths = [os.path.normpath(os.path.expanduser(os.path.expandvars(path.replace('${packages}', packages_path))))
                  for path in pypath if path]
    sys.path = updated_paths + sys.path

def import_formatter_modules():
    formatter_map = {}
    formatter_prefix = 'formatter_'
    formatter_prefix_len = len(formatter_prefix)
    modules_dir = os.path.dirname(__file__)

    try:
        original_sys_path = sys.path.copy()
        packages_path = sublime.packages_path()

        settings_file = os.path.join(packages_path, 'User', common.PACKAGE_NAME + '.sublime-settings')
        settings = common.read_settings_file(settings_file)

        environ = settings.get('environ', {})
        update_sys_path(environ, packages_path)

        for filename in os.listdir(modules_dir):
            if filename.startswith(formatter_prefix) and filename.endswith('.py'):
                module_name = filename[:-3]
                module_path = os.path.join(modules_dir, filename)

                try:
                    if sys.version_info < (3, 4):
                        module = imp.load_source(common.PACKAGE_NAME + '.modules.' + module_name, module_path)
                    else:
                        module = importlib.import_module(common.PACKAGE_NAME + '.modules.' + module_name, package=__name__)
                except Exception as e:
                    log.error('Error importing module %s: %s', module_name, str(e))
                    continue

                formatter_class_name = module_name[formatter_prefix_len:].capitalize() + common.PACKAGE_NAME
                formatter_class = getattr(module, formatter_class_name, None)
                formatter_const = {key.lower(): getattr(module, key, None) for key in ['INTERPRETERS', 'EXECUTABLES', 'DOTFILES']}

                if formatter_class:
                    formatter_uid = module_name[formatter_prefix_len:]
                    formatter_map[formatter_uid] = {
                        'const': formatter_const,
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
