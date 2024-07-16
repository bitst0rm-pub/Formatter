import os
import sys
import shutil
if sys.version_info < (3, 4):
    import imp
else:
    import importlib

import sublime

from . import (log, CONFIG, HashHandler)
from .constants import PACKAGE_NAME


EXCLUDE_DIRS = ['prettytable', 'sqlmin', 'toml', 'wcswidth', 'yaml']


def import_libs():
    packages_path = sublime.packages_path()
    libs_dir = os.path.join(packages_path, PACKAGE_NAME, 'libs')

    for root, dirs, files in os.walk(libs_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for filename in files:
            if filename.endswith('.py'):
                module_name = filename[:-3]
                module_path = os.path.join(root, filename)
                # Create the module name relative to the libs directory
                relative_path = os.path.relpath(module_path, libs_dir)
                module_name = relative_path.replace(os.sep, '.').rsplit('.', 1)[0]

                try:
                    if sys.version_info < (3, 4):
                        module = imp.load_source(PACKAGE_NAME + '.libs.' + module_name, module_path)
                    else:
                        module = importlib.import_module(PACKAGE_NAME + '.libs.' + module_name, package=PACKAGE_NAME)
                except Exception as e:
                    log.error('Error importing module %s: %s', module_name, str(e))
                    continue

def import_custom_modules():
    packages_path = sublime.packages_path()
    custom_modules = CONFIG.get('custom_modules', {})
    seen = set()

    for k, v in custom_modules.items():
        if k in ['config', 'modules', 'libs'] and isinstance(v, list):
            for src in v:
                src = sublime.expand_variables(os.path.normpath(os.path.expanduser(os.path.expandvars(src))), {'packages': packages_path})
                base = os.path.basename(src)

                if k == 'libs' and base in EXCLUDE_DIRS:
                    continue

                dst = os.path.join(packages_path, PACKAGE_NAME, k, base)

                if os.path.isfile(src):
                    src_md5 = HashHandler().md5f(src)
                    dst_md5 = HashHandler().md5f(dst) if os.path.exists(dst) else None
                    if src_md5 != dst_md5:
                        shutil.copy2(src, dst, follow_symlinks=True)
                        seen.add(True)
                elif os.path.isdir(src):
                    src_sum = HashHandler().md5d(src)
                    dst_sum = HashHandler().md5d(dst) if os.path.exists(dst) else None
                    if src_sum != dst_sum:
                        try:
                            shutil.copytree(src, dst)
                            seen.add(True)
                        except FileExistsError:
                            shutil.rmtree(dst)
                            shutil.copytree(src, dst)
                            seen.add(True)

    if any(seen):
        import_libs()  # libs folder

        from ..modules import update_formatter_modules
        update_formatter_modules()  # modules folder
