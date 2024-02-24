#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import os
import re
import sys
import json
import time
import shutil
import hashlib
import logging
import tempfile

import sublime

if sys.version_info < (3, 4):
    from imp import reload
else:
    from importlib import reload

from subprocess import Popen, PIPE, TimeoutExpired
from os.path import (basename, expanduser, expandvars, isdir, isfile, join,
                    normcase, normpath, pathsep, split, splitext, dirname)

log = logging.getLogger(__name__)

IS_WINDOWS = sublime.platform() == 'windows'
PACKAGE_NAME = 'Formatter'
ASSETS_DIRECTORY = 'formatter.assets'
QUICK_OPTIONS_SETTING_FILE = 'Formatter.quick-options'
RECURSIVE_SUCCESS_DIRECTORY = '__format_success__'
RECURSIVE_FAILURE_DIRECTORY = '__format_failure__'
STATUS_KEY = '@!' + PACKAGE_NAME.lower()

LAYOUTS = {
    'single': {
        'cols': [0.0, 1.0],
        'rows': [0.0, 1.0],
        'cells': [[0, 0, 1, 1]]
    },
    '2cols': {
        'cols': [0.0, 0.5, 1.0],
        'rows': [0.0, 1.0],
        'cells': [[0, 0, 1, 1], [1, 0, 2, 1]]
    },
    '2rows': {
        'cols': [0.0, 1.0],
        'rows': [0.0, 0.5, 1.0],
        'cells': [[0, 0, 1, 1], [0, 1, 1, 2]]
    }
}


class Module(object):
    '''
    A fundamental class providing the complete APIs for the formatting modules.
    These APIs are strictly limited for use with files located in the 'modules' folder.
    '''

    def __init__(self, view=None, uid=None, region=None, interpreters=None, executables=None, has_cfgignore=False, **kwargs):
        self.view = view
        self.uid = uid
        self.region = region
        self.interpreters = interpreters
        self.executables = executables
        self.has_cfgignore = has_cfgignore

    def is_executeable(self, file):
        if file and isinstance(file, str) and isfile(file):
            if os.access(file, os.F_OK | os.X_OK):
                return True

            if not IS_WINDOWS:
                import stat
                os.chmod(file, os.stat(file).st_mode | stat.S_IEXEC)
                log.debug('Set executable permission for: %s', file)
                return True

            log.warning('File exists but cannot be executed: %s', file)
        return False

    def get_pathinfo(self, path=None):
        try:
            cwd = tempfile.gettempdir()
        except AttributeError:
            # Fallback to ${HOME} for unsaved buffer
            cwd = expanduser('~')

        base = stem = suffix = ext = None
        if not path:
            path = self.view.file_name()

        if path:
            cwd, base = split(path)
            stem, suffix = splitext(base)
            ext = suffix[1:]

        return {'path': path, 'cwd': cwd, 'base': base, 'stem': stem, 'suffix': suffix, 'ext': ext}

    def update_environ(self):
        try:
            environ = os.environ.copy()

            for key, value in config.get('environ').items():
                if value and isinstance(value, list):
                    pathstring = environ.get(key, None)
                    items = list(filter(None, value))

                    if items:
                        if pathstring:
                            paths = pathstring.split(pathsep)
                            [i if normpath(i) in paths else paths.insert(0, normpath(i)) for i in reversed(items)]
                            environ[key] = pathsep.join(paths)
                        else:
                            environ[key] = pathsep.join(map(normpath, items))

            return environ
        except Exception as error:
            log.warning('Could not clone system environment: %s', error)

        return None

    def get_environ_path(self, fnames):
        if fnames and isinstance(fnames, list):
            environ = self.update_environ()
            if environ and isinstance(environ, dict):
                path = environ.get('PATH', os.defpath)
                if path:
                    dirs = path.split(pathsep)

                    if IS_WINDOWS:
                        pathext = os.environ.get('PATHEXT', '').split(pathsep)
                        match = [[fn, ext] for fn in fnames for ext in pathext if any([fn.lower().endswith(ext.lower())])]
                        if match:
                            files = [match[0][0]]
                        else:
                            files = [fn + ext for fn in fnames for ext in pathext]
                    else:
                        files = fnames

                    seen = set()
                    for dir in dirs:
                        normdir = normcase(dir)
                        if not normdir in seen:
                            seen.add(normdir)
                            for f in files:
                                file = join(dir, f)
                                if self.is_executeable(file):
                                    return file
                else:
                    log.error('"PATH" or default search path does not exist: %s', path)
            else:
                log.error('System environment is empty or not of type dict: %s', environ)
        else:
            log.error('File names variable is empty or not of type list: %s', fnames)

        return None

    def popen(self, cmd):
        info = None
        if IS_WINDOWS:
            from subprocess import STARTUPINFO, STARTF_USESHOWWINDOW, SW_HIDE
            # Hide the console window to avoid flashing an
            # ugly cmd prompt on Windows when invoking plugin.
            info = STARTUPINFO()
            info.dwFlags |= STARTF_USESHOWWINDOW
            info.wShowWindow = SW_HIDE

        # Input cmd must be a list of strings
        process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE, cwd=self.get_pathinfo()['cwd'],
                        env=self.update_environ(), shell=False, startupinfo=info)
        return process

    def kill(self, process):
        try:
            if self.is_alive(process):
                process.terminate()
                process.wait()
                time.sleep(1)
            if self.is_alive(process):
                process.kill()
                process.wait()
        except Exception as e:
            log.error('Error terminating process: %s', e)

    def is_alive(self, process):
        return process.poll() is None

    def timeout(self):
        timeout = config.get('timeout')
        return timeout if not isinstance(timeout, bool) and isinstance(timeout, int) else None

    def exec_com(self, cmd):
        timeout = self.timeout()
        process = self.popen(cmd)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except TimeoutExpired:
            self.kill(process)
            return 1, None, 'Aborted due to expired timeout=' + str(timeout)

        self.kill(process)
        return process.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')

    def exec_cmd(self, cmd):
        timeout = self.timeout()
        process = self.popen(cmd)
        try:
            stdout, stderr = process.communicate(self.get_text_from_region(self.region).encode('utf-8'), timeout=timeout)
        except TimeoutExpired:
            self.kill(process)
            return 1, None, 'Aborted due to expired timeout=' + str(timeout)

        self.kill(process)
        return process.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')

    def get_text_from_region(self, region):
        return self.view.substr(region)

    def query(self, data_dict, default=None, *keys):
        for key in keys:
            if not isinstance(data_dict, (dict, sublime.Settings)):
                return default
            data_dict = data_dict.get(key, default)
        return data_dict

    def create_tmp_file(self, suffix=None):
        import tempfile

        if not suffix:
            suffix = '.' + self.get_assigned_syntax()

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix, dir=self.get_pathinfo()['cwd'], encoding='utf-8') as file:
            file.write(self.get_text_from_region(self.region))
            file.close()
            return file.name

        return None

    def remove_tmp_file(self, tmp_file):
        if tmp_file and os.path.isfile(tmp_file):
            os.unlink(tmp_file)

    def is_generic_mode(self):
        formatter = self.query(config, {}, 'formatters', self.uid)
        name = formatter.get('name', None)
        typ = formatter.get('type', None)
        return bool(name and typ)

    def _get_active_view_parent_folders(self, max_depth=30):
        active_file_path = self.view.file_name()
        parent_folders = []

        if active_file_path:
            d = dirname(active_file_path)

            for _ in range(max_depth):
                if d == dirname(d):
                    break
                parent_folders.append(d)
                d = dirname(d)

        return parent_folders

    def set_generic_local_executables(self):
        is_generic = self.is_generic_mode()
        path = self.query(config, None, 'formatters', self.uid, 'executable_path')
        if is_generic and path:
            self.executables = [self.get_pathinfo(path)['base']]

    def get_local_executable(self, runtime_type=None):
        self.set_generic_local_executables()

        if not runtime_type or not self.executables:
            return None

        parent_folders = self._get_active_view_parent_folders()
        if parent_folders:
            paths = []
            if runtime_type == 'node':
                for folder in parent_folders:
                    for ex in self.executables:
                        paths.append(join(folder, 'node_modules', '.bin', ex))
                        paths.append(join(folder, 'node_modules', self.executables[0], 'bin', ex))
                        paths.append(join(folder, 'node_modules', self.executables[0], ex))
            if runtime_type == 'python':
                pass
            if runtime_type == 'perl':
                pass
            if runtime_type == 'ruby':
                pass
            for f in paths:
                if self.is_executeable(f):
                    log.debug('Local executable found: %s', f)
                    return f
        return None

    def _get_path_for(self, what):
        if what == 'executable':
            fnames_list = self.executables
        elif what == 'interpreter':
            fnames_list = self.interpreters
        else:
            return None

        user_files = self.query(config, None, 'formatters', self.uid, what + '_path')

        if isinstance(user_files, str):
            user_files = [user_files]
        elif not isinstance(user_files, list):
            user_files = []

        for user_file in user_files:
            a = self.get_pathinfo(user_file)
            if a['path'] == a['base'] and not a['cwd']:
                global_file = self.get_environ_path([user_file])
                if global_file:
                    log.debug('Global %s found: %s', what, global_file)
                    return global_file

            if self.is_executeable(user_file):
                log.debug('User %s found: %s', what, user_file)
                return user_file

        global_file = self.get_environ_path(fnames_list)
        if global_file:
            log.debug('Global %s found: %s', what, global_file)
            return global_file
        else:
            log.error('Files %s do not exist: %s', what, user_files)
            return None

    def get_executable(self, runtime_type=None):
        local_executable = self.get_local_executable(runtime_type)
        if local_executable:
            return local_executable

        user_and_global_executable = self._get_path_for('executable')
        return user_and_global_executable if user_and_global_executable else None

    def get_interpreter(self):
        user_and_global_interpreter = self._get_path_for('interpreter')
        return user_and_global_interpreter if user_and_global_interpreter else None

    def get_combo_cmd(self, runtime_type=None):
        cmd = [self.get_interpreter(), self.get_executable(runtime_type)]
        cmd.extend(self.get_args())
        return cmd if all(cmd) else None

    def get_assigned_syntax(self, view=None, uid=None, region=None):
        if not all((view, uid, region)):
            view, uid, region = self.view, self.uid, self.region

        syntaxes = self.query(config, None, 'formatters', uid, 'syntaxes')
        exclude_syntaxes = self.query(config, None, 'formatters', uid, 'exclude_syntaxes')

        def should_exclude(syntax, scope):
            return (
                exclude_syntaxes
                and isinstance(exclude_syntaxes, dict)
                and any(
                    (key.strip().lower() in ['all', syntax]) and
                    (isinstance(value, list) and any(x in scope for x in value))
                    for key, value in exclude_syntaxes.items()
                )
            )

        if syntaxes and isinstance(syntaxes, list):
            syntaxes = [syntax.lower() for syntax in syntaxes if syntax]
            scopes = view.scope_name(region.begin()).strip().lower().split(' ')

            for syntax in syntaxes:
                for scope in scopes:
                    if any(('source.' + syntax + x) in scope for x in ['.embedded', '.sublime', '.interpolated']):
                        if should_exclude(syntax, scope):
                            return None
                        return syntax
                    if 'source.' + syntax == scope:
                        if should_exclude(syntax, scope):
                            return None
                        return syntax

            for syntax in syntaxes:
                for scope in scopes:
                    if scope.endswith('.' + syntax):
                        if should_exclude(syntax, scope):
                            return None
                        return syntax

            for syntax in syntaxes:
                for scope in scopes:
                    if '.' + syntax + '.' in scope:
                        if should_exclude(syntax, scope):
                            return None
                        return syntax

            for syntax in syntaxes:
                for scope in scopes:
                    if scope.startswith(syntax + '.'):
                        if should_exclude(syntax, scope):
                            return None
                        return syntax

            return None

        log.error('Setting key "syntaxes" must be a non-empty list: %s', syntaxes)
        return None

    def check_cfgignore(self):
        paths = self._get_active_view_parent_folders()
        for path in paths:
            if isfile(join(path, '.cfgignore')):
                log.debug('.cfgignore found at: %s', path)
                return True
        return False

    def get_config_path(self):
        if self.has_cfgignore:
            return None

        shared_config = self.query(config, None, 'formatters', self.uid, 'config_path')

        if shared_config and isinstance(shared_config, dict):
            syntax = self.get_assigned_syntax()

            for key, path in shared_config.items():
                if key.strip().lower() == syntax and self.is_valid_path(path):
                    log.debug('Config [%s]: %s', syntax, path)
                    return path

            default_path = shared_config.get('default', None)
            if self.is_valid_path(default_path):
                log.debug('Config [default]: %s', default_path)
                return default_path

            log.warning('Could not obtain config file for syntax: %s', syntax)
        else:
            log.warning('Setting key "config_path" must be a non-empty dict: %s', shared_config)

        log.info('Plugin default or per-project config will be used instead if available.')
        return None

    def is_valid_path(self, path):
        return path and isinstance(path, str) and isfile(path) and os.access(path, os.R_OK)

    def get_args(self):
        args = self.query(config, None, 'formatters', self.uid, 'args')
        return list(map(str, args)) if args and isinstance(args, list) else []

    def get_success_code(self):
        return int(self.query(config, 0, 'formatters', self.uid, 'success_code'))

    def fix_cmd(self, cmd):
        fix_cmds = self.query(config, None, 'formatters', self.uid, 'fix_commands')

        if fix_cmds and isinstance(fix_cmds, list) and cmd and isinstance(cmd, list):
            for x in fix_cmds:
                if isinstance(x, list):
                    l = len(x)

                    if 3 <= l <= 5:
                        search = str(x[l-5])
                        replace = str(x[l-4])
                        index = int(x[l-3])
                        count = int(x[l-2])
                        position = int(x[l-1])

                        if isinstance(index, int) and isinstance(count, int) and isinstance(position, int):
                            for i, item in enumerate(cmd):
                                item = str(item)

                                if index == i:
                                    if l == 5:
                                        if search == item and position < 0:
                                            cmd.pop(i)
                                        else:
                                            cmd[i] = re.sub(r'%s' % search, replace, item, count)
                                    if l == 4:
                                        cmd[i] = replace
                                    if l == 3 and position < 0:
                                        cmd.pop(i)
                                    if position > -1:
                                        cmd.insert(position, cmd.pop(i))

                            log.debug('Fixed arguments: %s', cmd)
                        else:
                            log.error('index, count and position of "fix_commands" must be of type int.')
                            return None
                    else:
                        log.error('Length of each item in "fix_commands" must be between 3 and 5.')
                        return None
                else:
                    log.error('Items of "fix_commands" must be of type list.')
                    return None

        return cmd

    def is_valid_cmd(self, cmd):
        return all(isinstance(x, str) for x in cmd) if cmd and isinstance(cmd, list) else False

    def popup_message(self, text, title=None, dialog=False):
        template = u'%s' + (u' (%s)' if title else '') + u':\n\n%s'
        message = template % (PACKAGE_NAME, title, text) if title else template % (PACKAGE_NAME, text)

        if dialog:
            sublime.message_dialog(message)
        else:
            sublime.error_message(message)


class Base(Module):
    '''
    A base class extending the Module class with additional APIs for universal use.
    This class inherits all methods and attributes from the Module class.
    '''

    def __init__(self, view=None, uid=None, region=None, interpreters=None, executables=None, **kwargs):
        super().__init__(view=view, uid=uid, region=region, interpreters=interpreters, executables=executables, **kwargs)

    def remove_junk(self):
        parent_dir = dirname(dirname(__file__))
        items = [join(parent_dir, item) for item in ['.DS_Store', '.git']]

        for item in items:
            try:
                if isfile(item):
                    os.remove(item)
                elif isdir(item):
                    shutil.rmtree(item)
            except Exception as e:
                log.error('Error removing junk %s: %s', item, e)

    def generate_ascii_tree(self, reloaded_modules, package_name):
        tree = {}

        for module in reloaded_modules:
            parts = module.split('.')
            current_node = tree
            for part in parts:
                current_node = current_node.setdefault(part, {})

        def print_tree(node, prefix):
            sorted_keys = sorted(node.keys())
            for i, key in enumerate(sorted_keys):
                is_last = i == len(sorted_keys) - 1
                print(prefix + ('└── ' if is_last else '├── ') + key)
                print_tree(node[key], prefix + ('    ' if is_last else '│   '))

        print(package_name)
        print_tree(tree[package_name], '')

    def reload_modules(self, print_tree=False):
        reloaded_modules = []
        modules_copy = dict(sys.modules)

        for module_name, module in modules_copy.items():
            if module_name.startswith(PACKAGE_NAME + '.') and module:
                reloaded_modules.append(module_name)

                try:
                    reload(module)
                except Exception as e:
                    log.error('Error reloading module %s: %s', module_name, str(e))
                    return None

        log.debug('Reloaded modules (Python %s)', '.'.join(map(str, sys.version_info[:3])))
        if print_tree:
            self.generate_ascii_tree(reloaded_modules, PACKAGE_NAME)

    def config_file(self):
        return PACKAGE_NAME + '.sublime-settings'

    def quick_options_config_file(self):
        return join(sublime.packages_path(), 'User', QUICK_OPTIONS_SETTING_FILE)

    def get_config(self):
        settings = sublime.load_settings(self.config_file())
        settings.add_on_change('@reload@', self.load_config)
        self.build_config(settings)

    def load_config(self):
        settings = sublime.load_settings(self.config_file())
        self.build_config(settings)

    def load_quick_options(self):
        qo_file = self.quick_options_config_file()

        try:
            if isfile(qo_file):
                with open(qo_file, 'r') as f:
                    data = json.load(f)
                quick_options = data
            else:
                quick_options = config.get('quick_options', {})
        except Exception as e:
            quick_options = {}

        return quick_options

    def build_config(self, settings):
        try:
            global config

            # Sublime settings dict is immutable and unordered
            config = {
                'quick_options': self.load_quick_options(),
                'debug': settings.get('debug', False),
                'dev': settings.get('dev', False),
                'open_console_on_failure': settings.get('open_console_on_failure', False),
                'timeout': settings.get('timeout', 10),
                'custom_modules': settings.get('custom_modules', {}),
                'show_statusbar': settings.get('show_statusbar', True),
                'show_words_count': {
                    'enable': self.query(settings, True, 'show_words_count', 'enable'),
                    'ignore_whitespace_char': self.query(settings, True, 'show_words_count', 'ignore_whitespace_char')
                },
                'remember_session': settings.get('remember_session', True),
                'layout': {
                    'enable': self.query(settings, False, 'layout', 'enable'),
                    'sync_scroll': self.query(settings, False, 'layout', 'sync_scroll')
                },
                'environ': settings.get('environ', {}),
                'format_on_unique': settings.get('format_on_unique', {}),
                'formatters': settings.get('formatters', {})
            }

            config['formatters'].pop('examplegeneric', None)
            config['formatters'].pop('examplemodules', None)
            config = self.recursive_map(self.expand_path, config)
            return config
        except Exception as e:
            self.reload_modules(print_tree=False)
            sublime.set_timeout_async(self.load_config, 100)

    def is_quick_options_mode(self):
        return self.query(config, {}, 'quick_options')

    def sort_dict(self, dictionary):
        sorted_dict = {}
        for key, value in sorted(dictionary.items()):
            if isinstance(value, dict):
                sorted_dict[key] = self.sort_dict(value)
            elif isinstance(value, list):
                sorted_dict[key] = sorted(value)
            else:
                sorted_dict[key] = value
        return sorted_dict

    def get_mode_description(self, short=False):
        qo_memory = self.sort_dict(self.is_quick_options_mode())

        try:
            file = self.quick_options_config_file()
            with open(file, 'r') as f:
                qo_file = self.sort_dict(json.load(f))
        except FileNotFoundError:
            log.error('The file %s was not found.', file)
            qo_file = None
        except json.JSONDecodeError as e:
            log.error('Error decoding JSON: %s', e)
            qo_file = None
        except Exception as e:
            log.error('An error occurred: %s', e)
            qo_file = None

        mode_descriptions = {
            'Permanent User Settings': 'PUS',
            'Permanent Quick Options': 'PQO',
            'Temporary Quick Options': 'TQO'
        }

        if not qo_file and not qo_memory:
            mode = 'Permanent User Settings'
        elif qo_file != qo_memory:
            mode = 'Temporary Quick Options'
        elif qo_file:
            mode = 'Permanent Quick Options'

        return mode_descriptions[mode] if short else mode

    def assign_layout(self, layout):
        return LAYOUTS.get(layout, None)

    def want_layout(self):
        return self.query(config, False, 'layout', 'enable') in LAYOUTS

    def setup_layout(self, view):
        layout = self.query(config, False, 'layout', 'enable')

        if layout in LAYOUTS:
            view.window().set_layout(self.assign_layout(layout))
            return True

        return False

    def recursive_map(self, func, data):
        if isinstance(data, dict):
            return dict(map(lambda item: (item[0], self.recursive_map(func, item[1])), data.items()))
        elif isinstance(data, list):
            return list(map(lambda x: self.recursive_map(func, x), data))
        else:
            return func(data)

    def setup_shared_config_files(self):
        src = 'Packages/' + PACKAGE_NAME + '/config'
        dst = join(sublime.packages_path(), 'User', ASSETS_DIRECTORY, 'config')

        try:
            os.makedirs(dst, exist_ok=True)
        except OSError as e:
            if e.errno != os.errno.EEXIST:
                log.warning('Could not create directory: %s', dst)
            return None

        if not isdir(dst):
            log.warning('Could not create directory: %s', dst)
            return None

        for resource in sublime.find_resources('*'):
            if resource.startswith(src):
                file = basename(resource)
                path = join(dst, file)

                if isfile(path):
                    try:
                        res = sublime.load_binary_resource(resource)
                        hash_src = hashlib.md5(res).hexdigest()
                        hash_dst = self.md5f(path)
                        master_path = '{0}.{2}{1}'.format(*splitext(path) + ('master',))
                        hash_dst_master = self.md5f(master_path) if isfile(master_path) else None

                        if not hash_dst_master or (hash_dst_master and hash_src != hash_dst_master):
                            with open(master_path, 'wb') as f:
                                f.write(res)
                            log.debug('Setup shared master config: %s', master_path)
                    except Exception as e:
                        log.warning('Could not setup shared master config: %s\n%s', master_path, e)
                else:
                    try:
                        res = sublime.load_binary_resource(resource)
                        with open(path, 'wb') as f:
                            f.write(res)
                        log.debug('Setup shared config: %s', path)
                    except Exception as e:
                        log.warning('Could not setup shared config: %s\n%s', path, e)

        return True

    def md5f(self, file_path):
        hash_md5 = hashlib.md5()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_md5.update(chunk)

        return hash_md5.hexdigest()

    def md5d(self, dir_path):
        hash_md5 = hashlib.md5()

        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = join(root, file)
                hash_md5.update(self.md5f(file_path).encode('utf-8'))

        return hash_md5.hexdigest()

    def print_sysinfo(self):
        log.info('System environments:\n%s', json.dumps(self.update_environ(), ensure_ascii=False, indent=4))

        if self.is_quick_options_mode():
            log.info('Current mode: Quick Options: \n%s', json.dumps(self.query(config, {}, 'quick_options'), ensure_ascii=False, indent=4))
        else:
            log.info('Current mode: User Settings')

    def is_view(self, file_or_view):
        return (type(file_or_view) is sublime.View)

    def is_text_data(self, data):
        try:
            data = data.decode('utf-8')
            return data
        except (UnicodeDecodeError, AttributeError):
            return False

    def is_text_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    # Attempt to read the first line
                    next(f)
                except StopIteration:
                    # If the file is empty, return False
                    return False
            return True
        except UnicodeDecodeError:
            # If a UnicodeDecodeError occurs, the file is not a text file
            return False

    def get_unique(self, data):
        if isinstance(data, list):
            unique_list = []
            for item in data:
                if item not in unique_list:
                    unique_list.append(item)
            return unique_list
        elif isinstance(data, dict):
            unique_keys = []
            unique_values = []
            unique_dict = {}
            for key, value in data.items():
                if key not in unique_keys and value not in unique_values:
                    unique_keys.append(key)
                    unique_values.append(value)
                    unique_dict[key] = value
            return unique_dict
        else:
            raise ValueError('Input data type not supported')

    def get_recursive_filelist(self, dir, exclude_dirs_regex, exclude_files_regex, exclude_extensions):
        text_files = []

        for root, dirs, files in os.walk(dir):
            dirs[:] = [d for d in dirs if not any(re.match(pattern, d) for pattern in exclude_dirs_regex) and d not in [RECURSIVE_SUCCESS_DIRECTORY, RECURSIVE_FAILURE_DIRECTORY]]

            for file in files:
                p = self.get_pathinfo(file)
                if p['ext'] in exclude_extensions or not p['ext'] and p['base'] == p['stem'] and p['stem'] in exclude_extensions:
                    continue
                if any(re.match(pattern, file) for pattern in exclude_files_regex):
                    continue
                file_path = join(root, file)
                if self.is_text_file(file_path):
                    text_files.append(file_path)

        return text_files

    def expand_path(self, path):
        if path and isinstance(path, str):
            path = normpath(expanduser(expandvars(path)))
            path = sublime.expand_variables(path, sublime.active_window().extract_variables())
        return path


'''
Static helper APIs
'''

def read_settings_file(settings_file):
    try:
        with open(settings_file, 'r', encoding='utf-8') as f:
            file_content = f.read()
            return sublime.decode_value(file_content)
    except:
        return {}

def run_once(func):
    def wrapper(*args, **kwargs):
        if not wrapper.has_run:
            wrapper.has_run = True
            return func(*args, **kwargs)
    wrapper.has_run = False

    def reset_run():
        wrapper.has_run = False
    wrapper.reset_run = reset_run
    return wrapper

def setup_logger(name):
    formatter = logging.Formatter(fmt='▋[' + PACKAGE_NAME + '](%(filename)s#L%(lineno)s): [%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)
    return logger

def enable_logging():
    root_logger = logging.getLogger(PACKAGE_NAME)
    root_logger.setLevel(logging.DEBUG)

def disable_logging():
    root_logger = logging.getLogger(PACKAGE_NAME)
    root_logger.setLevel(logging.CRITICAL)
