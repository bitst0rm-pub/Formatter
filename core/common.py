import os
import re
import sys
import json
import time
import shutil
import struct
import hashlib
import logging
import tempfile
from datetime import datetime

if sys.version_info < (3, 4):
    from imp import reload
else:
    from importlib import reload

from subprocess import Popen, PIPE, TimeoutExpired
from os.path import (
    basename,
    expanduser,
    expandvars,
    isdir,
    isfile,
    join,
    normcase,
    normpath,
    pathsep,
    split,
    splitext,
    dirname
)

import sublime
from . import (
    log,
    enable_logging,
    enable_status,
    disable_logging
)

from .constants import (
    IS_WINDOWS,
    PACKAGE_NAME,
    ASSETS_DIRECTORY,
    QUICK_OPTIONS_SETTING_FILE,
    RECURSIVE_SUCCESS_DIRECTORY,
    RECURSIVE_FAILURE_DIRECTORY,
    STATUS_KEY,
    GFX_OUT_NAME,
    LAYOUTS
)


class Module(object):
    '''
    API for use with files located in the 'modules' folder.
    '''

    def __init__(self, view=None, uid=None, region=None, interpreters=None, executables=None, **kwargs):
        self.view = view
        self.uid = uid
        self.region = region
        self.interpreters = interpreters
        self.executables = executables
        self.dotfiles = kwargs.get('dotfiles', [])
        self.kwargs = kwargs or {}

    @staticmethod
    def _is_valid_file(file):
        return file and isinstance(file, str) and isfile(file)

    @staticmethod
    def _has_permission(file, permission, permission_name):
        if os.access(file, permission):
            return True
        log.warning('File exists but cannot get permission to %s: %s', permission_name, file)
        return False

    def is_executeable(self, file):
        if not self._is_valid_file(file):
            return False
        return self._has_permission(file, os.X_OK, 'execute')

    def is_readable(self, file):
        if not self._is_valid_file(file):
            return False
        return self._has_permission(file, os.R_OK, 'read')

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

            environ.update({'NO_COLOR': '1'})
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

    def popen(self, cmd, stdout=PIPE):
        info = None
        if IS_WINDOWS:
            from subprocess import STARTUPINFO, STARTF_USESHOWWINDOW, SW_HIDE
            # Hide the console window to avoid flashing an
            # ugly cmd prompt on Windows when invoking plugin.
            info = STARTUPINFO()
            info.dwFlags |= STARTF_USESHOWWINDOW
            info.wShowWindow = SW_HIDE

        # Input cmd must be a list of strings
        process = Popen(cmd, stdout=stdout, stdin=PIPE, stderr=PIPE, cwd=self.get_pathinfo()['cwd'],
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
            return 1, None, 'Aborted due to expired timeout=%s (adjust this in Formatter settings)' % str(timeout)

        self.kill(process)
        return process.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')

    def _exec_file_or_pipe_cmd(self, cmd, outfile=None):
        timeout = self.timeout()
        process = self.popen(cmd, outfile or PIPE)
        try:
            stdout, stderr = process.communicate(self.get_text_from_region(self.region).encode('utf-8'), timeout=timeout)
        except TimeoutExpired:
            self.kill(process)
            return 1, None, 'Aborted due to expired timeout=%s (adjust this in Formatter settings)' % str(timeout)

        self.kill(process)
        return process.returncode, '' if outfile else stdout.decode('utf-8'), stderr.decode('utf-8')

    def exec_cmd(self, cmd, outfile=None):
        if outfile:
            with open(outfile, 'wb') as file:
                returncode, stdout, stderr = self._exec_file_or_pipe_cmd(cmd, file)
        else:
            returncode, stdout, stderr = self._exec_file_or_pipe_cmd(cmd)

        return returncode, stdout, stderr

    def get_text_from_region(self, region):
        return self.view.substr(region)

    def is_view_formattable(self):
        return not (self.view.is_read_only() or not self.view.window() or self.view.size() == 0)

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

    def _get_active_view_parent_folders(self, active_file_path=None, max_depth=50):
        if not active_file_path:
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
        if self.is_generic_mode():
            path = self.query(config, None, 'formatters', self.uid, 'executable_path')
            if isinstance(path, list):
                self.executables = [self.get_pathinfo(p)['base'] for p in path]
            elif isinstance(path, str):
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
        return user_and_global_executable or None

    def get_interpreter(self):
        user_and_global_interpreter = self._get_path_for('interpreter')
        return user_and_global_interpreter or None

    def get_iprexe_cmd(self, runtime_type=None):
        user_files = self.query(config, None, 'formatters', self.uid, 'interpreter_path')
        if user_files:
            cmd = [self.get_interpreter(), self.get_executable(runtime_type)]
        else:
            cmd = [self.get_executable(runtime_type)]
        return cmd if all(cmd) else None

    def get_combo_cmd(self, runtime_type=None):
        cmd = self.get_iprexe_cmd(runtime_type)
        if cmd:
            cmd.extend(self.get_args())
        return cmd if all(cmd) else None

    def get_assigned_syntax(self, view=None, uid=None, region=None):
        kwargs = self.kwargs if hasattr(self, 'kwargs') else {}
        auto_format_config = kwargs.get('auto_format_config', {})
        if auto_format_config:
            for syntax, v in auto_format_config.items():
                self.uid = v.get('uid', None)
                kwargs = {
                    'is_auto_format': True,
                    'syntaxes': [syntax],
                    'exclude_syntaxes': v.get('exclude_syntaxes', {})
                }
                syntax = self._detect_assigned_syntax(view, uid, region, **kwargs)
                if syntax:
                    return syntax
        else:
            return self._detect_assigned_syntax(view, uid, region)

    def _detect_assigned_syntax(self, view=None, uid=None, region=None, **kwargs):
        if not all((view, uid, region)):
            view, uid, region = self.view, self.uid, self.region

        if kwargs.get('is_auto_format', False):
            syntaxes = kwargs.get('syntaxes')
            exclude_syntaxes = kwargs.get('exclude_syntaxes')
        else:
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

        #log.error('Setting key "syntaxes" must be a non-empty list: %s', syntaxes)
        return None

    def _read_config_file(self, paths, filenames):
        config = {}
        for path in reversed(paths):
            for filename in filenames:
                p = join(path, filename)
                if isfile(p):
                    try:
                        with open(p, 'r', encoding='utf-8') as f:
                            self.update_json_recursive(config, sublime.decode_value(f.read()))
                    except Exception as e:
                        log.error('Error reading %s at: %s', filename, p)
        return config

    def update_json_recursive(self, json_data, update_data):
        for key, value in update_data.items():
            if key in json_data and isinstance(value, dict) and isinstance(json_data[key], dict):
                self.update_json_recursive(json_data[key], value)
            else:
                json_data[key] = value

    def get_cfgignore(self, active_file_path=None):
        paths = self._get_active_view_parent_folders(active_file_path)
        return self._read_config_file(paths, ['.sublimeformatter.cfgignore.json', '.sublimeformatter.cfgignore'])

    def get_auto_format_config(self, active_file_path=None):
        paths = self._get_active_view_parent_folders(active_file_path)
        config = self._read_config_file(paths, ['.sublimeformatter.json', '.sublimeformatter'])
        if 'config' in config: config.pop('config')
        return {'auto_format_config': config} if config else {}

    def get_auto_format_user_config(self, active_file_path=None):
        paths = self._get_active_view_parent_folders(active_file_path)
        return self._read_config_file(paths, ['.sublimeformatter.user.json', '.sublimeformatter-user'])

    def get_auto_format_args(self, active_file_path=None):
        auto_format = self.query(config, {}, 'auto_format').copy()
        auto_format.update(self.get_auto_format_config(active_file_path).get('auto_format_config', {}))
        return {'auto_format_config': auto_format} if auto_format else {}

    def _traverse_find_config_dotfile(self):
        if not self.dotfiles:
            return None

        parent_folders = self._get_active_view_parent_folders()
        candidate_paths = []

        def should_stop_search(folder):
            return any(isdir(join(folder, vcs_dir)) for vcs_dir in ['.git', '.hg'])

        if parent_folders:
            for folder in parent_folders:
                candidate_paths.extend(join(folder, dotfile) for dotfile in self.dotfiles)
                if should_stop_search(folder):
                    break

        xdg_config_home = os.getenv('XDG_CONFIG_HOME')
        if xdg_config_home and not IS_WINDOWS:
            candidate_paths.extend(join(xdg_config_home, dotfile) for dotfile in self.dotfiles)
            for child in os.listdir(xdg_config_home):
                candidate_paths.extend(join(xdg_config_home, child, dotfile) for dotfile in self.dotfiles)
                break  # only look in the first child folder
        else:
            appdata = os.getenv('APPDATA')
            if appdata:
                candidate_paths.extend(join(appdata, dotfile) for dotfile in self.dotfiles)
                for child in os.listdir(appdata):
                    candidate_paths.extend(join(appdata, child, dotfile) for dotfile in self.dotfiles)
                    break

        for path in candidate_paths:
            if self.is_readable(path):
                log.debug('Auto-set "config_path" to the detected dot file: %s', path)
                return path

        return None

    def get_config_path(self):
        ignore_config_path = self.query(config, [], 'quick_options', 'ignore_config_path')
        if self.uid in ignore_config_path:
            return None

        shared_config = self.query(config, None, 'formatters', self.uid, 'config_path')

        if shared_config and isinstance(shared_config, dict):
            syntax = self.get_assigned_syntax()

            for k, v in self.get_cfgignore().items():
                if (k.strip().lower() == syntax or k == 'default') and self.uid in v:
                    return None

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
            log.info('User specific "config_path" is not set: %s', shared_config)

            dotfile_path = self._traverse_find_config_dotfile()
            if dotfile_path:
                return dotfile_path

        log.info('Running third-party plugin without specifying any "config_path"')
        return None

    def is_valid_path(self, path):
        return path and isinstance(path, str) and isfile(path) and os.access(path, os.R_OK)

    @staticmethod
    def convert_list_items_to_string(lst):
        return list(map(str, lst)) if lst and isinstance(lst, list) else []

    def get_args(self):
        args = self.query(config, None, 'formatters', self.uid, 'args')
        return self.convert_list_items_to_string(args)

    def is_render_extended(self):
        if self.query(config, {}, 'quick_options'):
            render_extended = self.uid in self.query(config, [], 'quick_options', 'render_extended')
        else:
            render_extended = self.query(config, False, 'formatters', self.uid, 'render_extended')

        return isinstance(render_extended, bool) and render_extended

    def get_args_extended(self):
        if self.is_render_extended():
            args_extended = self.query(config, {}, 'formatters', self.uid, 'args_extended')
            valid = {}
            for k, v in args_extended.items():
                valid[k.strip().lower()] = self.convert_list_items_to_string(v)
            return valid
        else:
            return {}

    @staticmethod
    def ext_png_to_svg_cmd(cmd):
        return [x.replace(GFX_OUT_NAME + '.png', GFX_OUT_NAME+ '.svg') for x in cmd]

    @staticmethod
    def all_png_to_svg_cmd(cmd):
        return [x.replace('png', 'svg') for x in cmd]

    def get_output_image(self):
        temp_dir = self.kwargs.get('temp_dir', None)
        if temp_dir and self.kwargs.get('type', None) == 'graphic':
            temp_dir = join(temp_dir, GFX_OUT_NAME + '.png')
            return temp_dir
        else:
            log.error('Wrong args param: get_output_image() is only applicable to type: graphic')
            return '!wrong_param!'

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

    def is_empty_or_whitespace(self, s):
        return s is not None and not s.strip()

    def print_exiterr(self, exitcode, stderr):
        sep = '=' * 87
        s = 'File not formatted due to an error (exitcode=%d)' % exitcode
        log.status(s + '.' if self.is_empty_or_whitespace(stderr) else s + ':\n%s\n%s\n%s' % (sep, stderr, sep))

    def print_oserr(self, cmd):
        log.status('An error occurred while executing the command: %s', ' '.join(cmd))


class Base(Module):
    '''
    Extended API for universal use.
    '''

    def __init__(self, view=None, uid=None, region=None, interpreters=None, executables=None, **kwargs):
        super().__init__(view=view, uid=uid, region=region, interpreters=interpreters, executables=executables, **kwargs)

    @staticmethod
    def remove_junk():
        try:
            parent_dir = dirname(dirname(__file__))
            items = [join(parent_dir, item) for item in ['.DS_Store', '.editorconfig', '.gitattributes', '.gitignore', '.git']]

            for item in items:
                if isfile(item):
                    os.remove(item)
                elif isdir(item):
                    shutil.rmtree(item)
        except Exception as e:
            pass

    @staticmethod
    def generate_ascii_tree(reloaded_modules, package_name):
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

        prefix = PACKAGE_NAME + '.'
        for module_name, module in tuple(filter(lambda item: item[0].startswith(prefix), sys.modules.items())):
            try:
                reload(module)
                reloaded_modules.append(module_name)
            except Exception as e:
                log.error('Error reloading module %s: %s', module_name, str(e))
                return None

        log.debug('Reloaded modules (Python %s)', '.'.join(map(str, sys.version_info[:3])))
        if print_tree:
            self.generate_ascii_tree(reloaded_modules, PACKAGE_NAME)

    @staticmethod
    def config_file():
        return PACKAGE_NAME + '.sublime-settings'

    @staticmethod
    def quick_options_config_file():
        return join(sublime.packages_path(), 'User', QUICK_OPTIONS_SETTING_FILE)

    @staticmethod
    def load_settings(file):
        return sublime.load_settings(file)

    def get_config(self):
        settings = self.load_settings(self.config_file())
        settings.add_on_change('@reload@', self.load_config)
        self.build_config(settings)

    def load_config(self):
        settings = self.load_settings(self.config_file())
        self.build_config(settings)

    def load_quick_options(self):
        qo_file = self.quick_options_config_file()

        try:
            if isfile(qo_file):
                with open(qo_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                quick_options = data
            else:
                quick_options = config.get('quick_options', {})
        except Exception as e:
            quick_options = {}

        return quick_options

    def project_config_overwrites_config(self, config):
        project_data = sublime.active_window().project_data()
        project_settings = self.query(project_data, {}, 'settings', PACKAGE_NAME)
        if project_settings:
            self.update_json_recursive(config, project_settings)

    def load_sublime_preferences(self):
        global sublime_preferences

        try:
            sublime_preferences = self.load_settings('Preferences.sublime-settings')
        except Exception as e:
            sublime_preferences = {}

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
                    'ignore_whitespace_char': self.query(settings, True, 'show_words_count', 'ignore_whitespace_char'),
                    'use_short_label': self.query(settings, False, 'show_words_count', 'use_short_label')
                },
                'remember_session': settings.get('remember_session', True),
                'layout': {
                    'enable': self.query(settings, '2cols', 'layout', 'enable'),
                    'sync_scroll': self.query(settings, True, 'layout', 'sync_scroll')
                },
                'environ': settings.get('environ', {}),
                'format_on_priority': settings.get('format_on_priority', {}),
                'format_on_unique': settings.get('format_on_unique', {}),
                'auto_format': settings.get('auto_format', {}),
                'formatters': settings.get('formatters', {})
            }

            config['formatters'].pop('examplegeneric', None)
            config['formatters'].pop('examplemodule', None)
            self.project_config_overwrites_config(config)
            config = self.recursive_map(self.expand_path, config)
            return config
        except Exception as e:
            self.reload_modules(print_tree=False)
            sublime.set_timeout_async(self.load_config, 100)

    @staticmethod
    def clear_console():
        if sublime_preferences:
            current = sublime_preferences.get('console_max_history_lines', None)
            if current is None:
                return  # <ST4088

            sublime_preferences.set('console_max_history_lines', 1)
            print('')
            sublime_preferences.set('console_max_history_lines', current)

    @staticmethod
    def style_view(dst_view):
        style = {
            'highlight_line': False,
            'highlight_gutter': False,
            'highlight_line_number': False,
            'block_caret': False,
            'gutter': False,
            'word_wrap': False
        }

        for k, v in style.items():
            if dst_view.settings().get(k):
                dst_view.settings().set(k, v)

    @staticmethod
    def markdown_to_html(markdown):
        html = []
        lines = markdown.split('\n')

        # Regular expressions for Markdown syntax
        heading_re = re.compile(r'^(#{1,6})\s*(.*)')
        link_re = re.compile(r'\[([^\[\]]+)\]\(([^()]+)\)')
        bold_re = re.compile(r'\*\*(.*?)\*\*')
        italic_re = re.compile(r'\*(.*?)\*')
        code_re = re.compile(r'`(.*?)`')
        commit_re = re.compile(r'\[`(.*?)`\]\((.*?)\)')
        github_issue_re = re.compile(r'(?<!\<a href=")https?://github\.com/([^/]+/[^/]+)/(issues|pull)/(\d+)')

        in_code_block = False
        in_list = False

        for line in lines:
            # Skip HTML comments generated by git-cliff
            if line.strip().startswith('<!--'):
                continue

            if line.startswith('```'):
                html.append('</code>' if in_code_block else '<code>')
                in_code_block = not in_code_block
                continue

            if in_code_block:
                html.append(line)
                continue

            # Headings
            heading_match = heading_re.match(line)
            if heading_match:
                level = len(heading_match.group(1))
                content = heading_match.group(2)
                line = '<h{0}>{1}</h{0}>'.format(level, content)
                if level <= 2:  # Only add <hr> after H1 and H2
                    line += '<hr>'

            # Links
            line = link_re.sub(r'<a href="\2">\1</a>', line)

            # Commit links (inline code with links)
            line = commit_re.sub(r'<a href="\2"><code>\1</code></a>', line)

            # GitHub issue links
            line = github_issue_re.sub(r'<a href="https://github.com/\1/\2/\3">\1#\3</a>', line)

            # Bold and italic
            line = bold_re.sub(r'<strong>\1</strong>', line)
            line = italic_re.sub(r'<em>\1</em>', line)

            # Inline code
            line = code_re.sub(r'<code>\1</code>', line)

            # Lists (simple implementation for unordered lists)
            if line.startswith('- '):
                if not in_list:
                    html.append('<ul>')
                    in_list = True
                line = '<li>' + line[2:] + '</li>'
            else:
                if in_list:
                    html.append('</ul>')
                    in_list = False

            html.append(line)

        if in_list:
            html.append('</ul>')

        return '''
        <body id="phantom-body">
            <style>
                a {text-decoration:none}
                code {font-family:ui-monospace,SFMono-Regular,SF Mono,Menlo,Consolas,Liberation Mono,monospace;background-color:#afb8c133;padding:.1em .2em;border-radius:4px;}
            </style>
            <div class="container">
                ''' + '\n'.join(html) + '''
            </div>
        </body>
        '''

    def set_html_phantom(self, dst_view, image_data, image_width, image_height, fit_image_width, fit_image_height, extended_data):
        self.style_view(dst_view)

        image_tag = '<img class="image" src="data:image/png;base64,' + image_data + '" width="' + str(fit_image_width) + '" height="' + str(fit_image_height) + '">'
        dimension = '<div class="image-dimension"><span class="dimension-text">' + str(image_width) + ' x ' + str(image_height) + '</span></div>'
        zoom_link = '<div class="zoom-link"><span class="button"><a href="zoom_image">Zoom</a></span></div>'
        download_link = '<div class="download-link"><span class="button"><a href="data:application/png;base64,' + image_data + '" download>Save PNG</a></span></div>'

        extended_download_link = []
        for ext, image_data in extended_data.items():
            extended_download_link.append('<div class="download-link"><span class="button"><a href="data:application/' + ext + ';base64,' + image_data + '" download>Save ' + ext.upper() + '</a></span></div>')

        html = '''
        <body id="phantom-body">
            <style>
                html, body {display:block;margin:0;padding:0;text-align:center;border-style:none;width:''' + str(dst_view.viewport_extent()[0]) + '''px;}
                .container {display:block;margin:0 auto;text-align:center;font-weight:bold;padding:2rem 0;}
                .image {margin:0 auto;}
                a {text-decoration:none;color:#FF8C00;}
                span.button {border:1px solid #FF8C00;border-radius:0.313rem;padding:.125rem .375rem;}
                .image-dimension {font-weight:normal;font-size:0.8rem;margin-top:1rem;}
                .zoom-link {margin-top:.625rem;margin-bottom:1.125rem;}
                .download-link {display:inline;padding:0 .313rem;}
            </style>
            <div class="container">
                ''' + image_tag + dimension + zoom_link + download_link + ''.join(extended_download_link) + '''
            </div>
        </body>
        '''
        return html

    @staticmethod
    def get_image_size(data):
        if data.startswith(b'\211PNG\r\n\032\n') and (data[12:16] == b'IHDR'):
            width, height = struct.unpack('>LL', data[16:24])
            return int(width), int(height)
        elif data.startswith(b'\211PNG\r\n\032\n'):
            width, height = struct.unpack('>LL', data[8:16])
            return int(width), int(height)
        else:
            return None, None

    @staticmethod
    def image_scale_fit(view, image_width, image_height):
        image_width = image_width or 300  # default to 300 if None
        image_height = image_height or 300
        scrollbar_width = 20  # adjust this if needed

        view_width, view_height = view.viewport_extent()
        width_scale = view_width / image_width
        height_scale = view_height / image_height
        scale_factor = min(width_scale, height_scale)
        image_width = round(int(image_width * scale_factor)) - scrollbar_width
        image_height = round(int(image_height * scale_factor)) - scrollbar_width

        return image_width, image_height

    def is_generic_method(self):
        name = self.query(config, None, 'formatters', self.kwargs.get('uid'), 'name')
        return name is not None

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
            with open(file, 'r', encoding='utf-8') as f:
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

                        if hash_src != hash_dst and (not hash_dst_master or hash_src != hash_dst_master):
                            with open(master_path, 'wb') as f:
                                f.write(res)
                        elif hash_dst_master:
                            os.remove(master_path)

                    except Exception as e:
                        log.warning('Could not setup shared master config: %s\n%s', master_path, e)
                else:
                    try:
                        res = sublime.load_binary_resource(resource)
                        with open(path, 'wb') as f:
                            f.write(res)
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

    def print_sysinfo(self, pretty=False):
        if self.query(config, False, 'environ', 'print_on_console'):
            log.info('Environments:\n%s', json.dumps(self.update_environ(), ensure_ascii=False, indent=4 if pretty else None))

            if self.is_quick_options_mode():
                log.info('Mode: Quick Options: \n%s', json.dumps(self.query(config, {}, 'quick_options'), ensure_ascii=False, indent=4 if pretty else None))
            else:
                log.info('Mode: User Settings')

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
                    next(f)
                except StopIteration:
                    return False
            return True
        except UnicodeDecodeError:
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

    def get_downloads_folder(self):
        downloads_folder = join(expanduser('~'), 'Downloads')

        try:
            os.makedirs(downloads_folder, exist_ok=True)
        except Exception as e:
            return tempfile.TemporaryDirectory()

        return downloads_folder

    def set_debug_mode(self):
        if self.is_quick_options_mode():
            debug = self.query(config, False, 'quick_options', 'debug')
        else:
            debug = config.get('debug')

        if debug == 'status':
            enable_status()
        elif (isinstance(debug, str) and debug.strip().lower() == 'true') or (debug == True):
            enable_logging()
        else:
            disable_logging()


'''
Static helper API
'''

def read_settings_file(settings_file):
    try:
        with open(settings_file, 'r', encoding='utf-8') as f:
            file_content = f.read()
            return sublime.decode_value(file_content)
    except Exception as e:
        return {}
