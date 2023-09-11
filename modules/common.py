#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @rev          $Format:%H$ ($Format:%h$)
# @tree         $Format:%T$ ($Format:%t$)
# @date         $Format:%ci$
# @author       $Format:%an$ <$Format:%ae$>
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import hashlib
import logging
import os
import re
import sys
import tempfile
import sublime
if sys.version_info < (3, 4):
    from imp import reload
else:
    from importlib import reload
from subprocess import Popen, PIPE
from os.path import (basename, expanduser, expandvars, isdir, isfile, join,
                    exists, normcase, normpath, pathsep, split, splitext, dirname)

log = logging.getLogger(__name__)

IS_WINDOWS = sublime.platform() == 'windows'
PACKAGE_NAME = 'Formatter'
ASSETS_DIRECTORY = 'formatter.assets'
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

def reload_modules():
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
    log.debug('Reloaded modules (Python %s):', '.'.join(map(str, sys.version_info[:3])))
    generate_ascii_tree(reloaded_modules, PACKAGE_NAME)

def config_file():
    return PACKAGE_NAME + '.sublime-settings'

def get_config():
    settings = sublime.load_settings(config_file())
    settings.add_on_change('@reload@', load_config)
    build_config(settings)

def load_config():
    settings = sublime.load_settings(config_file())
    build_config(settings)

def build_config(settings):
    global config

    # Sublime settings dict is immutable and unordered
    config = {
        'debug': settings.get('debug', False),
        'dev': settings.get('dev', False),
        'open_console_on_failure': settings.get('open_console_on_failure', False),
        'show_statusbar': settings.get('show_statusbar', True),
        'layout': {
            'enable': query(settings, False, 'layout', 'enable'),
            'sync_scroll': query(settings, False, 'layout', 'sync_scroll')
        },
        'environ': settings.get('environ', {}),
        'formatters': settings.get('formatters', {})
    }
    config['formatters'].pop('example', None)
    config = recursive_map(expand_path, config)
    return config

def assign_layout(layout):
    return LAYOUTS.get(layout, None)

def want_layout():
    return query(config, False, 'layout', 'enable') in LAYOUTS

def setup_layout(view):
    layout = query(config, False, 'layout', 'enable')
    if layout in LAYOUTS:
        view.window().set_layout(assign_layout(layout))
        return True
    return False

def recursive_map(func, data):
    if isinstance(data, dict):
        return dict(map(lambda item: (item[0], recursive_map(func, item[1])), data.items()))
    elif isinstance(data, list):
        return list(map(lambda x: recursive_map(func, x), data))
    else:
        return func(data)

def update_environ():
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

def setup_shared_config_files():
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
                    hash_dst = md5f(path)
                    master_path = '{0}.{2}{1}'.format(*splitext(path) + ('master',))
                    hash_dst_master = md5f(master_path) if isfile(master_path) else None

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

def md5f(fname):
    hash_md5 = hashlib.md5()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_pathinfo(path):
    try:
        cwd = tempfile.gettempdir()
    except AttributeError:
        # Fallback to ${HOME} for unsaved buffer
        cwd = expanduser('~')
    base = stem = suffix = ext = None
    if path:
        cwd, base = split(path)
        stem, suffix = splitext(base)
        ext = suffix[1:]
    return {'path': path, 'cwd': cwd, 'base': base, 'stem': stem, 'suffix': suffix, 'ext': ext}

def exec_cmd(cmd, cwd):
    info = None
    if IS_WINDOWS:
        from subprocess import STARTUPINFO, STARTF_USESHOWWINDOW, SW_HIDE
        # Hide the console window to avoid flashing an
        # ugly cmd prompt on Windows when invoking plugin.
        info = STARTUPINFO()
        info.dwFlags |= STARTF_USESHOWWINDOW
        info.wShowWindow = SW_HIDE

    # Input cmd must be a list of strings
    process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE, cwd=cwd,
                    env=update_environ(), shell=IS_WINDOWS, startupinfo=info)
    return process

def query(data_dict, default=None, *keys):
    for key in keys:
        if not isinstance(data_dict, (dict, sublime.Settings)):
            return default
        data_dict = data_dict.get(key, default)
    return data_dict

def is_view(file_or_view):
    return (type(file_or_view) is sublime.View)

def is_text_data(data):
    try:
        data = data.decode('utf-8')
        return data
    except (UnicodeDecodeError, AttributeError):
        return False

def is_text_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            next(f)
        return True
    except UnicodeDecodeError:
        return False

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

def get_unique(data):
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

def get_recursive_filelist(dir, exclude_dirs_regex, exclude_files_regex, exclude_extensions):
    text_files = []
    for root, dirs, files in os.walk(dir):
        dirs[:] = [d for d in dirs if not any(re.match(pattern, d) for pattern in exclude_dirs_regex) and d not in [RECURSIVE_SUCCESS_DIRECTORY, RECURSIVE_FAILURE_DIRECTORY]]
        for file in files:
            p = get_pathinfo(file)
            if p['ext'] in exclude_extensions or not p['ext'] and p['base'] == p['stem'] and p['stem'] in exclude_extensions:
                continue
            if any(re.match(pattern, file) for pattern in exclude_files_regex):
                continue
            file_path = join(root, file)
            if is_text_file(file_path):
                text_files.append(file_path)
    return text_files

def expand_path(path):
    if path and isinstance(path, str):
        variables = sublime.active_window().extract_variables()
        path = sublime.expand_variables(path, variables)
        path = normpath(expanduser(expandvars(path)))
        # log.debug('Normalized path: %s', path)
    return path

def is_exe(file):
    if file and isinstance(file, str) and exists(file) and isfile(file):
        if os.access(file, os.F_OK | os.X_OK):
            return True
        if not IS_WINDOWS:
            import stat
            os.chmod(file, os.stat(file).st_mode | stat.S_IEXEC)
            log.debug('Set executable permission for: %s', file)
            return True
        log.warning('File exists but cannot be executed: %s', file)
    return False

def get_environ_path(fnames):
    if fnames and isinstance(fnames, list):
        environ = update_environ()
        if environ and isinstance(environ, dict):
            path = environ.get('PATH', os.defpath)
            if path:
                dirs = path.split(pathsep)
                if IS_WINDOWS:
                    pathext = os.environ.get('PATHEXT', '').split(pathsep)
                    final = [[fn, ext] for fn in fnames for ext in pathext if any([fn.lower().endswith(ext.lower())])]
                    if final:
                        files = [final[0][0]]
                    else:
                        files = [fn + ext for fn in fnames for ext in pathext]
                else:
                    files = fnames
                seen = set()
                for dir in dirs:
                    normdir = normcase(dir)
                    if not normdir in seen:
                        seen.add(normdir)
                        for thefile in files:
                            file = join(dir, thefile)
                            if is_exe(file):
                                return file
            else:
                log.error('"PATH" or default search path does not exist: %s', path)
        else:
            log.error('System environment is empty or not of type dict: %s', environ)
    else:
        log.error('File names variable is empty or not of type list: %s', fnames)
    return None

def get_head_cmd(uid, intr_names, exec_names):
    interpreter = get_runtime_path(uid, intr_names, 'interpreter')
    executable = get_runtime_path(uid, exec_names, 'executable')
    if not interpreter or not executable:
        return None
    cmd = [interpreter, executable]
    args = get_args(uid)
    if args:
        cmd.extend(args)
    return cmd

def get_runtime_path(uid, fnames, path_type):
    if path_type not in ['interpreter', 'executable']:
        log.error('Invalid runtime type. Either use the keyword "interpreter" or "executable".')
        return None

    local_file = query(config, None, 'formatters', uid, path_type + '_path')
    if local_file and not isfile(local_file):
        log.error('File does not exist: %s', local_file)
        return None
    if is_exe(local_file):
        log.debug('%s: %s', path_type.capitalize(), local_file)
        return local_file
    global_file = get_environ_path(fnames)
    if global_file:
        return global_file
    log.error('Could not find %s: %s', path_type, fnames)
    return None

def get_config_path(view, uid, region, is_selected):
    shared_config = query(config, None, 'formatters', uid, 'config_path')
    if shared_config and isinstance(shared_config, dict):
        syntax = get_assigned_syntax(view, uid, region, is_selected)
        for key, path in shared_config.items():
            if key.strip().lower() == syntax and path and isinstance(path, str) and isfile(path) and os.access(path, os.R_OK):
                log.debug('Config [%s]: %s', syntax, path)
                return path
        default_path = shared_config.get('default', None)
        if default_path and isinstance(default_path, str) and isfile(default_path) and os.access(default_path, os.R_OK):
            log.debug('Config [default]: %s', default_path)
            return default_path
        log.warning('Could not obtain config file for syntax: %s', syntax)
        log.warning('Default core config will be used instead if any.')
        return None
    log.warning('Setting key "config_path" is empty or not of type dict: %s', shared_config)
    log.warning('Default core config will be used instead if any.')
    return None

def get_assigned_syntax(view, uid, region, is_selected):
    syntaxes = query(config, None, 'formatters', uid, 'syntaxes')
    if syntaxes and isinstance(syntaxes, list):
        syntaxes = list(map(str.lower, filter(None, syntaxes)))
        scopes = view.scope_name(0 if not is_selected else region.a).strip().lower().split(' ')
        for syntax in syntaxes:
            for scope in scopes:
                if 'source.' + syntax + '.embedded' in scope:
                    return syntax
                if 'source.' + syntax == scope:
                    return syntax
        for syntax in syntaxes:
            for scope in scopes:
                if scope.endswith('.' + syntax):
                    return syntax
        for syntax in syntaxes:
            for scope in scopes:
                if '.' + syntax + '.' in scope:
                    return syntax
        for syntax in syntaxes:
            for scope in scopes:
                if scope.startswith(syntax + '.'):
                    return syntax
        return None
    log.error('Setting key "syntaxes" may not be empty and must be of type list: %s', syntaxes)
    return None

def get_args(uid):
    args = query(config, None, 'formatters', uid, 'args')
    if args and isinstance(args, list):
        return map(str, args)
    return None

def set_fix_cmds(cmd, uid):
    fix_cmds = query(config, None, 'formatters', uid, 'fix_commands')
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
                log.error('Items of "fix_commands" must be of type list.')
                return None
    return cmd

def prompt_error(text, name=None):
    if name:
        string = u'%s (%s):\n\n%s' % (PACKAGE_NAME, name, text)
    else:
        string = u'%s:\n\n%s' % (PACKAGE_NAME, text)
    sublime.error_message(string)

def setup_logger(name):
    formatter = logging.Formatter(fmt='▋[' + PACKAGE_NAME + '](%(threadName)s:%(filename)s#L%(lineno)s): [%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)
    return logger
