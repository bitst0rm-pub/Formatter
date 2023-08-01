#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @id           $Id$
# @rev          $Format:%H$ ($Format:%h$)
# @tree         $Format:%T$ ($Format:%t$)
# @date         $Format:%ci$
# @author       $Format:%an$ <$Format:%ae$>
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import os
from os.path import (basename, expanduser, expandvars, isdir, isfile, join,
                    exists, normpath, normcase, pathsep, split, splitext)
import sys
from imp import reload
import re
import hashlib
from subprocess import Popen, PIPE
import logging
import sublime

log = logging.getLogger('root')

IS_WINDOWS = sublime.platform() == 'windows'
VERSION = '1.0.1'
PLUGIN_NAME = 'Formatter'
ASSETS_DIRECTORY = 'formatter.assets'
RECURSIVE_SUCCESS_DIRECTORY = '__format_success__'
RECURSIVE_FAILURE_DIRECTORY = '__format_failure__'
STATUS_KEY = '@!' + PLUGIN_NAME.lower()

LOAD_ORDER = [
    '.src.formatter_beautysh',
    '.src.formatter_black',
    '.src.formatter_clangformat',
    '.src.formatter_cleancss',
    '.src.formatter_csscomb',
    '.src.formatter_eslint',
    '.src.formatter_htmlminifier',
    '.src.formatter_htmltidy',
    '.src.formatter_jsbeautifier',
    '.src.formatter_jsonmax',
    '.src.formatter_jsonmin',
    '.src.formatter_perltidy',
    '.src.formatter_phpcsfixer',
    '.src.formatter_prettier',
    '.src.formatter_prettydiffmax',
    '.src.formatter_prettydiffmin',
    '.src.formatter_prettytable',
    '.src.formatter_pythonminifier',
    '.src.formatter_rubocop',
    '.src.formatter_sqlformatter',
    '.src.formatter_sqlmin',
    '.src.formatter_stylelint',
    '.src.formatter_terser',
    '.src.formatter_uncrustify',
    '.src.formatter_yapf',
    '.src.formatter',
    '.src.common',
    '.main'
]


def reload_modules():
    modules = []
    for module in sys.modules:
        if module.startswith(PLUGIN_NAME + '.') and sys.modules[module]:
            modules.append(module)

    for module in LOAD_ORDER:
        module = PLUGIN_NAME + module
        if module in modules:
            log.debug('Reloading: %s', module)
            reload(sys.modules[module])

def config_file():
    return PLUGIN_NAME + '.sublime-settings'

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
    config = {}
    config['debug'] = settings.get('debug', False)
    config['open_console_on_failure'] = settings.get('open_console_on_failure', False)
    config['show_statusbar'] = settings.get('show_statusbar', True)
    config['environ'] = settings.get('environ', {})
    config['formatters'] = settings.get('formatters', {})
    config.get('formatters', {}).pop('example', None)
    config = recursive_map(expand_path, config)

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

def setup_shared_config():
    src = 'Packages/' + PLUGIN_NAME + '/config'
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
                    hash_dst = md5(path)
                    master_path = '{0}.{2}{1}'.format(*splitext(path) + ('master',))
                    hash_dst_master = md5(master_path) if isfile(master_path) else None

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

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_pathinfo(path):
    # Fallback to ${HOME} for unsaved buffer
    cwd = expanduser('~')
    base = stem = suffix = ext = None
    if path:
        cwd, base = split(path)
        stem, suffix = splitext(base)
        ext = suffix[1:]
    return (path, cwd, base, stem, suffix, ext)

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
        if not isinstance(data_dict, dict):
            return default
        data_dict = data_dict.get(key, default)
    return data_dict

def is_text_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            _ = f.readlines(1)
        return True
    except UnicodeDecodeError:
        return False

def get_recursive_filelist(dir, exclude_dirs_regex, exclude_files_regex, exclude_extensions):
    text_files = []
    for root, dirs, files in os.walk(dir):
        dirs[:] = [d for d in dirs if not any(re.match(pattern, d) for pattern in exclude_dirs_regex) and d not in [RECURSIVE_SUCCESS_DIRECTORY, RECURSIVE_FAILURE_DIRECTORY]]
        for file in files:
            p = get_pathinfo(file)
            if p[5] in exclude_extensions or not p[5] and p[2] == p[3] and p[3] in exclude_extensions:
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
            sta = os.stat(file)
            os.chmod(file, sta.st_mode | stat.S_IEXEC)
            log.debug('Set executable permission for: %s', file)
            return True
        log.warning('File exists but is not executable: %s', file)
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

def get_interpreter_path(fnames):
    global_file = get_environ_path(fnames)
    if global_file:
        log.debug('Interpreter: %s', global_file)
        return global_file
    log.error('Could not find interpreter: %s', fnames)
    return None

def get_executable_path(identifier, fnames):
    local_file = query(config, None, 'formatters', identifier, 'executable_path')
    if local_file and not isfile(local_file):
        log.warning('File does not exist: %s', local_file)
    if is_exe(local_file):
        log.debug('Executable: %s', local_file)
        return local_file
    global_file = get_environ_path(fnames)
    if global_file:
        return global_file
    log.error('Could not find executable: %s', fnames)
    return None

def get_config_path(view, identifier, region, is_selected):
    shared_config = query(config, None, 'formatters', identifier, 'config_path')
    if shared_config and isinstance(shared_config, dict):
        syntax = get_assigned_syntax(view, identifier, region, is_selected)
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

def get_assigned_syntax(view, identifier, region, is_selected):
    syntaxes = query(config, None, 'formatters', identifier, 'syntaxes')
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

def get_args(identifier):
    args = query(config, None, 'formatters', identifier, 'args')
    if args and isinstance(args, list):
        return map(str, args)
    return None

def set_fix_cmds(cmd, identifier):
    fix_cmds = query(config, None, 'formatters', identifier, 'fix_commands')
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
                        log.debug('Changed arguments: %s', cmd)
                    else:
                        log.error('index, count and position of "fix_commands" must be of type int.')
                        return None
            else:
                log.error('Items of "fix_commands" must be of type list.')
                return None
    return cmd

def prompt_error(text, name=None):
    if name:
        string = u'%s (%s):\n\n%s' % (PLUGIN_NAME, name, text)
    else:
        string = u'%s:\n\n%s' % (PLUGIN_NAME, text)
    sublime.error_message(string)

def setup_logger(name):
    formatter = logging.Formatter(fmt='▋[' + PLUGIN_NAME + '](%(threadName)s:%(filename)s#L%(lineno)s): [%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)
    return logger
