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
from os.path import (abspath, basename, expanduser, expandvars, isdir,
                     isfile, join, normpath, pathsep, split, splitext)
import sys
from imp import reload
import logging
import sublime


log = logging.getLogger('root')
IS_WINDOWS = sublime.platform() == 'windows'
VERSION = '0.1.5'
PLUGIN_NAME = 'Formatter'
ASSETS_DIRECTORY = 'formatter.assets'

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
    '.src.formatter_rubocop',
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


def update_environ():
    try:
        environ = os.environ.copy()
        env = settings().get('environ', None)
        if env and isinstance(env, dict):
            for key, value in env.items():
                if value and isinstance(value, list):
                    pathstring = environ.get(key, None)
                    items = list(filter(None, map(expand_path, value)))
                    if items:
                        if pathstring:
                            paths = pathstring.split(pathsep)
                            for item in items:
                                item = normpath(item)
                                ismatch = False
                                for path in paths:
                                    if path == item:
                                        ismatch = True
                                if not ismatch:
                                    paths.append(item)
                            environ[key] = pathsep.join(paths)
                        else:
                            environ[key] = pathsep.join(map(normpath, items))
        return environ
    except Exception as error:
        log.warning('Could not clone system environment: %s', error)
    return None


def setup_config():
    src = 'Packages/' + PLUGIN_NAME + '/config'
    dst = join(sublime.packages_path(), 'User', ASSETS_DIRECTORY, 'config')
    os.makedirs(dst, exist_ok=True)
    if not isdir(dst):
        log.warning('Could not create directory: %s', dst)
        return None

    for resource in sublime.find_resources('*'):
        if resource.startswith(src):
            file = basename(resource)
            path = join(dst, file)
            if not isfile(path):
                try:
                    content = sublime.load_resource(resource)
                    with open(path, 'w+', encoding='utf-8') as fil:
                        fil.write(content)
                    log.debug('Setup config: %s', path)
                except UnicodeDecodeError:
                    log.warning('Setup config skipped due to UnicodeDecodeError: %s', path)
    return True


def get_pathinfo(path):
    # Fallback to ${HOME} for unsaved buffer
    cwd = expanduser('~')
    base = None
    root = None
    ext = None
    if path:
        cwd, base = split(path)
        root, ext = splitext(base)
    return (path, cwd, base, root, ext)


def exec_cmd(cmd, path):
    from subprocess import Popen, PIPE
    if IS_WINDOWS:
        from subprocess import STARTUPINFO, STARTF_USESHOWWINDOW, SW_HIDE
        # Hide the console window
        info = STARTUPINFO()
        info.dwFlags |= STARTF_USESHOWWINDOW
        info.wShowWindow = SW_HIDE
    else:
        info = None

    process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE, cwd=get_pathinfo(path)[1],
                    env=update_environ(), shell=IS_WINDOWS, startupinfo=info)
    return process


def settings():
    base_name = PLUGIN_NAME + '.sublime-settings'
    prefs = sublime.load_settings(base_name)
    if prefs:
        return prefs
    log.error('Could not load settings file: %s', base_name)
    return None


def gets(dct, *keys):
    for key in keys:
        try:
            dct = dct.get(key)
        except AttributeError:
            log.error('Key assignment failed to: %s', key)
            return None
    return dct


def expand_path(path):
    if path and isinstance(path, str):
        variables = sublime.active_window().extract_variables()
        path = sublime.expand_variables(path, variables)
        return abspath(expanduser(expandvars(path)))
    return path


def is_exe(path):
    if path and isinstance(path, str) and isfile(path):
        if os.access(path, os.X_OK):
            return True
        if not IS_WINDOWS:
            import stat
            sta = os.stat(path)
            os.chmod(path, sta.st_mode | stat.S_IEXEC)
            log.debug('Set executable permission for: %s', path)
            return True
        log.warning('File exists but is not executable: %s', path)
        return False
    return False


def get_environ_path(fnames):
    if fnames and isinstance(fnames, list):
        environ = update_environ()
        if environ and isinstance(environ, dict):
            paths = environ.get('PATH', '').split(pathsep)
            for path in paths:
                for fname in fnames:
                    file = join(path, fname)
                    if IS_WINDOWS and not splitext(file)[1]:
                        for extension in ('.exe', '.cmd', '.bat'):
                            file_ext = file + extension
                            if is_exe(file_ext):
                                return file_ext
                    if is_exe(file):
                        return file
            log.error('Could not locate file in PATH environment: %s', fnames)
            return None
        log.error('System environment is empty or not of type dict: %s', environ)
        return None
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
    local_file = expand_path(gets(settings(), 'formatters', identifier, 'executable_path'))
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
    config = gets(settings(), 'formatters', identifier, 'config_path')
    if config and isinstance(config, dict):
        syntax = get_assign_syntax(view, identifier, region, is_selected)
        for key, value in config.items():
            if key.strip().lower() == syntax and value and isinstance(value, str):
                path = expand_path(value)
                if isfile(path) and os.access(path, os.R_OK):
                    log.debug('Config [%s]: %s', syntax, path)
                    return path
        default = config.get('default', None)
        if default and isinstance(default, str):
            path = expand_path(default)
            if isfile(path) and os.access(path, os.R_OK):
                log.debug('Config [default]: %s', path)
                return path
        log.warning('Could not obtain config file for syntax: %s', syntax)
        log.warning('Default config will be used instead.')
        return None
    log.warning('Setting key "config_path" is empty or not of type dict: %s', config)
    log.warning('Default config will be used instead.')
    return None


def get_assign_syntax(view, identifier, region, is_selected):
    syntaxes = gets(settings(), 'formatters', identifier, 'syntaxes')
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
        return None
    log.error('Setting key "syntaxes" may not be empty and must be of type list: %s', syntaxes)
    return None


def get_args(identifier):
    args = gets(settings(), 'formatters', identifier, 'args')
    if args and isinstance(args, list):
        return map(expand_path, args)
    return None


def show_error(text, name=None):
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
