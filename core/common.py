import abc
import hashlib
import json
import os
import re
import shutil
import signal
import struct
import sys
import tempfile
from copy import deepcopy
from functools import lru_cache
from os.path import (basename, dirname, expanduser, expandvars, isdir, isfile,
                     join, normcase, normpath, pathsep, split, splitext)
from subprocess import PIPE, Popen, TimeoutExpired

import sublime

from . import (check_deprecated_api, check_deprecated_options, disable_logging,
               enable_logging, enable_status, log, retry_on_exception,
               sanitize_cmd_output, transform_cmd_arg, validate_cmd_arg)
from .constants import (ASSETS_DIRECTORY, AUTO_FORMAT_ACTION_KEY, GFX_OUT_NAME,
                        IS_WINDOWS, LAYOUTS, PACKAGE_NAME,
                        QUICK_OPTIONS_SETTING_FILE,
                        RECURSIVE_FAILURE_DIRECTORY,
                        RECURSIVE_SUCCESS_DIRECTORY)

if IS_WINDOWS:
    from subprocess import (CREATE_NEW_PROCESS_GROUP, STARTF_USESHOWWINDOW,
                            STARTUPINFO, SW_HIDE)

CONFIG = {}
PROJECT_CONFIG = {}
SUBLIME_PREFERENCES = {}


###################################################
# === Module Class and Its Supporting Classes === #
###################################################

class ModuleMeta(abc.ABCMeta):
    def __init__(cls, name, bases, namespace, **kwargs):
        super().__init__(name, bases, namespace, **kwargs)

        if cls.__module__.startswith(PACKAGE_NAME + '.modules.formatter_') and 'formatter_generic' not in cls.__module__:
            module = sys.modules[cls.__module__]
            if 'MODULE_CONFIG' not in module.__dict__:
                raise NotImplementedError(name + ' must define a MODULE_CONFIG dictionary at the module level.')


class Module(metaclass=ModuleMeta):
    '''
    API solely for interacting with files located in the 'modules' folder.
    '''

    def __init__(self, view=None, uid=None, region=None, interpreters=None, executables=None, dotfiles=None, temp_dir=None, type=None, auto_format_config=None, **kwargs):
        self.view = view
        self.uid = uid
        self.region = region
        self.interpreters = interpreters
        self.executables = executables
        self.dotfiles = dotfiles
        self.temp_dir = temp_dir
        self.type = type
        self.auto_format_config = auto_format_config
        self.kwargs = kwargs  # @unused

    @abc.abstractmethod
    def format(self):
        raise NotImplementedError('Subclasses must implement the "format()" method.')

    def is_executable(self, file=None):
        return FileHandler.is_executable(file=file)

    def is_readable(self, file=None):
        return FileHandler.is_readable(file=file)

    def get_pathinfo(self, path=None):
        return PathHandler.get_pathinfo(view=self.view, path=path)

    def is_valid_path(self, path=None):
        return PathHandler.is_valid_path(path=path)

    def update_environ(self, dict_to_update=None):
        return EnvironmentHandler.update_environ(dict_to_update=dict_to_update)

    def get_environ_path(self, fnames=None):
        return EnvironmentHandler.get_environ_path(fnames=fnames)

    def exec_com(self, cmd=None):
        return CommandHandler.exec_com(view=self.view, uid=self.uid, cmd=cmd)

    def exec_cmd(self, cmd=None, outfile=None):
        return CommandHandler.exec_cmd(view=self.view, uid=self.uid, region=self.region, cmd=cmd, outfile=outfile)

    def get_success_code(self):
        return CommandHandler.get_success_code(uid=self.uid)

    def print_exiterr(self, exitcode=None, stderr=None):
        return CommandHandler.print_exiterr(exitcode=exitcode, stderr=stderr)

    def print_oserr(self, cmd=None, error=''):
        return CommandHandler.print_oserr(cmd=cmd, error=error)

    def get_text_from_region(self, region=None):
        return ViewHandler.get_text_from_region(view=self.view, region=region)

    def is_view_formattable(self):
        return ViewHandler.is_view_formattable(view=self.view)

    def query(self, data_dict, default=None, *keys):
        return OptionHandler.query(data_dict, default, *keys)

    def create_tmp_file(self, suffix=None):
        return TempFileHandler.create_tmp_file(view=self.view, uid=self.uid, region=self.region, auto_format_config=self.auto_format_config, suffix=suffix)

    def remove_tmp_file(self, tmp_file=None):
        return TempFileHandler.remove_tmp_file(tmp_file=tmp_file)

    def get_executable(self, runtime_type=None):
        return ArgumentHandler.get_executable(view=self.view, uid=self.uid, executables=self.executables, runtime_type=runtime_type)

    def get_interpreter(self):
        return ArgumentHandler.get_interpreter(view=self.view, uid=self.uid, interpreters=self.interpreters)

    def get_iprexe_cmd(self, runtime_type=None):
        return ArgumentHandler.get_iprexe_cmd(view=self.view, uid=self.uid, interpreters=self.interpreters, executables=self.executables, runtime_type=runtime_type)

    def get_combo_cmd(self, runtime_type=None):
        return ArgumentHandler.get_combo_cmd(view=self.view, uid=self.uid, interpreters=self.interpreters, executables=self.executables, runtime_type=runtime_type)

    def get_args(self):
        return ArgumentHandler.get_args(uid=self.uid)

    def get_config_path(self):
        return ArgumentHandler.get_config_path(view=self.view, uid=self.uid, region=self.region, dotfiles=self.dotfiles, auto_format_config=self.auto_format_config)

    @check_deprecated_api(start_date='2024-07-30', deactivate_after_days=90)
    def is_valid_cmd(self, cmd=None):  # @deprecated
        return ArgumentHandler.is_valid_cmd(cmd=cmd)

    @check_deprecated_api(start_date='2024-07-30', deactivate_after_days=90)
    def fix_cmd(self, cmd=None):  # @deprecated
        return ProcessHandler(view=self, uid=self.uid).fix_cmd(cmd=cmd)

    def get_assigned_syntax(self):
        uid, syntax = SyntaxHandler.get_assigned_syntax(view=self.view, uid=self.uid, region=self.region, auto_format_config=self.auto_format_config)
        self.uid = uid  # update for auto format
        return syntax

    def update_json_recursive(self, json_data=None, update_data=None):
        return StringHandler.update_json_recursive(json_data=json_data, update_data=update_data)

    def is_render_extended(self):
        return GraphicHandler.is_render_extended(uid=self.uid)

    def get_args_extended(self):
        return GraphicHandler.get_args_extended(uid=self.uid)

    def ext_png_to_svg_cmd(self, cmd=None):
        return GraphicHandler.ext_png_to_svg_cmd(cmd=cmd)

    def all_png_to_svg_cmd(self, cmd=None):
        return GraphicHandler.all_png_to_svg_cmd(cmd=cmd)

    def get_output_image(self):
        return GraphicHandler.get_output_image(temp_dir=self.temp_dir, type=self.type)

    def popup_message(self, text, title=None, dialog=False):
        return InterfaceHandler.popup_message(text, title, dialog)


# === Module Supporting Classes === #

class FileHandler:
    @staticmethod
    def _is_valid_file(file=None):
        return file and isinstance(file, str) and isfile(file)

    @staticmethod
    def _has_permission(file, permission, permission_name):
        if os.access(file, permission):
            return True
        log.warning('File exists but cannot get permission to %s: %s', permission_name, file)
        return False

    @classmethod
    @lru_cache(maxsize=128)
    def is_executable(cls, file=None):
        if not cls._is_valid_file(file=file):
            return False
        return cls._has_permission(file, os.X_OK, 'execute')

    @classmethod
    @lru_cache(maxsize=128)
    def is_readable(cls, file=None):
        if not cls._is_valid_file(file=file):
            return False
        return cls._has_permission(file, os.R_OK, 'read')


class PathHandler:
    @staticmethod
    def get_pathinfo(view=None, path=None):
        base = stem = suffix = ext = None

        if not path:
            path = view.file_name()

        if path:
            cwd, base = split(path)
            stem, suffix = splitext(base)
            ext = suffix[1:]
        else:
            try:
                cwd = tempfile.gettempdir()
            except Exception:
                cwd = expanduser('~')  # fallback for buffer

        return {'path': path, 'cwd': cwd, 'base': base, 'stem': stem, 'suffix': suffix, 'ext': ext}

    @staticmethod
    def is_valid_path(path=None):
        return path and isinstance(path, str) and isfile(path) and os.access(path, os.R_OK)


class EnvironmentHandler:
    @staticmethod
    def update_environ(dict_to_update=None):
        try:
            environ = os.environ.copy()

            for key, value in OptionHandler.query(CONFIG, {}, 'environ').items():
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
            if dict_to_update and isinstance(dict_to_update, dict):
                environ.update(dict_to_update)

            return environ
        except Exception as e:
            log.warning('Could not clone system environment: %s', e)

        return None

    @classmethod
    def get_environ_path(cls, fnames=None):
        if fnames and isinstance(fnames, list):
            environ = cls.update_environ()
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
                        if normdir not in seen:
                            seen.add(normdir)
                            for f in files:
                                file = join(dir, f)
                                if FileHandler.is_executable(file=file):
                                    return file
                else:
                    log.error('"PATH" or default search path does not exist: %s', path)
            else:
                log.error('System environment is empty or not of type dict: %s', environ)
        else:
            log.error('File names variable is empty or not of type list: %s', fnames)

        return None


class ProcessHandler:
    def __init__(self, view=None, uid=None):
        self.view = view
        self.uid = uid
        self.process = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.process and self.is_alive(process=self.process):
            self.kill(process=self.process)

    def fix_cmd(self, cmd=None):
        fix_cmds = OptionHandler.query(CONFIG, None, 'formatters', self.uid, 'fix_commands')

        if fix_cmds and isinstance(fix_cmds, list) and cmd and isinstance(cmd, list):
            for x in fix_cmds:
                if isinstance(x, list):
                    length = len(x)

                    if 3 <= length <= 5:
                        search = str(x[length - 5])
                        replace = str(x[length - 4])
                        index = int(x[length - 3])
                        count = int(x[length - 2])
                        position = int(x[length - 1])

                        for i, item in enumerate(cmd):
                            item = str(item)

                            if index == i:
                                if length == 5:
                                    if search == item and position < 0:
                                        cmd.pop(i)
                                    else:
                                        cmd[i] = re.sub(r'%s' % search, replace, item, count)
                                if length == 4:
                                    cmd[i] = replace
                                if length == 3 and position < 0:
                                    cmd.pop(i)
                                if position > -1:
                                    cmd.insert(position, cmd.pop(i))

                        log.debug('Fixed command: %s', cmd)
                    else:
                        log.error('Each list item in "fix_commands" must contain between 3 and 5 elements.')
                        return None
                else:
                    log.error('Items of "fix_commands" must be of type list.')
                    return None

        return cmd

    @validate_cmd_arg
    @transform_cmd_arg(fix_cmd)
    def popen(self, cmd=None, stdout=PIPE):
        cwd = PathHandler.get_pathinfo(view=self.view)['cwd']
        env = EnvironmentHandler.update_environ()
        info = None

        if IS_WINDOWS:
            # Hide the console window
            info = STARTUPINFO()
            info.dwFlags |= STARTF_USESHOWWINDOW
            info.wShowWindow = SW_HIDE

            # Input cmd must be a list of strings
            self.process = Popen(
                cmd, stdout=stdout, stdin=PIPE, stderr=PIPE, shell=True,
                cwd=cwd, env=env, startupinfo=info,
                creationflags=CREATE_NEW_PROCESS_GROUP
            )
        else:
            self.process = Popen(
                cmd, stdout=stdout, stdin=PIPE, stderr=PIPE, shell=False,
                cwd=cwd, env=env, startupinfo=info
            )

        return self.process

    def kill(self, process=None):
        try:
            if self.is_alive(process=process):
                if IS_WINDOWS:
                    os.kill(process.pid, signal.CTRL_BREAK_EVENT)
                else:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                process.wait(timeout=1)  # 1s

            if self.is_alive(process=process):
                process.kill()
                process.wait(timeout=1)
        except Exception as e:
            log.error('Error terminating process: %s', e)

    @staticmethod
    def is_alive(process=None):
        return process.poll() is None

    @staticmethod
    def timeout():
        timeout = OptionHandler.query(CONFIG, 10, 'timeout')
        return timeout if not isinstance(timeout, bool) and isinstance(timeout, int) else None


class CommandHandler:
    @staticmethod
    def exec_com(view=None, uid=None, cmd=None):
        with ProcessHandler(view=view, uid=uid) as ph:
            timeout = ph.timeout()
            process = ph.popen(cmd=cmd)

            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except TimeoutExpired:
                return 1, None, 'Aborted due to expired timeout=%s (Tip: Increase execution timeout in Formatter settings)' % str(timeout)
            except Exception as e:
                return 1, None, 'Error during process execution: %s' % e

            return process.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')

    @staticmethod
    def _exec_file_or_pipe_cmd(view=None, uid=None, region=None, cmd=None, outfile=None):
        with ProcessHandler(view=view, uid=uid) as ph:
            timeout = ph.timeout()
            process = ph.popen(cmd=cmd, stdout=(outfile or PIPE))
            text = ViewHandler.get_text_from_region(view=view, region=region)

            try:
                stdout, stderr = process.communicate(text.encode('utf-8'), timeout=timeout)
            except TimeoutExpired:
                return 1, None, 'Aborted due to expired timeout=%s (Tip: Increase execution timeout in Formatter settings)' % str(timeout)
            except Exception as e:
                return 1, None, 'Error during process execution: %s' % e

            return process.returncode, '' if outfile else stdout.decode('utf-8'), stderr.decode('utf-8')

    @classmethod
    @sanitize_cmd_output
    def exec_cmd(cls, view=None, uid=None, region=None, cmd=None, outfile=None):
        if outfile:
            with open(outfile, 'wb') as file:
                returncode, stdout, stderr = cls._exec_file_or_pipe_cmd(view=view, uid=uid, region=region, cmd=cmd, outfile=file)
        else:
            returncode, stdout, stderr = cls._exec_file_or_pipe_cmd(view=view, uid=uid, region=region, cmd=cmd)

        return returncode, stdout, stderr

    @staticmethod
    def get_success_code(uid=None):
        return int(OptionHandler.query(CONFIG, 0, 'formatters', uid, 'success_code'))

    @staticmethod
    def print_exiterr(exitcode=None, stderr=None):
        sep = '=' * 87
        s = 'File not formatted due to an error (exitcode=%d)' % exitcode
        log.status(s + '.' if StringHandler.is_empty_or_whitespace(string=stderr) else s + ':\n%s\n%s\n%s' % (sep, stderr, sep))

    @staticmethod
    def print_oserr(cmd=None, error=''):
        log.status('Error while executing the command: %s\nError: %s', cmd, error)


class ViewHandler:
    @staticmethod
    def get_text_from_region(view=None, region=None):
        return view.substr(region)

    @staticmethod
    def is_view_formattable(view=None):
        return not (view.is_read_only() or not view.window() or view.size() == 0)


class OptionHandler:
    # Do NOT use 'get()' for retrieving values from CONFIG; instead, use 'query()'
    @staticmethod
    def query(data_dict, default=None, *keys):
        if PROJECT_CONFIG and any(key in data_dict for key in PROJECT_CONFIG):
            data_dict = PROJECT_CONFIG

        for key in keys:
            if not isinstance(data_dict, (dict, sublime.Settings)):
                return default
            data_dict = data_dict.get(key, default)
        return data_dict


class TempFileHandler:
    @staticmethod
    def create_tmp_file(view=None, uid=None, region=None, auto_format_config=None, suffix=None):
        import tempfile

        if not suffix:
            uid, syntax = SyntaxHandler.get_assigned_syntax(view=view, uid=uid, region=region, auto_format_config=auto_format_config)
            suffix = '.' + syntax if syntax else None

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix, dir=None, encoding='utf-8') as file:
            file.write(ViewHandler.get_text_from_region(view=view, region=region))
            file.close()
            return file.name

        return None

    @staticmethod
    def remove_tmp_file(tmp_file=None):
        if tmp_file and os.path.isfile(tmp_file):
            os.unlink(tmp_file)


class ModeHandler:
    @staticmethod
    def is_generic_mode(uid=None):
        formatter = OptionHandler.query(CONFIG, {}, 'formatters', uid)
        name = formatter.get('name', None)
        typ = formatter.get('type', None)
        return bool(name and typ)


class FolderHandler:
    @staticmethod
    def _get_active_view_parent_folders(view=None, active_file_path=None, max_depth=50):
        if not active_file_path:
            active_file_path = view.file_name()
        parent_folders = []

        if active_file_path:
            d = dirname(active_file_path)

            for _ in range(max_depth):
                if d == dirname(d):
                    break
                parent_folders.append(d)
                d = dirname(d)

        return parent_folders


class ArgumentHandler:
    @staticmethod
    def _extract_generic_local_executables(view=None, uid=None):
        _executables = None
        if ModeHandler.is_generic_mode(uid=uid):
            path = OptionHandler.query(CONFIG, None, 'formatters', uid, 'executable_path')
            if isinstance(path, list):
                _executables = [PathHandler.get_pathinfo(view=view, path=p)['base'] for p in path]
            elif isinstance(path, str):
                _executables = [PathHandler.get_pathinfo(view=view, path=path)['base']]
        return _executables

    @classmethod
    def _get_local_executable(cls, view=None, uid=None, executables=None, runtime_type=None):
        _executables = cls._extract_generic_local_executables(view=view, uid=uid)
        if _executables:
            executables = _executables

        if not runtime_type or not executables:
            return None

        parent_folders = FolderHandler._get_active_view_parent_folders(view=view)
        if parent_folders:
            paths = []
            if runtime_type == 'node':
                for folder in parent_folders:
                    for ex in executables:
                        paths.append(join(folder, 'node_modules', '.bin', ex))
                        paths.append(join(folder, 'node_modules', executables[0], 'bin', ex))
                        paths.append(join(folder, 'node_modules', executables[0], ex))
            if runtime_type == 'python':
                pass
            if runtime_type == 'perl':
                pass
            if runtime_type == 'ruby':
                pass
            for file in paths:
                if FileHandler.is_executable(file=file):
                    log.debug('Local executable: %s', file)
                    return file
        return None

    @classmethod
    def _get_path_for(cls, view=None, uid=None, interpreters=None, executables=None, what=None):
        if what == 'executable':
            fnames_list = executables
        elif what == 'interpreter':
            fnames_list = interpreters
        else:
            return None

        user_files = OptionHandler.query(CONFIG, None, 'formatters', uid, what + '_path')

        if isinstance(user_files, str):
            user_files = [user_files]
        elif not isinstance(user_files, list):
            user_files = []

        for user_file in user_files:
            a = PathHandler.get_pathinfo(view=view, path=user_file)
            if a['path'] == a['base'] and not a['cwd']:
                global_file = EnvironmentHandler.get_environ_path(fnames=[user_file])
                if global_file:
                    log.debug('Global %s: %s', what, global_file)
                    return global_file

            if FileHandler.is_executable(file=user_file):
                log.debug('User %s: %s', what, user_file)
                return user_file

        global_file = EnvironmentHandler.get_environ_path(fnames=fnames_list)
        if global_file:
            log.debug('Global %s: %s', what, global_file)
            return global_file
        else:
            log.error('Files %s do not exist: %s', what, user_files)
            return None

    @classmethod
    def get_executable(cls, view=None, uid=None, executables=None, runtime_type=None):
        local_executable = cls._get_local_executable(view=view, uid=uid, executables=executables, runtime_type=runtime_type)
        if local_executable:
            return local_executable

        user_and_global_executable = cls._get_path_for(view=view, uid=uid, executables=executables, what='executable')
        return user_and_global_executable or None

    @classmethod
    def get_interpreter(cls, view=None, uid=None, interpreters=None):
        user_and_global_interpreter = cls._get_path_for(view=view, uid=uid, interpreters=interpreters, what='interpreter')
        return user_and_global_interpreter or None

    @classmethod
    def get_iprexe_cmd(cls, view=None, uid=None, interpreters=None, executables=None, runtime_type=None):
        user_files = OptionHandler.query(CONFIG, None, 'formatters', uid, 'interpreter_path')
        if user_files:
            cmd = [cls.get_interpreter(view=view, uid=uid, interpreters=interpreters), cls.get_executable(view=view, uid=uid, executables=executables, runtime_type=runtime_type)]
        else:
            cmd = [cls.get_executable(view=view, uid=uid, executables=executables, runtime_type=runtime_type)]
        return cmd if all(cmd) else None

    @classmethod
    def get_combo_cmd(cls, view=None, uid=None, interpreters=None, executables=None, runtime_type=None):
        cmd = cls.get_iprexe_cmd(view=view, uid=uid, interpreters=interpreters, executables=executables, runtime_type=runtime_type)
        if cmd is None:
            return None

        if cmd:
            cmd.extend(cls.get_args())
        return cmd if all(cmd) else None

    @staticmethod
    def get_args(uid=None):
        args = OptionHandler.query(CONFIG, None, 'formatters', uid, 'args')
        return StringHandler.convert_list_items_to_string(lst=args)

    @classmethod
    def get_config_path(cls, view=None, uid=None, region=None, dotfiles=None, auto_format_config=None):
        ignore_config_path = OptionHandler.query(CONFIG, [], 'quick_options', 'ignore_config_path')
        if uid in ignore_config_path:
            return None

        shared_config = OptionHandler.query(CONFIG, None, 'formatters', uid, 'config_path')

        if shared_config and isinstance(shared_config, dict):
            uid, syntax = SyntaxHandler.get_assigned_syntax(view=view, uid=uid, region=region, auto_format_config=auto_format_config)

            for k, v in DotFileHandler.get_cfgignore(view=view).items():
                if (k.strip().lower() == syntax or k == 'default') and uid in v:
                    return None

            for key, path in shared_config.items():
                if key.strip().lower() == syntax and PathHandler.is_valid_path(path=path):
                    log.debug('Config [%s]: %s', syntax, path)
                    return path

            default_path = shared_config.get('default', None)
            if PathHandler.is_valid_path(path=default_path):
                log.debug('Config [default]: %s', default_path)
                return default_path

            log.warning('Could not obtain config file for syntax: %s', syntax)
        else:
            log.info('User specific "config_path" is not set: %s', shared_config)

            dotfile_path = cls._traverse_find_config_dotfile(view=view, dotfiles=dotfiles)
            if dotfile_path:
                return dotfile_path

        log.info('↳Running third-party plugin without specifying any "config_path"')
        return None

    @staticmethod
    def _traverse_find_config_dotfile(view=None, dotfiles=None):
        if not dotfiles:
            return None

        parent_folders = FolderHandler._get_active_view_parent_folders(view=view)
        candidate_paths = []

        def should_stop_search(folder):
            return any(isdir(join(folder, vcs_dir)) for vcs_dir in ['.git', '.hg'])

        if parent_folders:
            for folder in parent_folders:
                candidate_paths.extend(join(folder, dotfile) for dotfile in dotfiles)
                if should_stop_search(folder):
                    break

        xdg_config_home = os.getenv('XDG_CONFIG_HOME')
        if xdg_config_home and not IS_WINDOWS:
            candidate_paths.extend(join(xdg_config_home, dotfile) for dotfile in dotfiles)
            for child in os.listdir(xdg_config_home):
                candidate_paths.extend(join(xdg_config_home, child, dotfile) for dotfile in dotfiles)
                break  # only look in the first child folder
        else:
            appdata = os.getenv('APPDATA')
            if appdata:
                candidate_paths.extend(join(appdata, dotfile) for dotfile in dotfiles)
                for child in os.listdir(appdata):
                    candidate_paths.extend(join(appdata, child, dotfile) for dotfile in dotfiles)
                    break

        for path in candidate_paths:
            if FileHandler.is_readable(file=path):
                log.debug('Auto-set "config_path" to the detected dot file: %s', path)
                return path

        return None

    @staticmethod
    def is_valid_cmd(cmd=None):  # @deprecated
        return all(isinstance(x, str) for x in cmd) if cmd and isinstance(cmd, list) else False


class SyntaxHandler:
    @classmethod
    def get_assigned_syntax(cls, view=None, uid=None, region=None, auto_format_config=None):  # return tuple
        if auto_format_config:
            for syntax, v in auto_format_config.items():
                if syntax == 'config':
                    continue
                v_is_dict = isinstance(v, dict)
                uid = v.get('uid', None) if v_is_dict else v
                kwargs = {
                    'is_auto_format': True,
                    'syntaxes': [syntax],
                    'exclude_syntaxes': v.get('exclude_syntaxes', {}) if v_is_dict else None
                }
                syntax = cls._detect_assigned_syntax(view=view, uid=uid, region=region, **kwargs)
                if syntax:
                    action = OptionHandler.query(auto_format_config, None, 'config', AUTO_FORMAT_ACTION_KEY)
                    if syntax in OptionHandler.query(auto_format_config, [], 'config', action, 'exclude_syntaxes'):
                        return '@@noop@@', None
                    else:
                        return uid, syntax
            return '@@noop@@', None
        else:
            syntax = cls._detect_assigned_syntax(view=view, uid=uid, region=region)
            return uid, syntax

    @staticmethod
    def _detect_assigned_syntax(view=None, uid=None, region=None, **kwargs):
        if kwargs.get('is_auto_format', False):
            syntaxes = kwargs.get('syntaxes')
            exclude_syntaxes = kwargs.get('exclude_syntaxes')
        else:
            syntaxes = OptionHandler.query(CONFIG, None, 'formatters', uid, 'syntaxes')
            exclude_syntaxes = OptionHandler.query(CONFIG, None, 'formatters', uid, 'exclude_syntaxes')

        def should_exclude(syntax, scope):
            return (
                exclude_syntaxes
                and isinstance(exclude_syntaxes, dict)  # noqa: W503
                and any(  # noqa: W503
                    (key.strip().lower() in ['all', syntax])
                    and (isinstance(value, list) and any(x in scope for x in value))  # noqa: W503
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


class StringHandler:
    @classmethod
    def update_json_recursive(cls, json_data=None, update_data=None):
        for key, value in update_data.items():
            if key in json_data and isinstance(value, dict) and isinstance(json_data[key], dict):
                cls.update_json_recursive(json_data=json_data[key], update_data=value)
            else:
                json_data[key] = value

    @staticmethod
    def convert_list_items_to_string(lst=None):
        return list(map(str, lst)) if lst and isinstance(lst, list) else []

    @staticmethod
    def is_empty_or_whitespace(string=None):
        return string is not None and not string.strip()


class DotFileHandler:
    @staticmethod
    def _read_config_file(paths, filenames):
        config = {}
        for path in reversed(paths):
            for filename in filenames:
                p = join(path, filename)
                if isfile(p):
                    try:
                        with open(p, 'r', encoding='utf-8') as f:
                            StringHandler.update_json_recursive(json_data=config, update_data=sublime.decode_value(f.read()))
                    except Exception as e:
                        log.error('Error reading %s at %s: %s', filename, p, e)
                    return config
        return config

    @classmethod
    def get_cfgignore(cls, view=None, active_file_path=None):
        paths = FolderHandler._get_active_view_parent_folders(view=view, active_file_path=active_file_path)
        return cls._read_config_file(paths, ['.sublimeformatter.cfgignore.json', '.sublimeformatter.cfgignore']) or {}

    @classmethod
    def get_auto_format_config(cls, view=None, active_file_path=None):
        paths = FolderHandler._get_active_view_parent_folders(view=view, active_file_path=active_file_path)
        return cls._read_config_file(paths, ['.sublimeformatter.json', '.sublimeformatter']) or {}

    @classmethod
    def get_auto_format_user_config(cls, view=None, active_file_path=None):
        paths = FolderHandler._get_active_view_parent_folders(view=view, active_file_path=active_file_path)
        return cls._read_config_file(paths, ['.sublimeformatter.user.json', '.sublimeformatter-user']) or {}

    @classmethod
    def _auto_format_config_merge(cls, view=None, active_file_path=None):
        config = cls.get_auto_format_config(view=view, active_file_path=active_file_path)
        user_config = cls.get_auto_format_user_config(view=view, active_file_path=active_file_path)
        if user_config:
            config['config'] = user_config
        return config

    @classmethod
    def get_auto_format_args(cls, view=None, active_file_path=None):
        auto_format = OptionHandler.query(CONFIG, {}, 'auto_format').copy()
        auto_format.update(cls._auto_format_config_merge(view=view, active_file_path=active_file_path))
        return {'auto_format_config': auto_format}


class GraphicHandler:
    @staticmethod
    def is_render_extended(uid=None):
        if OptionHandler.query(CONFIG, {}, 'quick_options'):
            render_extended = uid in OptionHandler.query(CONFIG, [], 'quick_options', 'render_extended')
        else:
            render_extended = OptionHandler.query(CONFIG, False, 'formatters', uid, 'render_extended')

        return isinstance(render_extended, bool) and render_extended

    @classmethod
    def get_args_extended(cls, uid=None):
        if cls.is_render_extended(uid=uid):
            args_extended = OptionHandler.query(CONFIG, {}, 'formatters', uid, 'args_extended')
            valid = {}
            for k, v in args_extended.items():
                valid[k.strip().lower()] = StringHandler.convert_list_items_to_string(lst=v)
            return valid
        else:
            return {}

    @staticmethod
    def ext_png_to_svg_cmd(cmd=None):
        return [x.replace(GFX_OUT_NAME + '.png', GFX_OUT_NAME + '.svg') for x in cmd]

    @staticmethod
    def all_png_to_svg_cmd(cmd=None):
        return [x.replace('png', 'svg') for x in cmd]

    @staticmethod
    def get_output_image(temp_dir=None, type=None):
        if temp_dir and type == 'graphic':
            temp_dir = join(temp_dir, GFX_OUT_NAME + '.png')
            return temp_dir
        else:
            log.error('Wrong args param: method get_output_image() is only applicable to type: graphic')
            return '!wrong_param!'


class InterfaceHandler:
    @staticmethod
    def popup_message(text, title=None, dialog=False):
        template = u'%s' + (u' (%s)' if title else '') + u':\n\n%s'
        message = template % ('🧜‍♀️ ' + PACKAGE_NAME, title, text) if title else template % ('🧜‍♀️ ' + PACKAGE_NAME, text)

        if dialog:
            sublime.message_dialog(message)
        else:
            sublime.error_message(message)


#####################################################
# === Extended Class and Its Supporting Classes === #
#####################################################

class _Extended(Module):  # @unused
    '''
    Extended API for universal use, inheriting all methods from the Module class.
    This subclass is never used and is included here for overview only.
    '''

    def __init__(self, view=None, uid=None, region=None, interpreters=None, executables=None, dotfiles=None, temp_dir=None, type=None, auto_format_config=None, **kwargs):
        super().__init__(view=view, uid=uid, region=region, interpreters=interpreters, executables=executables, dotfiles=dotfiles, temp_dir=temp_dir, type=type, auto_format_config=auto_format_config, **kwargs)

    def remove_junk(self):
        raise NotImplementedError('CleanupHandler')

    def clear_console(self):
        raise NotImplementedError('CleanupHandler')

    def setup_config(self):
        raise NotImplementedError('ConfigHandler')

    def load_sublime_preferences(self):
        raise NotImplementedError('ConfigHandler')

    def setup_shared_config_files(self):
        raise NotImplementedError('ConfigHandler')

    def is_quick_options_mode(self):
        raise NotImplementedError('ConfigHandler')

    def get_mode_description(self, short=False):
        raise NotImplementedError('ConfigHandler')

    def set_debug_mode(self):
        raise NotImplementedError('ConfigHandler')

    def is_generic_method(self, uid):
        raise NotImplementedError('ConfigHandler')

    def recursive_map(self, func, data):
        raise NotImplementedError('TransformHandler')

    def expand_path(self, path):
        raise NotImplementedError('TransformHandler')

    def get_recursive_filelist(self, dir, exclude_dirs_regex, exclude_files_regex, exclude_extensions_regex):
        raise NotImplementedError('TransformHandler')

    def md5f(self, file_path):
        raise NotImplementedError('HashHandler')

    def md5d(self, dir_path):
        raise NotImplementedError('HashHandler')

    def markdown_to_html(self, markdown):
        raise NotImplementedError('MarkdownHandler')

    def style_view(self, dst_view):
        raise NotImplementedError('PhantomHandler')

    def set_html_phantom(self, dst_view, image_data, image_width, image_height, fit_image_width, fit_image_height, extended_data):
        raise NotImplementedError('PhantomHandler')

    def get_image_size(self, data):
        raise NotImplementedError('PhantomHandler')

    def image_scale_fit(self, view, image_width, image_height):
        raise NotImplementedError('PhantomHandler')

    def get_downloads_folder(self):
        raise NotImplementedError('PhantomHandler')

    def assign_layout(self, layout):
        raise NotImplementedError('LayoutHandler')

    def want_layout(self):
        raise NotImplementedError('LayoutHandler')

    def setup_layout(self, view):
        raise NotImplementedError('LayoutHandler')

    def is_text_data(self, data):
        raise NotImplementedError('TextHandler')

    def is_text_file(self, file_path):
        raise NotImplementedError('TextHandler')

    def print_sysinfo(self, pretty=False):
        raise NotImplementedError('PrintHandler')

    def is_view(self, file_or_view):
        raise NotImplementedError('MiscHandler')

    def get_unique(self, data):
        raise NotImplementedError('MiscHandler')


# === Extended Supporting Classes === #

class CleanupHandler:
    @staticmethod
    def remove_junk():
        try:
            parent_dir = dirname(dirname(__file__))
            items = [join(parent_dir, item) for item in ['.DS_Store', '.gitattributes', '.gitignore', '.git']]

            for item in items:
                if isfile(item):
                    os.remove(item)
                elif isdir(item):
                    shutil.rmtree(item)
        except Exception:
            pass

    @staticmethod
    def clear_console():
        if OptionHandler.query(CONFIG, True, 'clear_console'):
            if SUBLIME_PREFERENCES:
                orig = SUBLIME_PREFERENCES.get('console_max_history_lines', None)
                if orig is None:
                    return  # not implemented in <ST4088

                SUBLIME_PREFERENCES.set('console_max_history_lines', 1)
                print('')
                SUBLIME_PREFERENCES.set('console_max_history_lines', orig)


class ConfigHandler:
    @staticmethod
    def config_file():
        return PACKAGE_NAME + '.sublime-settings'

    @staticmethod
    def quick_options_config_file():
        return join(sublime.packages_path(), 'User', QUICK_OPTIONS_SETTING_FILE)

    @staticmethod
    def load_settings(file):
        return sublime.load_settings(file)

    @classmethod
    def setup_config(cls):
        settings = cls.load_settings(cls.config_file())
        settings.add_on_change('290c6488-3973-493b-9151-137042f0fa36', cls.load_config)
        cls.build_config(settings)

    @classmethod
    def load_config(cls):
        settings = cls.load_settings(cls.config_file())
        cls.build_config_with_retry(settings)

    @classmethod
    def load_quick_options(cls):
        qo_file = cls.quick_options_config_file()

        try:
            if isfile(qo_file):
                with open(qo_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                quick_options = data
            else:
                quick_options = OptionHandler.query(CONFIG, {}, 'quick_options')
        except Exception:
            quick_options = {}

        return quick_options

    @staticmethod
    def project_config_overwrites_config():
        global PROJECT_CONFIG

        project_data = sublime.active_window().project_data()
        if project_data and isinstance(project_data, dict):
            project_settings = project_data.get('settings', {}).get(PACKAGE_NAME, None)
            if project_settings:
                PROJECT_CONFIG = deepcopy(CONFIG)
                project_settings = TransformHandler.recursive_map(TransformHandler.expand_path, project_settings)
                StringHandler.update_json_recursive(json_data=PROJECT_CONFIG, update_data=project_settings)
            else:
                PROJECT_CONFIG = {}
        else:
            PROJECT_CONFIG = {}

        ConfigHandler.set_debug_mode()  # update

    @classmethod
    def load_sublime_preferences(cls):
        global SUBLIME_PREFERENCES

        try:
            SUBLIME_PREFERENCES = cls.load_settings('Preferences.sublime-settings')
        except Exception:
            SUBLIME_PREFERENCES = {}

    @classmethod
    @check_deprecated_options
    @retry_on_exception(retries=5, delay=500)  # 2s
    def build_config(cls, settings):
        global CONFIG

        # Sublime settings dict is immutable and unordered
        c = {
            'quick_options': cls.load_quick_options(),
            'debug': settings.get('debug', False),
            'dev': settings.get('dev', False),
            'clear_console': settings.get('clear_console', True),
            'open_console_on_failure': settings.get('open_console_on_failure', False),
            'close_console_on_success': settings.get('close_console_on_success', False),
            'timeout': settings.get('timeout', 10),
            'file_chars_limit': settings.get('file_chars_limit', False),
            'custom_modules': settings.get('custom_modules', {}),  # @deprecated
            'custom_modules_manifest': settings.get('custom_modules_manifest', ''),
            'show_statusbar': settings.get('show_statusbar', True),
            'show_words_count': {
                'enable': OptionHandler.query(settings, True, 'show_words_count', 'enable'),
                'ignore_whitespace_char': OptionHandler.query(settings, True, 'show_words_count', 'ignore_whitespace_char'),
                'use_short_label': OptionHandler.query(settings, False, 'show_words_count', 'use_short_label')
            },
            'remember_session': settings.get('remember_session', True),
            'layout': {
                'enable': OptionHandler.query(settings, '2cols', 'layout', 'enable'),
                'sync_scroll': OptionHandler.query(settings, True, 'layout', 'sync_scroll')
            },
            'environ': settings.get('environ', {}),
            'format_on_priority': settings.get('format_on_priority', {}),
            'format_on_unique': settings.get('format_on_unique', {}),  # @deprecated
            'auto_format': settings.get('auto_format', {}),
            'formatters': settings.get('formatters', {})
        }
        c['formatters'].pop('examplegeneric', None)
        c['formatters'].pop('examplemodule', None)
        c = TransformHandler.recursive_map(TransformHandler.expand_path, c)
        c['custom_modules_manifest'] = re.sub(r'(\bhttps?|ftp):/(?=[^/])', r'\1://', c['custom_modules_manifest'])
        CONFIG.update(c)

        if not CONFIG:
            raise  # invoke @retry_on_exception
        return c

    @classmethod
    def build_config_with_retry(cls, settings):
        # Directly retry the build_config method without invoking retry_on_exception again
        retry_on_exception(retries=5, delay=500)(cls.build_config)(settings)

    @staticmethod
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
                        hash_dst = HashHandler.md5f(path)
                        master_path = '{0}.{2}{1}'.format(*splitext(path) + ('master',))
                        hash_dst_master = HashHandler.md5f(master_path) if isfile(master_path) else None

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

    @staticmethod
    def is_quick_options_mode():
        return OptionHandler.query(CONFIG, {}, 'quick_options')

    @classmethod
    def get_mode_description(cls, short=False):
        qo_memory = cls.sort_dict(cls.is_quick_options_mode())

        try:
            file = cls.quick_options_config_file()
            with open(file, 'r', encoding='utf-8') as f:
                qo_file = cls.sort_dict(json.load(f))
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

    @classmethod
    def sort_dict(cls, dictionary):
        sorted_dict = {}
        for key, value in sorted(dictionary.items()):
            if isinstance(value, dict):
                sorted_dict[key] = cls.sort_dict(value)
            elif isinstance(value, list):
                sorted_dict[key] = sorted(value)
            else:
                sorted_dict[key] = value
        return sorted_dict

    @classmethod
    def set_debug_mode(cls):
        if cls.is_quick_options_mode():
            debug = OptionHandler.query(CONFIG, False, 'quick_options', 'debug')
        else:
            debug = OptionHandler.query(CONFIG, False, 'debug')

        if debug == 'status':
            enable_status()
        elif (isinstance(debug, str) and debug.strip().lower() == 'true') or debug is True:
            enable_logging()
        else:
            disable_logging()

    @staticmethod
    def is_generic_method(uid):
        name = OptionHandler.query(CONFIG, None, 'formatters', uid, 'name')
        return name is not None


class TransformHandler:
    @classmethod
    def recursive_map(cls, func, data):
        if isinstance(data, dict):
            return dict(map(lambda item: (item[0], cls.recursive_map(func, item[1])), data.items()))
        elif isinstance(data, list):
            return list(map(lambda x: cls.recursive_map(func, x), data))
        else:
            return func(data)

    @staticmethod
    def expand_path(path):
        if path and isinstance(path, str):
            path = normpath(expanduser(expandvars(path)))
            path = sublime.expand_variables(path, sublime.active_window().extract_variables())
        return path

    @staticmethod
    def compile_regex_patterns(patterns_lst):
        compiled_patterns = []
        for pattern in patterns_lst:
            try:
                compiled_patterns.append(re.compile(pattern))
            except re.error as e:
                log.error('Invalid regex pattern: %s. Error: %s', pattern, e)
                raise
        return compiled_patterns

    @staticmethod
    def get_recursive_filelist(dir, exclude_dirs_regex, exclude_files_regex, exclude_extensions_regex):
        text_files = []
        exclude_dirs_regex_compiled = TransformHandler.compile_regex_patterns(exclude_dirs_regex)
        exclude_files_regex_compiled = TransformHandler.compile_regex_patterns(exclude_files_regex)
        exclude_extensions_regex_compiled = TransformHandler.compile_regex_patterns(exclude_extensions_regex)

        for root, dirs, files in os.walk(dir):
            dirs[:] = [d for d in dirs if not any(pattern.match(join(root, d)) for pattern in exclude_dirs_regex_compiled) and d not in [RECURSIVE_SUCCESS_DIRECTORY, RECURSIVE_FAILURE_DIRECTORY]]

            for file in files:
                file_path = join(root, file)

                if any(pattern.match(file_path) for pattern in exclude_files_regex_compiled):
                    continue

                extension = splitext(basename(file_path))[1].lstrip('.').lower()
                if any(pattern.match(extension) for pattern in exclude_extensions_regex_compiled):
                    continue

                if TextHandler.is_text_file(file_path):
                    text_files.append(file_path)

        return text_files


class HashHandler:
    @staticmethod
    def md5f(file_path):
        hash_md5 = hashlib.md5()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_md5.update(chunk)

        return hash_md5.hexdigest()

    @classmethod
    def md5d(cls, dir_path):
        hash_md5 = hashlib.md5()

        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = join(root, file)
                hash_md5.update(cls.md5f(file_path).encode('utf-8'))

        return hash_md5.hexdigest()


class MarkdownHandler:
    @staticmethod
    def markdown_to_html(markdown):
        # Preprocess the markdown to handle special cases
        markdown = re.sub(r'\[@see\]\([^\)]+\)', '__SEE_PLACEHOLDER__', markdown)
        markdown = re.sub(r'\[@noop\]\([^\)]+\)', '@noop', markdown)

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

            # Escape HTML characters to prevent mistakenly interpreted as an HTML tag
            line = (
                line
                .replace('&', '&amp;')   # Escape &
                .replace('<', '&lt;')    # Escape <
                .replace('>', '&gt;')    # Escape >
                .replace('"', '&quot;')  # Escape "
                .replace("'", '&#39;')   # Escape '
            )

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

        # Replace the custom placeholder with the actual <em> tag for @see
        html_output = '\n'.join(html).replace('__SEE_PLACEHOLDER__', '<em>@see</em>')

        return '''
        <body id="phantom-body">
            <style>
                a {text-decoration:none}
                code {font-family:ui-monospace,SFMono-Regular,SF Mono,Menlo,Consolas,Liberation Mono,monospace;background-color:#afb8c133;padding:.1em .2em;border-radius:4px;}
            </style>
            <div class="container">
                ''' + html_output + '''
            </div>
        </body>
        '''


class PhantomHandler:
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

    @classmethod
    def set_html_phantom(cls, dst_view, image_data, image_width, image_height, fit_image_width, fit_image_height, extended_data):
        cls.style_view(dst_view)

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

    @staticmethod
    def get_downloads_folder():
        if IS_WINDOWS:
            downloads_folder = join(os.getenv('USERPROFILE', ''), 'Downloads')
        else:
            downloads_folder = join(os.getenv('HOME', ''), 'Downloads')

        if not isdir(downloads_folder):
            try:
                os.makedirs(downloads_folder, exist_ok=True)
            except Exception:
                return tempfile.mkdtemp()

        return downloads_folder


class LayoutHandler:
    @staticmethod
    def assign_layout(layout):
        return LAYOUTS.get(layout, None)

    @staticmethod
    def want_layout():
        return OptionHandler.query(CONFIG, False, 'layout', 'enable') in LAYOUTS

    @classmethod
    def setup_layout(cls, view):
        layout = OptionHandler.query(CONFIG, False, 'layout', 'enable')

        if layout in LAYOUTS:
            view.window().set_layout(cls.assign_layout(layout))
            return True

        return False


class TextHandler:
    @staticmethod
    def is_text_data(data):
        try:
            data = data.decode('utf-8')
            return data
        except (UnicodeDecodeError, AttributeError):
            return False

    @staticmethod
    def is_text_file(file_path, block_size=1024):
        try:
            with open(file_path, 'rb') as file:
                chunk = file.read(block_size)
                if not chunk:
                    return False  # empty file
                try:
                    chunk.decode('utf-8')
                except UnicodeDecodeError:
                    return False
                return True
        except Exception:
            return False

    @staticmethod
    def is_chars_limit_exceeded(view):
        file_chars_limit = OptionHandler.query(CONFIG, False, 'file_chars_limit')
        if isinstance(file_chars_limit, int) and file_chars_limit > 0:
            current_size = view.size()
            if file_chars_limit < current_size:
                log.info('File chars limit exceeded: Limit = %s, Current = %s', file_chars_limit, current_size)
                return True
        return False


class PrintHandler:
    @staticmethod
    def print_sysinfo(pretty=False):
        if OptionHandler.query(CONFIG, False, 'environ', 'print_on_console'):
            log.info('Environments:\n%s', json.dumps(EnvironmentHandler.update_environ(), ensure_ascii=False, indent=4 if pretty else None))

            if ConfigHandler.is_quick_options_mode():
                log.info('Mode: Quick Options: \n%s', json.dumps(OptionHandler.query(CONFIG, {}, 'quick_options'), ensure_ascii=False, indent=4 if pretty else None))
            else:
                log.info('Mode: User Settings')


class MiscHandler:  # @unused
    @staticmethod
    def is_view(file_or_view):
        return (type(file_or_view) is sublime.View)

    @staticmethod
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
