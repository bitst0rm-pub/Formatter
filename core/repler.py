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

import os
import re
import io
import sys
import json
import logging
import threading
import subprocess
import sublime
import sublime_plugin
from . import common
from ..libs.killableprocess import Popen

log = logging.getLogger(__name__)

HISTORY_FILE = common.join(sublime.packages_path(), '..', 'Local', 'History.formatter_repl')
MAX_HISTORY_RECORDS = 100


class Repl:
    PROMPT = b'>>> '
    rinstances = {}
    rhistory = {}

    def __init__(self, view, **kwargs):
        self.view = view
        self.kwargs = kwargs
        self.rview = self.view
        self.rprocess = None
        self.rthread = None
        self.rencoding = None
        self.should_filter_color = False
        self.should_filter_echo = False
        self.should_remove_prompt = False
        self.script_path = None

    def run(self):
        self.script_path = self.view.file_name()
        if not self.script_path:
            common.prompt_error('Please save the file first.')
            return

        interpreter = self.get_interpreter()
        if not interpreter:
            common.prompt_error('No interpreter found.')
            return

        self.init_history()
        self.set_env()
        self.get_encoding_setting()
        self.get_color_filter_setting()
        self.get_echo_filter_setting()
        self.get_remove_prompt_setting()
        self.create_repl_view()
        self.set_repl_view_settings()
        self.set_repl_view_attributes()
        cmd, cwd = self.set_command(interpreter, self.get_command_args())
        self.set_search_path(cwd)
        self.popen(cmd, cwd)
        self.start_repl_thread()
        self.store_repl_instance()

    def init_history(self):
        if common.query(common.config, True, 'interactive_repl', 'enable_persistent_history'):
            self.rhistory.update(self.read_history_file())

    def read_history_file(self):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def set_env(self):
        env = self.kwargs.get('env', None)
        if env and isinstance(env, dict):
            for key, value in env.items():
                os.environ[key] = value

    def get_encoding_setting(self):
        encoding = self.kwargs.get('encoding', None)
        if encoding:
            if isinstance(encoding, str):
                self.rencoding = encoding
            elif isinstance(encoding, dict):
                self.rencoding = encoding.get(sublime.platform(), 'utf-8')
                if self.rencoding == '${{locale_encoding}}':
                    self.rencoding = self.get_default_locale_encoding()
        else:
            self.rencoding = self.get_default_locale_encoding()

    def get_default_locale_encoding(self):
        import locale
        # Equivalent to Popen() universal_newlines=True
        return locale.getdefaultlocale()[1]

    def get_color_filter_setting(self):
        self.should_filter_color = self.get_filter_setting(filter_type='filter_color')

    def get_echo_filter_setting(self):
        self.should_filter_echo = self.get_filter_setting(filter_type='filter_echo')

    def get_remove_prompt_setting(self):
        self.should_remove_prompt = self.get_filter_setting(filter_type='remove_prompt')

    def get_filter_setting(self, filter_type=None):
        item = self.kwargs.get(filter_type, False)
        if item:
            if isinstance(item, bool):
                return item
            elif isinstance(item, dict):
                return item.get(sublime.platform(), False)
        else:
            return False

    def create_repl_view(self):
        syntax = common.query(common.config, None, 'interactive_repl', 'syntax', self.kwargs.get('uid', None))
        if not syntax:
            syntax = self.kwargs.get('syntax', '')
        self.rview = self.view.window().new_file(syntax=syntax)

    def set_repl_view_settings(self):
        settings = self.rview.settings()
        settings.set('spell_check', False)
        settings.set('detect_indentation', False)
        settings.set('auto_indent', False)
        settings.set('smart_indent', False)
        settings.set('indent_subsequent_lines', False)

        view_settings = common.query(common.config, {}, 'interactive_repl', 'view_settings')
        for k, v in view_settings.items():
            settings.set(k, v)

    def set_repl_view_attributes(self):
        self.rview.set_name(self.kwargs.get('uid', 'untitled').capitalize() + ' REPL')
        self.rview.set_scratch(True)

    def get_interpreter(self):
        interpreter_list = common.query(common.config, None, 'interactive_repl', 'interpreter_path', self.kwargs.get('uid', None))
        if interpreter_list and isinstance(interpreter_list, list):
            for local_interpreter in interpreter_list:
                if common.is_executeable(local_interpreter):
                    return local_interpreter

        cmd_list = self.get_command_list()
        if cmd_list:
            interpreter_list = cmd_list[0]
            global_interpreter = common.get_environ_path(interpreter_list)
            if global_interpreter:
                return global_interpreter

        log.error('Could not find REPL interpreter: %s %s', interpreter_list, global_interpreter)
        return None

    def get_command_list(self):
        cmd = self.kwargs.get('cmd', None)
        if isinstance(cmd, list):
            cmd_list = cmd
        elif isinstance(cmd, dict):
            cmd_list = cmd[sublime.platform()]
        else:
            log.error('Missing or wrong input cmd type: %s', cmd)
            cmd_list = None
        return cmd_list

    def get_command_args(self):
        args = self.get_command_list()[1:]
        for i in range(len(args)):
            args[i] = common.expand_path(args[i].replace('${{file}}', self.script_path))
        return args

    def set_command(self, interpreter, command):
        command.insert(0, interpreter)
        return command, common.dirname(self.script_path)

    def set_search_path(self, cwd):
        if cwd not in sys.path:
            sys.path.append(cwd)

    def popen(self, cmd, cwd):
        self.rprocess = Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=common.update_environ(),
            shell=common.IS_WINDOWS,
            startupinfo=self.get_startupinfo(),
            creationflags=self.creationflags()
        )

    def creationflags(self):
        creationflags = 0
        if common.IS_WINDOWS and sys.version_info >= (3, 7):
            creationflags = 0x8000000  # CREATE_NO_WINDOW
        return creationflags

    def get_startupinfo(self):
        info = None
        if common.IS_WINDOWS:
            from ..libs.killableprocess import STARTUPINFO, STARTF_USESHOWWINDOW
            info = STARTUPINFO()
            info.dwFlags |= STARTF_USESHOWWINDOW
            info.wShowWindow |= 1
        return info

    def start_repl_thread(self):
        with threading.Lock():
            self.rthread = threading.Thread(target=self.capture_output)
            self.rthread.start()

    def capture_output(self):
        def append_output(output_bytes):
            self.rview.run_command('append', {'characters': output_bytes.decode(self.rencoding)})

        stdout_buffer = io.BytesIO()
        flush_timer = None
        flush_timer_lock = threading.Lock()

        def flush_buffer():
            nonlocal flush_timer
            with flush_timer_lock:
                if stdout_buffer.tell() > 0:
                    append_output(stdout_buffer.getvalue())
                    stdout_buffer.seek(0)
                    stdout_buffer.truncate()
                if flush_timer:
                    flush_timer.cancel()
                flush_timer = None

                # Output end here. Begin post fixes
                self.do_filter_ansi_escape_color()
                self.do_filter_echo()

                # Magic to calculate room between output_end and eof
                self.set_cursor_to_eof()
                self.store_repl_output_end()
                self.store_repl_prompt()  # not in use, save for future

                # Automatically insert a custom prompt if it is missing
                if not self.has_repl_prompt() and not self.should_remove_prompt:
                    append_output(self.PROMPT)
                    self.set_cursor_to_eof()
                    self.store_repl_output_end()

        def clear_buffer_and_cancel_timer():
            nonlocal flush_timer
            with flush_timer_lock:
                if stdout_buffer.tell() > 0:
                    stdout_buffer.seek(0)
                    stdout_buffer.truncate()
                if flush_timer:
                    flush_timer.cancel()
                flush_timer = None

        clear_buffer_and_cancel_timer()

        while True:
            output_byte = self.rprocess.stdout.readline(1)

            if common.IS_WINDOWS and output_byte == b'\r':
                continue  # fix \r\n in Windows

            if self.rprocess.poll() is not None and not output_byte:
                log.info('Subprocess successfully killed.')
                break

            stdout_buffer.write(output_byte)

            with flush_timer_lock:
                if flush_timer is None:
                    flush_timer = threading.Timer(0.1, flush_buffer)  # 100 milliseconds
                    flush_timer.start()

        sublime.set_timeout(lambda: append_output(b'\n*** Non-interactive REPL closed ***'), 100)

    def do_filter_ansi_escape_color(self):
        if self.should_filter_color:
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            start = self.get_repl_output_end()
            end = self.eof()
            selected_text = self.rview.substr(sublime.Region(start, end))
            cleaned_text = ansi_escape.sub('', selected_text)
            self.rview.run_command('replace_region_text', {'start_pos': start, 'end_pos': end, 'replacement_text': cleaned_text})

    def do_filter_echo(self):
        if self.should_filter_echo:
            command_len = self.rinstances[self.rview.id()]['command_len']
            if command_len:
                start = self.get_repl_output_end()
                self.delete_text_between_positions(start, start + command_len + 1)

    def store_repl_instance(self):
        self.rinstances.setdefault(self.rview.id(), {
            'kwargs': self.kwargs,
            'view': self.rview,
            'process': self.rprocess,
            'thread': self.rthread,
            'encoding': self.rencoding,
            'ready': False,
            'output_end': -1,
            'command_len': -1,
            'prompt': None
        })

    def eof(self):
        return self.rview.size()

    def cursor(self):
        return self.rview.sel()[0].begin()

    def set_cursor_to_eof(self):
        eof = self.eof()
        self.rview.sel().clear()
        self.rview.sel().add(sublime.Region(eof, eof))
        self.rview.show(eof, animate=False)

    def store_repl_output_end(self):
        self.rinstances[self.rview.id()].update(output_end=self.rview.size())

    def get_repl_output_end(self):
        return self.rinstances[self.rview.id()]['output_end']

    def has_repl_prompt(self):
        line_region = self.rview.line(self.rview.sel()[0])
        prompt = self.rview.substr(line_region)
        return prompt

    def store_repl_prompt(self):
        prompt = self.has_repl_prompt()
        self.rinstances[self.rview.id()].update(prompt=(prompt if prompt else self.PROMPT))

    def on_pre_close_terminate(self):
        if self.is_repl_instance():
            rinstance = self.rinstances[self.rview.id()]
            self.terminate_repl(rinstance['process'], rinstance['thread'])
            del self.rinstances[self.rview.id()]

    def terminate_repl(self, rprocess, rthread):
        if rprocess:
            rprocess.kill()
            rprocess = None

        if rthread and rthread.is_alive():
            rthread.join()
            rthread = None

    def on_text_command_user_input(self):
        rinstance = self.rinstances[self.rview.id()]
        rprocess = rinstance['process']
        if rprocess and rprocess.poll() is None:
            # Prevent breaking up user_input into new lines when pressing the Enter key
            self.set_cursor_to_eof()

            user_input = self.rview.substr(sublime.Region(self.get_repl_output_end(), self.eof()))
            self.add_command_to_history(user_input)

            # For filtering command echo
            rinstance['command_len'] = len(user_input)

            rprocess.stdin.write((user_input + '\n').encode(rinstance['encoding']))
            rprocess.stdin.flush()

    def is_cursor_between_output_end_and_eof(self):
        return self.get_repl_output_end() < self.cursor() <= self.eof()

    def is_cursor_in_output_end_region(self):
        return self.get_repl_output_end() - 1 >= self.cursor()

    def store_repl_ready(self, is_ready=False):
        if self.is_repl_instance():
            self.rinstances[self.rview.id()].update(ready=is_ready)

    def is_repl_ready(self):
        if self.is_repl_instance():
            return self.rinstances[self.rview.id()].get('ready', False)

    def is_repl_instance(self):
        return self.rview.id() in self.rinstances

    def add_command_to_history(self, command):
        uid = common.query(self.rinstances, None, self.rview.id(), 'kwargs', 'uid')
        if command and uid:
            if uid in self.rhistory:
                self.rhistory[uid]['command_history'].append(command)
                self.rhistory[uid]['history_index'] = len(self.rhistory[uid]['command_history'])
            else:
                self.rhistory.setdefault(uid, {
                    'command_history': [command],
                    'history_index': 1
                })

            self.trim_database(uid, self.rhistory[uid]['command_history'])

    def trim_database(self, uid, data):
        if len(data) > MAX_HISTORY_RECORDS:
            num_records_to_remove = len(data) - MAX_HISTORY_RECORDS
            data[:num_records_to_remove] = []
            self.rhistory[uid]['history_index'] = len(data)

    def get_previous_command_history(self):
        uid = common.query(self.rinstances, None, self.rview.id(), 'kwargs', 'uid')
        if self.rhistory[uid]['history_index'] > 0:
            self.rhistory[uid]['history_index'] -= 1
            return self.rhistory[uid]['command_history'][self.rhistory[uid]['history_index']]
        else:
            return ''

    def get_next_command_history(self):
        uid = common.query(self.rinstances, None, self.rview.id(), 'kwargs', 'uid')
        if self.rhistory[uid]['history_index'] < len(self.rhistory[uid]['command_history']) - 1:
            self.rhistory[uid]['history_index'] += 1
            return self.rhistory[uid]['command_history'][self.rhistory[uid]['history_index']]
        else:
            self.rhistory[uid]['history_index'] = len(self.rhistory[uid]['command_history'])
            return ''

    def delete_all_between_output_end_and_eof(self):
        self.delete_text_between_positions(self.get_repl_output_end(), self.eof())

    def delete_text_between_positions(self, start, end):
        if start < end:
            self.rview.sel().clear()
            self.rview.sel().add(sublime.Region(start, end))
            self.rview.run_command('right_delete')
            self.set_cursor_to_eof()

    def write_history_file(self):
        if self.is_repl_instance():
            common.os.makedirs(common.dirname(HISTORY_FILE), exist_ok=True)
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.rhistory, f, ensure_ascii=False, indent=4, sort_keys=True)


class RunReplCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        Repl(self.view, **kwargs).run()

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))


class ReplaceRegionTextCommand(sublime_plugin.TextCommand):
    def run(self, edit, start_pos, end_pos, replacement_text):
        # Ensure start_pos and end_pos are within the valid range
        start_pos = max(0, min(start_pos, self.view.size()))
        end_pos = max(0, min(end_pos, self.view.size()))

        # Replace the text in the specified range
        region = sublime.Region(start_pos, end_pos)
        self.view.replace(edit, region, replacement_text)


class ReplListener(sublime_plugin.EventListener):
    def on_selection_modified(self, view):
        if Repl(view).is_repl_ready():
            view.set_read_only(Repl(view).is_cursor_in_output_end_region())

    def on_text_command(self, view, command_name, args):
        rv = Repl(view)
        if not rv.is_repl_instance():
            return None

        if command_name not in ['append', 'run_repl']:
            rv.store_repl_ready(is_ready=True)

        if command_name == 'insert' and args.get('characters') == '\n':
            rv.on_text_command_user_input()  # handle the enter key

        if command_name == 'left_delete' or (command_name == 'delete_word' and not args.get('forward')):
            if rv.is_cursor_between_output_end_and_eof():
                return None  # allow backspace and ctrl+backspace
            else:
                return ('nop', {})  # block backspace and ctrl+backspace

        if command_name == 'move' and args.get('by', None) == 'lines' and 'forward' in args:
            rv.delete_all_between_output_end_and_eof()
            if args.get('forward'):  # arrow down key
                view.run_command('insert', {'characters': rv.get_next_command_history()})
            else:  # arrow up key
                view.run_command('insert', {'characters': rv.get_previous_command_history()})
            return ('nop', {})  # block default behavior

        return None

    def on_pre_close(self, view):
        rv = Repl(view)
        if common.query(common.config, True, 'interactive_repl', 'enable_persistent_history'):
            rv.write_history_file()
        rv.on_pre_close_terminate()
