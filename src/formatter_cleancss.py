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
import logging
import tempfile
import sublime
from . import common


log = logging.getLogger('root')
INTERPRETER_NAMES = ['node']
EXECUTABLE_NAMES = ['cleancss']


class CleancssFormatter:
    def __init__(self, view, identifier, region, is_selected):
        self.view = view
        self.identifier = identifier
        self.region = region
        self.is_selected = is_selected
        self.pathinfo = common.get_pathinfo(view.file_name())


    def get_cmd(self, filename):
        interpreter = common.get_interpreter_path(INTERPRETER_NAMES)
        executable = common.get_executable_path(self.identifier, EXECUTABLE_NAMES)

        if not interpreter or not executable:
            return None

        cmd = [interpreter, executable]

        args = common.get_args(self.identifier)
        if args:
            cmd.extend(args)

        config = common.get_config_path(self.view, self.identifier, self.region, self.is_selected)
        if config:
            cmd.extend(self.get_config(config))

        cmd.extend([filename, '--output', filename])

        return cmd


    def format(self, text):
        suffix = '.' + common.get_assign_syntax(self.view, self.identifier, self.region, self.is_selected)

        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix, dir=self.pathinfo[1], encoding='utf-8') as file:
                file.write(text)
                file.close()
                result = self._format(file.name)
        finally:
            if os.path.isfile(file.name):
                os.unlink(file.name)

        return result


    def _format(self, filename):
        cmd = self.get_cmd(filename)
        if not cmd:
            return None

        try:
            proc = common.exec_cmd(cmd, self.pathinfo[0])
            stderr = proc.communicate()[1]

            errno = proc.returncode
            if errno > 0:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, stderr.decode('utf-8'))
            else:
                with open(filename, 'r', encoding='utf-8') as file:
                    result = file.read()
                    return result
        except OSError:
            log.error('Error occurred when running: %s', ' '.join(cmd))

        return None


    @classmethod
    def get_config(cls, path):
        # Cleancss CLI does not have an option to
        # read external config file. We build one.
        with open(path, 'r', encoding='utf-8') as file:
            string = file.read()
        json = sublime.decode_value(string)

        result = []

        for key, value in json.items():
            typ = type(value)
            if typ == list:
                result.extend(['--' + key, ','.join(value)])
            if typ == int:
                result.extend(['--' + key, '%d' % value])
            if typ == bool:
                if value:
                    result.append('--' + key)
            if typ == dict:
                if key == 'compatibility':
                    for keylv1, valuelv1 in value.items():
                        string = ''
                        for keylv2, valuelv2 in valuelv1.items():
                            typ = type(valuelv2)
                            if typ == bool:
                                string += (('+' if valuelv2 else '-') + keylv2 + ',')
                        if string:
                            result.extend(['--compatibility', keylv1 + ',' + string[:-1]])
                if key == 'format':
                    for keylv1, valuelv1 in value.items():
                        if keylv1 in ('beautify', 'keep-breaks'):
                            result.extend(['--format', keylv1])
                        else:
                            string = ''
                            for keylv2, valuelv2 in valuelv1.items():
                                typ = type(valuelv2)
                                if typ == bool:
                                    string += (keylv2 + '=' + ('on' if valuelv2 else 'off') + ';')
                                if typ == str:
                                    string += (keylv2 + ':' + valuelv2 + ';')
                                if typ == int:
                                    string += (keylv2 + ':' + '%d' % valuelv2 + ';')
                            if string:
                                result.extend(['--format', string[:-1]])
                if key == 'optimization':
                    if '0' in str(value['level']):
                        result.append('-O0')
                    else:
                        for keylv1, valuelv1 in value.items():
                            if keylv1 in str(value['level']):
                                string = ''
                                for keylv2, valuelv2 in valuelv1.items():
                                    typ = type(valuelv2)
                                    if typ == bool:
                                        string += (keylv2 + ':' + ('on' if valuelv2 else 'off') + ';')
                                    if typ == list and valuelv2:
                                        string += (keylv2 + ':' + ','.join(valuelv2) + ';')
                                    if typ == str:
                                        string += (keylv2 + ':' + valuelv2 + ';')
                                    if typ == int:
                                        string += (keylv2 + ':' + '%d' % valuelv2 + ';')
                                if string:
                                    result.extend(['-O' + keylv1, string[:-1]])
        return result
