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

import logging
import sublime
from . import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['cleancss']
MODULE_CONFIG = {
    'source': 'https://github.com/jakubpawlowicz/clean-css-cli',
    'name': 'Clean CSS',
    'uid': 'cleancss',
    'type': 'minifier',
    'syntaxes': ['css', 'scss', 'sass', 'less'],
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'cleancss_rc.json'
    }
}


class CleancssFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.uid = kwargs.get('uid', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def get_cmd(self):
        cmd = common.get_head_cmd(self.uid, INTERPRETERS, EXECUTABLES)
        if not cmd:
            return None

        config = common.get_config_path(self.view, self.uid, self.region, self.is_selected)
        if config:
            cmd.extend(self.get_config(config))

        cmd.extend(['--'])

        return cmd

    def get_config(self, path):
        # Cleancss CLI does not have an option to
        # read external config file. We build one.
        with open(path, 'r', encoding='utf-8') as file:
            data = file.read()
        json = sublime.decode_value(data)

        result = []

        for key, value in json.items():
            if type(value) == list:
                result.extend(['--' + key, ','.join(value)])
            elif type(value) == int:
                result.extend(['--' + key, '%d' % value])
            elif type(value) == bool and value:
                result.append('--' + key)
            elif type(value) == str:
                result.extend(['--' + key, '%s' % value])
            elif type(value) == dict:
                if key == 'compatibility':
                    for keylv1, valuelv1 in value.items():
                        string = ''
                        for keylv2, valuelv2 in valuelv1.items():
                            if type(valuelv2) == bool:
                                string += (('+' if valuelv2 else '-') + keylv2 + ',')
                            elif type(valuelv2) == list and valuelv2:
                                string += (('+' if valuelv2 else '-') + keylv2 + ':' + ','.join(valuelv2) + ';')
                        if string:
                            result.extend(['--compatibility', keylv1 + ',' + string[:-1]])
                if key == 'format':
                    for keylv1, valuelv1 in value.items():
                        if keylv1 in ('beautify', 'keep-breaks'):
                            result.extend(['--format', keylv1])
                        else:
                            string = ''
                            for keylv2, valuelv2 in valuelv1.items():
                                if type(valuelv2) == bool:
                                    string += (keylv2 + '=' + ('on' if valuelv2 else 'off') + ';')
                                elif type(valuelv2) == str:
                                    string += (keylv2 + ':' + valuelv2 + ';')
                                elif type(valuelv2) == int:
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
                                    if type(valuelv2) == bool:
                                        string += (keylv2 + ':' + ('on' if valuelv2 else 'off') + ';')
                                    elif type(valuelv2) == list and valuelv2:
                                        string += (keylv2 + ':' + ','.join(valuelv2) + ';')
                                    elif type(valuelv2) == str:
                                        string += (keylv2 + ':' + valuelv2 + ';')
                                    elif type(valuelv2) == int:
                                        string += (keylv2 + ':' + '%d' % valuelv2 + ';')
                                if string:
                                    result.extend(['-O' + keylv1, string[:-1]])

        return result

    def format(self, text):
        cmd = self.get_cmd()
        log.debug('Current arguments: %s', cmd)
        cmd = common.set_fix_cmds(cmd, self.uid)
        if not cmd:
            return None

        try:
            proc = common.exec_cmd(cmd, self.pathinfo['cwd'])
            stdout, stderr = proc.communicate(text.encode('utf-8'))

            errno = proc.returncode
            if errno > 0:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, stderr.decode('utf-8'))
            else:
                return stdout.decode('utf-8')
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
