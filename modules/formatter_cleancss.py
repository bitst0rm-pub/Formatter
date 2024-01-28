#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
import sublime
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['cleancss']
MODULE_CONFIG = {
    'source': 'https://github.com/jakubpawlowicz/clean-css-cli',
    'name': 'Clean CSS',
    'uid': 'cleancss',
    'type': 'minifier',
    'syntaxes': ['css', 'scss', 'sass', 'less'],
    'exclude_syntaxes': None,
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'cleancss_rc.json'
    }
}


class CleancssFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(self.get_config(path))

        cmd.extend(['--'])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

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

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                log.error('File not formatted due to an error (exitcode=%d): "%s"', exitcode, stderr)
            else:
                return stdout
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
