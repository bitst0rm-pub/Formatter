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
EXECUTABLES = ['eslint_d', 'eslint_d.js']
MODULE_CONFIG = {
    'source': 'https://github.com/mantoni/eslint_d.js',
    'name': 'ESLintd',
    'uid': 'eslintd',
    'type': 'beautifier',
    'syntaxes': ['js'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/eslint_d or /path/to/node_modules/.bin/eslint_d.js',
    'args': ['--resolve-plugins-relative-to', '/path/to/javascript/node_modules'],
    'config_path': {
        'default': 'eslintd_rc.json'
    },
    'comment': 'requires node on PATH if omit interpreter_path'
}


class EslintdFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--no-eslintrc', '--config', path])

        cmd.extend(['--no-color', '--stdin', '--fix-dry-run', '--format=json'])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 1:
                self.print_exiterr(exitcode, stderr)
            else:
                obj = sublime.decode_value(stdout)[0]
                if 'output' in obj:
                    return obj.get('output', None)
                self.print_exiterr(exitcode, stderr)
                for i in obj.get('messages', []):
                    print(i)
        except OSError:
            self.print_oserr(cmd)

        return None
