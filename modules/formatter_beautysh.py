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
INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['beautysh']
MODULE_CONFIG = {
    'source': 'https://github.com/lovesegfault/beautysh',
    'name': 'Beautysh',
    'uid': 'beautysh',
    'type': 'beautifier',
    'syntaxes': ['bash'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/beautysh',
    'args': None,
    'config_path': {
        'default': 'beautysh_rc.json'
    },
    'comment': 'requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}'
}


class BeautyshFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(self.get_config(path))

        cmd.extend(['-'])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def get_config(self, path):
        # Beautysh CLI does not have an option to
        # read external config file. We build one.
        with open(path, 'r', encoding='utf-8') as file:
            data = file.read()
        json = sublime.decode_value(data)

        result = []
        for key, value in json.items():
            if type(value) == int:
                result.extend(['--' + key, '%d' % value])
            elif type(value) == bool and value:
                result.extend(['--' + key])
            elif type(value) == str:
                result.extend(['--' + key, '%s' % value])

        return result

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
