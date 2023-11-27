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
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'beautysh_rc.json'
    }
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
                log.error('File not formatted due to an error (exitcode=%d): "%s"', exitcode, stderr)
            else:
                return stdout
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
