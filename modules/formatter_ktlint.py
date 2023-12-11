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
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['java']
EXECUTABLES = ['ktlint']
MODULE_CONFIG = {
    'source': 'https://github.com/pinterest/ktlint',
    'name': 'Ktlint',
    'uid': 'ktlint',
    'type': 'beautifier',
    'syntaxes': ['kotlin'],
    'exclude_syntaxes': None,
    "executable_path": "",
    'args': None,
    'comment': 'no config'
}


class KtlintFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        if common.IS_WINDOWS:
            executable = self.get_executable(runtime_type=None)
            if executable.endswith('bat'):
                cmd = [executable]

                cmd.extend(self.get_args())
            else:
                cmd = self.get_combo_cmd(runtime_type=None)
                cmd[1:1] = ['-jar']
        else:
            cmd = self.get_combo_cmd(runtime_type=None)
            cmd[1:1] = ['-jar']

        if not self.is_valid_cmd(cmd):
            return None

        cmd.extend(['--format', '--stdin', '-'])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

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
