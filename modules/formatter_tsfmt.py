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
INTERPRETERS = ['node']
EXECUTABLES = ['tsfmt']
MODULE_CONFIG = {
    'source': 'https://github.com/vvakame/typescript-formatter',
    'name': 'TSfmt',
    'uid': 'tsfmt',
    'type': 'beautifier',
    'syntaxes': ['ts', 'tsx'],
    'exclude_syntaxes': None,
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'tsfmt.json'
    },
    'comment': 'hardcoded config file name'
}


class TsfmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path and '--baseDir' not in cmd:
            cmd.extend(['--baseDir', self.get_pathinfo(path)['cwd']])

        cmd.extend(['--stdin', '--'])

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
                return stdout.replace('\r', '')  # hack <0x0d>
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
