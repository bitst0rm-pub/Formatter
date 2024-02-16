#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['ruby']
EXECUTABLES = ['standardrb']
MODULE_CONFIG = {
    'source': 'https://github.com/standardrb/standard',
    'name': 'Standard RB',
    'uid': 'standardrb',
    'type': 'beautifier',
    'syntaxes': ['ruby'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/standardrb',
    'args': None,
    'config_path': None,
    'comment': 'requires "environ": {"GEM_PATH": ["/path/to/dir/ruby"]}. opinionated, no config'
}


class StandardrbFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='ruby')
        if not cmd:
            return None

        base = self.get_pathinfo()['base']
        cmd.extend(['--fix', '--stdin', base if base else 'untitled', '--stderr'])

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
                log.debug('Success (exitcode=%d): "%s"', exitcode, stderr)
                return stdout
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
