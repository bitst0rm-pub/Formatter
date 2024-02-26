#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['cabal-fmt']
MODULE_CONFIG = {
    'source': 'https://github.com/phadej/cabal-fmt',
    'name': 'Cabal-fmt',
    'uid': 'cabalfmt',
    'type': 'beautifier',
    'syntaxes': ['cabal'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/.cabal/bin/cabal-fmt',
    'args': ['--tabular', '--indent', '4'],
    'config_path': None,
    'comment': 'requires haskell. use args instead of config_path'
}


class CabalfmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        cmd.extend(['--stdout', '--'])

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
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
