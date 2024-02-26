#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['rebar3', 'efmt']
MODULE_CONFIG = {
    'source': 'https://github.com/sile/efmt',
    'name': 'Erlang efmt',
    'uid': 'efmt',
    'type': 'beautifier',
    'syntaxes': ['erlang'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/efmt (standalone bin) or /path/to/rebar3',
    'args': None,
    'config_path': None,
    'comment': 'opinionated, no config'
}


class EfmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        if common.basename(executable) == 'rebar3':
            cmd = [executable, 'efmt']
        else:
            cmd = [executable]

        cmd.extend(self.get_args())

        cmd.extend(['-'])

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
