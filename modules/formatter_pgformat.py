#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['perl']
EXECUTABLES = ['pg_format']
MODULE_CONFIG = {
    'source': 'https://github.com/darold/pgFormatter',
    'name': 'PgFormatter',
    'uid': 'pgformat',
    'type': 'beautifier',
    'syntaxes': ['sql'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/perl.exe or just omit',
    'executable_path': '/path/to/bin/pg_format',
    'args': None,
    'config_path': {
        'default': 'pg_format_rc.cfg'
    },
    'comment': 'requires Perl on PATH if omit interpreter_path'
}


class PgformatFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='perl')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--no-rcfile', '--config', path])

        cmd.extend(['--'])

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
