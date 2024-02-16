#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['raco']
MODULE_CONFIG = {
    'source': 'https://github.com/sorawee/fmt',
    'name': 'Racofmt',
    'uid': 'racofmt',
    'type': 'beautifier',
    'syntaxes': ['racket'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/raco',
    'args': ['--width', '102', '--limit', '120', '--max-blank-lines', '1', '--indent', '0'],
    'config_path': '',
    'comment': 'undocumented --config <config_path>, use args instead. config_path can be still used in place of --config'
}


class RacofmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

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
                log.error('File not formatted due to an error (exitcode=%d): "%s"', exitcode, stderr)
            else:
                return stdout
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
