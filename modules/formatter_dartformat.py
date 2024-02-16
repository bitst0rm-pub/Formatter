#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['dart']
MODULE_CONFIG = {
    'source': 'https://dart.dev/tools/dart-format',
    'name': 'Dart Format',
    'uid': 'dartformat',
    'type': 'beautifier',
    'syntaxes': ['dart'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/dart',
    'args': None,
    'config_path': None,
    'comment': 'opinionated, no config'
}


class DartformatFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type='dart')
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        cmd.extend(['format'])

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
