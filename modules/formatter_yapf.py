#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['yapf']
MODULE_CONFIG = {
    'source': 'https://github.com/google/yapf',
    'name': 'YAPF',
    'uid': 'yapf',
    'type': 'beautifier',
    'syntaxes': ['python'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/yapf',
    'args': None,
    'config_path': {
        'default': 'yapf_rc.yapf'
    },
    'comment': 'requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}'
}


class YapfFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--style=' + path])

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
                log.error('File not formatted due to an error (exitcode=%d): "%s"', exitcode, stderr)
            else:
                return stdout
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
