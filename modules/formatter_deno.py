#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['deno']
MODULE_CONFIG = {
    'source': 'https://github.com/denoland/deno',
    'name': 'Deno',
    'uid': 'deno',
    'type': 'beautifier',
    'syntaxes': ['js', 'jsx', 'ts', 'tsx', 'json', 'markdown', 'ipynb'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/deno',
    'args': None,
    'config_path': {
        'default': 'deno_rc.json'
    }
}


class DenoFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        syntax_mapping = {'markdown': 'md'}
        syntax = self.get_assigned_syntax()
        language = syntax_mapping.get(syntax, syntax)
        cmd.extend(['--ext', language])

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
