#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['prettierd']
MODULE_CONFIG = {
    'source': 'https://github.com/fsouza/prettierd',
    'name': 'Prettierd',
    'uid': 'prettierd',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'less', 'js', 'jsx', 'json', 'html', 'graphql', 'markdown', 'tsx', 'vue', 'yaml'],
    'exclude_syntaxes': None,
    "executable_path": "/path/to/node_modules/.bin/prettierd",
    'args': None,
    'config_path': {
        'default': 'prettierd_rc.json'
    }
}


class PrettierdFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            common.config.get('environ').update({'PRETTIERD_DEFAULT_CONFIG': [path]})

        file = self.get_pathinfo()['path']
        if file:
            cmd.extend(['--stdin-filepath', file])
        else:
            # Prettier automatically infers which parser to use based on the file extension.
            syntax = self.get_assigned_syntax()
            cmd.extend(['--stdin-filepath', 'dummy.' + syntax])

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
