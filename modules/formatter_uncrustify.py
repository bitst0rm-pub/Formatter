#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['uncrustify']
MODULE_CONFIG = {
    'source': 'https://github.com/uncrustify/uncrustify',
    'name': 'Uncrustify',
    'uid': 'uncrustify',
    'type': 'beautifier',
    'syntaxes': ['c', 'c++', 'cs', 'd', 'es', 'objc', 'objc++', 'java', 'pawn', 'vala'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/uncrustify',
    'args': None,
    'config_path': {
        'objc': 'uncrustify_objc_rc.cfg',
        'objc++': 'uncrustify_objc_rc.cfg',
        'java': 'uncrustify_sun_java_rc.cfg',
        'default': 'uncrustify_rc.cfg'
    }
}


class UncrustifyFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['-c', path])

        syntax_mapping = {'c++': 'cpp', 'objc': 'oc', 'objc++': 'oc+'}
        syntax = self.get_assigned_syntax()
        language = syntax_mapping.get(syntax, syntax)

        cmd.extend(['-l', language])

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
