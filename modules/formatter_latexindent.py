#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['perl', 'perl5']
EXECUTABLES = ['latexindent.pl', 'latexindent', 'latexindent-macos', 'latexindent-linux']
MODULE_CONFIG = {
    'source': 'https://github.com/cmhughes/latexindent.pl',
    'name': 'LaTeXindent',
    'uid': 'latexindent',
    'type': 'beautifier',
    'syntaxes': ['tex', 'latex'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/latexindent or /path/to/latexindent.pl',
    'args': None,
    'config_path': {
        'default': 'latexindent_rc.yaml'
    },
    'comment': 'requires perl on PATH if omit interpreter_path'
}


class LatexindentFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        interpreter = self.get_interpreter()
        executable = self.get_executable(runtime_type=None)
        if interpreter and executable and executable.endswith('.pl'):
            cmd = [interpreter, executable]
        elif executable:
            cmd = [executable]
        else:
            return None

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--local', path])

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
