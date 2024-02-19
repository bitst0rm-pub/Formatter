#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from distutils.version import StrictVersion
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['nginxfmt']
MODULE_CONFIG = {
    'source': 'https://github.com/slomkowski/nginx-config-formatter',
    'name': 'NGINXfmt',
    'uid': 'nginxfmt',
    'type': 'beautifier',
    'syntaxes': ['nginx'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/nginxfmt',
    'args': ['--indent', '4'],
    'config_path': None,
    'comment': 'requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}. no config, use args instead'
}


class NginxfmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def is_compat(self):
        try:
            python = self.get_interpreter()
            if python:
                proc = self.popen([python, '-V'])
                stdout = proc.communicate()[0]
                string = stdout.decode('utf-8')
                version = string.splitlines()[0].split(' ')[1]

                if StrictVersion(version) >= StrictVersion('3.4.0'):
                    return True
                self.popup_message('Current Python version: %s\nnginxfmt requires a minimum Python 3.4.0' % version, 'ID:' + self.uid)
            return False
        except OSError:
            log.error('Error occurred while validating Python compatibility.')

        return False

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

        cmd.extend(['--pipe', '--'])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd) or not self.is_compat():
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
