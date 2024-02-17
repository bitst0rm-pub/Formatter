#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import os
import logging
import tempfile
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['dockfmt']
MODULE_CONFIG = {
    'source': 'https://github.com/jessfraz/dockfmt',
    'name': 'Dockfmt',
    'uid': 'dockfmt',
    'type': 'beautifier',
    'syntaxes': ['dockerfile'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/dockfmt',
    'args': None,
    'config_path': None,
    'comment': 'opinionated, no config'
}


class DockfmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        cmd.extend(self.get_args())

        file = self.get_pathinfo()['path']
        tmp_file = None
        if file:
            cmd.extend([file])
        else:
            tmp_file = self.create_tmp_file()
            cmd.extend([tmp_file])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd, tmp_file

    def format(self):
        cmd, tmp_file = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            self.remove_tmp_file(tmp_file)
            return None

        try:
            exitcode, stdout, stderr = self.exec_com(cmd)

            self.remove_tmp_file(tmp_file)

            if exitcode > 0:
                log.error('File not formatted due to an error (exitcode=%d): "%s"', exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.remove_tmp_file(tmp_file)
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
