#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @rev          $Format:%H$ ($Format:%h$)
# @tree         $Format:%T$ ($Format:%t$)
# @date         $Format:%ci$
# @author       $Format:%an$ <$Format:%ae$>
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import os
import logging
import tempfile
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['prettydiff']
MODULE_CONFIG = {
    'source': 'https://github.com/prettydiff/prettydiff',
    'name': 'Pretty Diff',
    'uid': 'prettydiffmax',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'less', 'js', 'jsx', 'json', 'html', 'asp', 'xml', 'tsx'],
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'prettydiffmax_rc.json'
    }
}


class PrettydiffmaxFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        cmd.extend(['beautify'])

        path = self.get_config_path()
        if path:
            cmd.extend(['config', path])

        file = self.get_pathinfo()['path']
        tmp_file = None
        if file:
            cmd.extend(['source', file])
        else:
            tmp_file = self.create_tmp_file()
            cmd.extend(['source', tmp_file])

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
