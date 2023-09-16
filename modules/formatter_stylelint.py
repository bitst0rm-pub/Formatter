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
from . import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['stylelint']
MODULE_CONFIG = {
    'source': 'https://github.com/stylelint/stylelint',
    'name': 'Stylelint',
    'uid': 'stylelint',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'sass', 'less', 'sss', 'sugarss'],
    "executable_path": "",
    'args': ['--config-basedir', '/path/to/javascript/node_modules'],
    'config_path': {
        'default': 'stylelint_rc.json'
    }
}


class StylelintFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.uid = kwargs.get('uid', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def get_cmd(self, text):
        cmd = common.get_head_cmd(self.view, self.uid, INTERPRETERS, EXECUTABLES, runtime_type='node')
        if not cmd:
            return None

        config = common.get_config_path(self.view, self.uid, self.region, self.is_selected)
        if config:
            cmd.extend(['--config', config])

        tmp_file = None

        # Stylelint automatically infers syntax to use based on the file extension.
        suffix = '.' + common.get_assigned_syntax(self.view, self.uid, self.region, self.is_selected)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix, dir=self.pathinfo['cwd'], encoding='utf-8') as file:
            file.write(text)
            file.close()
            tmp_file = file.name
            cmd.extend(['--fix', tmp_file])

        return cmd, tmp_file

    def format(self, text):
        cmd, tmp_file = self.get_cmd(text)
        log.debug('Current arguments: %s', cmd)
        cmd = common.set_fix_cmds(cmd, self.uid)
        if not cmd:
            if tmp_file and os.path.isfile(tmp_file):
                os.unlink(tmp_file)
            return None

        try:
            proc = common.exec_cmd(cmd, self.pathinfo['cwd'])
            stdout, stderr = proc.communicate()

            result = None
            errno = proc.returncode
            if errno > 0:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, stdout.decode('utf-8'))
            else:
                with open(tmp_file, 'r', encoding='utf-8') as file:
                    result = file.read()
                    file.close()
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        if tmp_file and os.path.isfile(tmp_file):
            os.unlink(tmp_file)

        return result