#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @id           $Id$
# @rev          $Format:%H$ ($Format:%h$)
# @tree         $Format:%T$ ($Format:%t$)
# @date         $Format:%ci$
# @author       $Format:%an$ <$Format:%ae$>
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
import sublime
from . import common

log = logging.getLogger(__name__)
INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['pyminify']
MODULE_CONFIG = {
    'source': 'https://github.com/dflook/python-minifier',
    'name': 'Python Minifier',
    'uid': 'pythonminifier',
    'type': 'minifier',
    'syntaxes': ['python'],
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'python_minifier_rc.json'
    }
}


class PythonminifierFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.uid = kwargs.get('uid', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def get_cmd(self):
        cmd = common.get_head_cmd(self.uid, INTERPRETERS, EXECUTABLES)
        if not cmd:
            return None

        config = common.get_config_path(self.view, self.uid, self.region, self.is_selected)

        if config:
            params = [
                '--no-combine-imports',
                '--no-remove-pass',
                '--remove-literal-statements',
                '--no-remove-annotations',
                '--no-remove-variable-annotations',
                '--no-remove-return-annotations',
                '--no-remove-argument-annotations',
                '--remove-class-attribute-annotations',
                '--no-hoist-literals',
                '--no-rename-locals',
                '--preserve-locals',
                '--rename-globals',
                '--preserve-globals',
                '--no-remove-object-base',
                '--no-convert-posargs-to-args',
                '--no-preserve-shebang',
                '--remove-asserts',
                '--remove-debug',
                '--no-remove-explicit-return-none',
                '--no-remove-builtin-exception-brackets'
            ]

            with open(config, 'r', encoding='utf-8') as file:
                data = file.read()
            json = sublime.decode_value(data)

            for k, v in json.items():
                no_param = '--no-' + k
                param = '--' + k
                if no_param in params and isinstance(v, bool) and not v:
                        cmd.extend([no_param])
                if param in params:
                    if isinstance(v, bool) and v:
                        cmd.extend([param])
                    if isinstance(v, list) and v:
                        cmd.extend([param, ', '.join(v)])

        cmd.extend(['-'])

        return cmd

    def format(self, text):
        cmd = self.get_cmd()
        log.debug('Current arguments: %s', cmd)
        cmd = common.set_fix_cmds(cmd, self.uid)
        if not cmd:
            return None

        try:
            proc = common.exec_cmd(cmd, self.pathinfo['cwd'])
            stdout, stderr = proc.communicate(text.encode('utf-8'))

            errno = proc.returncode
            if errno > 0:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, stderr.decode('utf-8'))
            else:
                return stdout.decode('utf-8')
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
