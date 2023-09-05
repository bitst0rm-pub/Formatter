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
from . import common

log = logging.getLogger(__name__)
EXECUTABLES = ['uncrustify']
CONFIG_TEMPLATE = {
    'source': 'https://github.com/uncrustify/uncrustify',
    'name': 'Uncrustify',
    'uid': 'uncrustify',
    'type': 'beautifier',
    'syntaxes': ['c', 'c++', 'cs', 'objc', 'objc++', 'd', 'java', 'pawn', 'vala'],
    "executable_path": "",
    'args': None,
    'config_path': {
        'objc': 'uncrustify_objc_rc.cfg',
        'objc++': 'uncrustify_objc_rc.cfg',
        'java': 'uncrustify_sun_java_rc.cfg',
        'default': 'uncrustify_rc.cfg'
    }
}


class UncrustifyFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.uid = kwargs.get('uid', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def get_cmd(self):
        executable = common.get_intr_exec_path(self.uid, EXECUTABLES, 'executable')
        if not executable:
            return None

        cmd = [executable]

        args = common.get_args(self.uid)
        if args:
            cmd.extend(args)

        config = common.get_config_path(self.view, self.uid, self.region, self.is_selected)
        if config:
            cmd.extend(['-c', config])

        syntax = common.get_assigned_syntax(self.view, self.uid, self.region, self.is_selected)
        if syntax == 'c++':
            language = 'cpp'
        elif syntax == 'objc':
            language = 'oc'
        elif syntax == 'objc++':
            language = 'oc+'
        else:
            language = syntax

        cmd.extend(['-l', language])

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
            log.error('Error occurred while running: %s', ' '.join(cmd))

        return None
