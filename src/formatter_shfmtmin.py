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
EXECUTABLES = ['shfmt']


class ShfmtminFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.identifier = kwargs.get('identifier', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def get_cmd(self):
        executable = common.get_intr_exec_path(self.identifier, EXECUTABLES, 'executable')
        if not executable:
            return None

        cmd = [executable, '--minify']

        args = common.get_args(self.identifier)
        if args:
            cmd.extend(args)

        cmd.extend(['-'])

        return cmd

    def format(self, text):
        cmd = self.get_cmd()
        log.debug('Current arguments: %s', cmd)
        cmd = common.set_fix_cmds(cmd, self.identifier)
        if not cmd:
            return None

        try:
            proc = common.exec_cmd(cmd, self.pathinfo[1])
            stdout, stderr = proc.communicate(text.encode('utf-8'))

            errno = proc.returncode
            if errno > 0:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, stderr.decode('utf-8'))
            else:
                return stdout.decode('utf-8')
        except OSError:
            log.error('Error occurred while running: %s', ' '.join(cmd))

        return None
