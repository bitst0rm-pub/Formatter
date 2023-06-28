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


log = logging.getLogger('root')
INTERPRETER_NAMES = ['ruby']
EXECUTABLE_NAMES = ['rubocop']


class RubocopFormatter:
    def __init__(self, view, identifier, region, is_selected):
        self.view = view
        self.identifier = identifier
        self.region = region
        self.is_selected = is_selected
        self.pathinfo = common.get_pathinfo(view.file_name())


    def get_cmd(self):
        interpreter = common.get_interpreter_path(INTERPRETER_NAMES)
        executable = common.get_executable_path(self.identifier, EXECUTABLE_NAMES)

        if not interpreter or not executable:
            return None

        cmd = [interpreter, executable]

        args = common.get_args(self.identifier)
        if args:
            cmd.extend(args)

        config = common.get_config_path(self.view, self.identifier, self.region, self.is_selected)
        if config:
            cmd.extend(['--config', config])

        cmd.extend(['--stdin', '-', '--auto-correct'])

        return cmd


    def format(self, text):
        cmd = self.get_cmd()
        log.debug('Current executing arguments: %s', cmd)
        if not cmd:
            return None

        try:
            proc = common.exec_cmd(cmd, self.pathinfo[0])
            stdout, stderr = proc.communicate(text.encode('utf-8'))

            errno = proc.returncode
            if errno > 1:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, stderr.decode('utf-8'))
            else:
                if errno == 1:
                    log.warning('Inconsistencies occurred (errno=%d): "%s"', errno, stderr.decode('utf-8'))

                string = stdout.decode('utf-8')
                result = string.split('====================\n')
                if len(result) == 2:
                    return result[1]
                result = string.split('====================\r\n')
                if len(result) == 2:
                    return result[1]
        except OSError:
            log.error('Error occurred when running: %s', ' '.join(cmd))

        return None
