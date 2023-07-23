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

import os
import logging
import tempfile
from distutils.version import StrictVersion
from . import common

log = logging.getLogger('root')
INTERPRETER_NAMES = ['php']
EXECUTABLE_NAMES = ['php-cs-fixer-v3.phar', 'php-cs-fixer-v3', 'phpcsfixer.phar', 'phpcsfixer', 'php-cs-fixer.phar', 'php-cs-fixer', 'php-cs-fixer-v2.phar', 'php-cs-fixer-v2']


class PhpcsfixerFormatter:
    def __init__(self, view, identifier, region, is_selected):
        self.view = view
        self.identifier = identifier
        self.region = region
        self.is_selected = is_selected
        self.pathinfo = common.get_pathinfo(view.file_name())

    def is_compat(self):
        try:
            php = common.get_interpreter_path(INTERPRETER_NAMES)
            if php:
                proc = common.exec_cmd([php, '-v'], self.pathinfo[1])
                stdout = proc.communicate()[0]
                string = stdout.decode('utf-8')
                version = string.splitlines()[0].split(' ')[1]
                if StrictVersion(version) >= StrictVersion('7.4.0'):
                    return True
                common.prompt_error('Current PHP version: %s\nPHP CS Fixer requires a minimum PHP 7.4.0.' % version, 'ID:' + self.identifier)
            return None
        except OSError:
            log.error('Error occurred while validating PHP compatibility.')

        return None

    def get_cmd(self, text):
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
            cmd.extend(['--config=' + config])
            cmd.extend(['--allow-risky=yes'])

        tmp_file = None

        suffix = '.' + common.get_assign_syntax(self.view, self.identifier, self.region, self.is_selected)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix, dir=self.pathinfo[1], encoding='utf-8') as file:
            file.write(text)
            file.close()
            tmp_file = file.name
            cmd.extend(['fix', tmp_file])

        return cmd, tmp_file

    def format(self, text):
        if not self.is_compat():
            return None

        cmd, tmp_file = self.get_cmd(text)
        log.debug('Current arguments: %s', cmd)
        cmd = common.set_fix_cmds(cmd, self.identifier)
        if not cmd:
            if tmp_file and os.path.isfile(tmp_file):
                os.unlink(tmp_file)
            return None

        try:
            proc = common.exec_cmd(cmd, self.pathinfo[1])
            stdout, stderr = proc.communicate()

            result = None
            errno = proc.returncode
            out = stdout.decode('utf-8')

            if errno > 0 or not out:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, stderr.decode('utf-8'))
            else:
                with open(tmp_file, 'r', encoding='utf-8') as file:
                    result = file.read()
                    file.close()
        except OSError:
            log.error('Error occurred while running: %s', ' '.join(cmd))

        if tmp_file and os.path.isfile(tmp_file):
            os.unlink(tmp_file)

        return result
