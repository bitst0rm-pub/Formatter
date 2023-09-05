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

log = logging.getLogger(__name__)
INTERPRETERS = ['php']
EXECUTABLES = ['php-cs-fixer-v3.phar', 'php-cs-fixer-v3', 'phpcsfixer.phar', 'phpcsfixer', 'php-cs-fixer.phar', 'php-cs-fixer', 'php-cs-fixer-v2.phar', 'php-cs-fixer-v2']
CONFIG_TEMPLATE = {
    'source': 'https://github.com/FriendsOfPHP/PHP-CS-Fixer',
    'name': 'PHP CS Fixer',
    'uid': 'phpcsfixer',
    'type': 'beautifier',
    'syntaxes': ['php'],
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'php_cs_fixer_rc.php'
    }
}


class PhpcsfixerFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.uid = kwargs.get('uid', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def is_compat(self):
        try:
            php = common.get_intr_exec_path(self.uid, INTERPRETERS, 'interpreter')
            if php:
                proc = common.exec_cmd([php, '-v'], self.pathinfo['cwd'])
                stdout = proc.communicate()[0]
                string = stdout.decode('utf-8')
                version = string.splitlines()[0].split(' ')[1]
                if StrictVersion(version) >= StrictVersion('7.4.0'):
                    return True
                common.prompt_error('Current PHP version: %s\nPHP CS Fixer requires a minimum PHP 7.4.0.' % version, 'ID:' + self.uid)
            return None
        except OSError:
            log.error('Error occurred while validating PHP compatibility.')

        return None

    def get_cmd(self, text):
        cmd = common.get_head_cmd(self.uid, INTERPRETERS, EXECUTABLES)
        if not cmd:
            return None

        config = common.get_config_path(self.view, self.uid, self.region, self.is_selected)
        if config:
            cmd.extend(['--config=' + config])
            cmd.extend(['--allow-risky=yes'])

        tmp_file = None

        suffix = '.' + common.get_assigned_syntax(self.view, self.uid, self.region, self.is_selected)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix, dir=self.pathinfo['cwd'], encoding='utf-8') as file:
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
