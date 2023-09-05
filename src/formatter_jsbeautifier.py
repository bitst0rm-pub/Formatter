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
INTERPRETERS = ['node']
EXECUTABLES = ['js-beautify']
CONFIG_TEMPLATE = {
    'source': 'https://github.com/beautify-web/js-beautify',
    'name': 'JS Beautifier',
    'uid': 'jsbeautifier',
    'type': 'beautifier',
    'syntaxes': ['js', 'css', 'html', 'json', 'tsx', 'vue'],
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'jsbeautify_rc.json'
    }
}


class JsbeautifierFormatter:
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
            cmd.extend(['--config', config])

        syntax = common.get_assigned_syntax(self.view, self.uid, self.region, self.is_selected)
        cmd.extend(['--type', syntax if syntax in ('js', 'css', 'html') else 'js'])

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
