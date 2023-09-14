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

import logging
import os
from . import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['prettier']
MODULE_CONFIG = {
    'source': 'https://github.com/prettier/prettier',
    'name': 'Prettier',
    'uid': 'prettier',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'less', 'js', 'jsx', 'json', 'html', 'graphql', 'markdown', 'tsx', 'vue', 'yaml'],
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'prettier_rc.json'
    }
}


class PrettierFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.uid = kwargs.get('uid', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def get_cmd(self):
        cmd = common.get_head_cmd(self.uid, INTERPRETERS, EXECUTABLES)
        use_local_prettier = False

        if not cmd:
            log.debug("Looking for local prettier...")
            exe = self.resolve_prettier_cli()
            if exe:
                use_local_prettier = True
                cmd = [exe]

        if not cmd:
            return None

        if not use_local_prettier:
            config = common.get_config_path(self.view, self.uid, self.region, self.is_selected)
            if config:
                cmd.extend(['--config', config])
            else:
                cmd.extend(['--no-config'])

        if self.pathinfo['path']:
            cmd.extend(['--stdin-filepath', self.pathinfo['path']])
        else:
            # Prettier automatically infers which parser to use based on the file extension.
            extension = '.' + common.get_assigned_syntax(self.view, self.uid, self.region, self.is_selected)
            cmd.extend(['--stdin-filepath', 'dummy' + extension])

        return cmd

    def resolve_prettier_cli(self):
        """
        Recursively search up the tree from the current file
        to find a local prettier command.

        Code adapted from https://github.com/jonlabelle/SublimeJsPrettier
        """

        def make_local_prettier_path(base):
            return os.path.join(base, 'node_modules', '.bin', 'prettier')

        def make_local_nbl_prettier_path(base):
            return os.path.join(base, 'node_modules', 'prettier', 'bin-prettier.js')

        def make_parent_directories(start, limit = 500):
            dirs = [start]
            next_dir = start

            while limit > 0:
                next_dir = os.path.dirname(next_dir)
                dirs.append(next_dir)

                if (next_dir == os.path.abspath(os.sep)):
                    return dirs

                limit -= 1

            return dirs


        active_view_parents = make_parent_directories(os.path.dirname(self.view.file_name()), limit=500)

        for parent in active_view_parents:
            # Check standard bin
            closest_to_view_prettier = make_local_prettier_path(parent)
            if os.path.exists(closest_to_view_prettier):
                return closest_to_view_prettier

            # Check --no-bin-links
            closest_to_view_prettier = make_local_nbl_prettier_path(parent)
            if os.path.exists(closest_to_view_prettier):
                return closest_to_view_prettier

        # Couldn't find it, return None
        return None

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
