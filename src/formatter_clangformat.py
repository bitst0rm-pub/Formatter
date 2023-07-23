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
import json
from . import common

from ..lib3 import yaml

log = logging.getLogger('root')
EXECUTABLE_NAMES = ['clang-format']


class ClangformatFormatter:
    def __init__(self, view, identifier, region, is_selected):
        self.view = view
        self.identifier = identifier
        self.region = region
        self.is_selected = is_selected
        self.pathinfo = common.get_pathinfo(view.file_name())

    def get_cmd(self):
        executable = common.get_executable_path(self.identifier, EXECUTABLE_NAMES)

        if not executable:
            return None

        cmd = [executable]

        args = common.get_args(self.identifier)
        if args:
            cmd.extend(args)

        config = common.get_config_path(self.view, self.identifier, self.region, self.is_selected)
        if config:
            with open(config, 'r', encoding='utf-8') as file:
                cfg_dict = yaml.safe_load(file)
            cmd.extend(['--style', json.dumps(cfg_dict)])

        extmap = {
            # (sublime, clang)
            ('c', 'c'),
            ('cs', 'cs'),
            ('c++', 'cpp'),
            ('objc', 'm'),
            ('objc++', 'mm'),
            ('js', 'js'),
            ('tsx', 'ts'),
            ('jsx', 'mjs'),
            ('json', 'json'),
            ('java', 'java'),
            ('proto', 'proto'),
            ('protodevel', 'protodevel'),
            ('td', 'td'),
            ('textpb', 'textpb'),
            ('pb.txt', 'pb.txt'),
            ('textproto', 'textproto'),
            ('asciipb', 'asciipb'),
            ('sv', 'sv'),
            ('svh', 'svh'),
            ('v', 'v'),
            ('vh', 'vh')
        }
        syntax = common.get_assign_syntax(self.view, self.identifier, self.region, self.is_selected)
        for key, value in extmap:
            if key == syntax:
                syntax = value

        cmd.extend(['--assume-filename', 'dummy.' + syntax])

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
