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
import json
from ..core import common
from ..libs import yaml

log = logging.getLogger(__name__)
EXECUTABLES = ['clang-format']
MODULE_CONFIG = {
    'source': 'https://clang.llvm.org/docs/ClangFormat.html',
    'name': 'ClangFormat',
    'uid': 'clangformat',
    'type': 'beautifier',
    'syntaxes': ['c', 'cs', 'c++', 'objc', 'objc++', 'js', 'tsx', 'jsx', 'json', 'java', 'proto', 'protodevel', 'td', 'sv', 'svh', 'v', 'vh'],
    "executable_path": "",
    'args': None,
    'config_path': {
        'default': 'clang_format_llvm_rc.yaml'
    }
}


class ClangformatFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
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
        syntax = self.get_assigned_syntax()
        syntax = next(value for key, value in extmap if key == syntax)

        cmd.extend(['--assume-filename', 'dummy.' + syntax])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                log.error('File not formatted due to an error (exitcode=%d): "%s"', exitcode, stderr)
            else:
                return stdout
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
