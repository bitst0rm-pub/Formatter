#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['clang-format']
MODULE_CONFIG = {
    'source': 'https://clang.llvm.org/docs/ClangFormat.html',
    'name': 'ClangFormat',
    'uid': 'clangformat',
    'type': 'beautifier',
    'syntaxes': ['c', 'cs', 'c++', 'objc', 'objc++', 'js', 'tsx', 'jsx', 'json', 'java', 'proto', 'protodevel', 'td', 'sv', 'svh', 'v', 'vh'],
    'exclude_syntaxes': None,
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
            cmd.extend(['--style=file:' + path])

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

        cmd.extend(['--assume-filename=dummy.' + syntax, '--'])

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
