#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['ocp-indent']
MODULE_CONFIG = {
    'source': 'https://github.com/OCamlPro/ocp-indent',
    'name': 'OCP-indent',
    'uid': 'ocpindent',
    'type': 'beautifier',
    'syntaxes': ['ocaml', 'ocamlyacc', 'ocamllex'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/ocp-indent',
    'args': None,
    'config_path': {
        'default': 'ocpindent_rc.cfg'
    }
}


class OcpindentFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def parse_config(self, path):
        # OCP-indent CLI does not have an option to
        # read external config file. We build one.
        config = []
        with open(path, 'r', encoding='utf-8') as file:
            for line in file:
                original_line = line.strip()
                line_parts = original_line.split('#', 1)
                line = line_parts[0].strip()  # Extract key-value pair, ignoring comments
                if line:
                    if '=' in line:
                        key, value = map(str.strip, line.split('='))
                        config.append(key + '=' + value)
                    else:
                        config.append(line)

        return ','.join(config)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', self.parse_config(path)])

        cmd.extend(['--'])

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
