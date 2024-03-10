#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import logging
import re
from ..core import common

log = logging.getLogger(__name__)


class GenericFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kwargs = kwargs

    def rebuild_cmd(self, cmd):
        temp_dir = self.kwargs.get('temp_dir', None)
        if temp_dir and self.kwargs.get('type', None) == 'graphic':
            temp_dir = common.join(temp_dir, common.GFX_OUT_NAME + '.png')
        else:
            temp_dir = None

        runtime = None
        pattern = r'\{\{\s*e\s*=\s*(.*?)\s*\}\}'
        for item in cmd:
            match = re.search(pattern, item)
            if match:
                runtime = match.group(1).lower()
                break

        new_cmd = []
        for item in cmd:
            item = item.strip()

            match = re.search(r'.*?(\{\{\s*i\s*\}\})', item)
            if match:
                interpreter = self.get_interpreter()
                if interpreter:
                    item = item.replace(match.group(1), interpreter)
                else:
                    continue

            match = re.search(r'\{\{\s*e(?:\s*=\s*[^\s]+)?\s*\}\}', item)
            if match:
                executable = self.get_executable(runtime_type=runtime)
                if executable:
                    item = executable
                else:
                    continue

            match = re.search(r'.*?(\{\{\s*c\s*\}\})', item)
            if match:
                config = self.get_config_path()
                if config:
                    item = item.replace(match.group(1), config)
                else:
                    continue

            match = re.search(r'.*?(\{\{\s*o\s*\}\})', item)
            if match and temp_dir:
                item = item.replace(match.group(1), temp_dir)

            new_cmd.append(item)

        return new_cmd

    def get_cmd(self):
        cmd = self.get_args()
        cmd = self.rebuild_cmd(cmd)

        log.debug('Current arguments: %s', cmd)

        return cmd

    def get_extended_cmd(self):
        cmd_list = []
        for k, v in self.get_args_extended().items():
            if isinstance(v, list):
                cmd_list.append([item.replace(common.GFX_OUT_NAME + '.png', common.GFX_OUT_NAME + '.' + k) for item in self.rebuild_cmd(v)])

        log.debug('Current extended arguments: %s', cmd_list)

        return cmd_list

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode == self.get_success_code():

                for cmd in self.get_extended_cmd():
                    try:
                        self.exec_cmd(cmd)
                    except Exception as e:
                        log.error('An error occurred while executing extended cmd: %s', e)

                return stdout
            else:
                self.print_exiterr(exitcode, stderr)
        except OSError:
            self.print_oserr(cmd)

        return None
