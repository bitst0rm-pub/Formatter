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
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['tidy']
MODULE_CONFIG = {
    'source': 'https://github.com/htacg/tidy-html5',
    'name': 'HTML Tidy',
    'uid': 'htmltidy',
    'type': 'beautifier',
    'syntaxes': ['html', 'xml'],
    'exclude_syntaxes': None,
    "executable_path": "",
    'args': None,
    'config_path': {
        'html': 'htmltidy_html_rc.cfg',
        'xml': 'htmltidy_xml_rc.cfg'
    }
}


class HtmltidyFormatter(common.Module):
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
            cmd.extend(['-config', path])

        cmd.extend(['-'])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 1:
                log.error('File not formatted due to an error (exitcode=%d): "%s"', exitcode, stderr)
            else:
                if exitcode == 1:
                    log.warning('File formatted but with warnings (exitcode=%d): "%s"', exitcode, stderr)
                return stdout
        except OSError:
            log.error('An error occurred while executing the command: %s', ' '.join(cmd))

        return None
