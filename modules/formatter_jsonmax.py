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
import sublime
from ..core import common

log = logging.getLogger(__name__)
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'JSON',
    'uid': 'jsonmax',
    'type': 'beautifier',
    'syntaxes': ['json'],
    'exclude_syntaxes': None,
    "executable_path": None,
    'args': None,
    'config_path': {
        'default': 'jsonmax_rc.json'
    },
    'comment': 'build-in, no executable'
}


class JsonmaxFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                cmd = json.load(file)
            log.debug('Current arguments: %s', cmd)

        try:
            text = self.get_text_from_region(self.region)
            obj = sublime.decode_value(text)
            result = json.dumps(obj, **cmd)
            return result
        except ValueError as err:
            log.error('File not formatted due to ValueError: "%s"', err)

        return None
