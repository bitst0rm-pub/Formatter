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
import sublime
from . import common


log = logging.getLogger('root')


class JsonmaxFormatter:
    def __init__(self, view, identifier, region, is_selected):
        self.view = view
        self.identifier = identifier
        self.region = region
        self.is_selected = is_selected


    def format(self, text):
        config = common.get_config_path(self.view, self.identifier, self.region, self.is_selected)
        if config:
            with open(config, 'r', encoding='utf-8') as file:
                cfg = json.load(file)

        try:
            obj = sublime.decode_value(text)
            result = json.dumps(
                obj,
                ensure_ascii=False,
                indent=cfg.get('indent', 4),
                sort_keys=cfg.get('sort_keys', False),
                separators=cfg.get('separators', None))
            return result
        except ValueError as err:
            log.error('File not formatted due to ValueError: "%s"', err)

        return None
