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

log = logging.getLogger('root')


class JsonminFormatter:
    def __init__(self, view, identifier, region, is_selected):
        pass

    @classmethod
    def format(cls, text):
        try:
            obj = sublime.decode_value(text)
            result = json.dumps(obj, ensure_ascii=False, separators=(',', ':'), indent=None)
            return result
        except ValueError as err:
            log.error('File not formatted due to ValueError: "%s"', err)

        return None
