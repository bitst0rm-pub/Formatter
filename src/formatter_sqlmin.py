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
import sublime
from . import common

from ..lib3.sqlmin import sqlmin

log = logging.getLogger(__name__)


class SqlminFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.uid = kwargs.get('uid', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def format(self, text):
        config = common.get_config_path(self.view, self.uid, self.region, self.is_selected)
        json = {}
        if config:
            with open(config, 'r', encoding='utf-8') as file:
                data = file.read()
            json = sublime.decode_value(data)
            log.debug('Current arguments: %s', json)

        try:
            output = sqlmin.minify(text, json)
            errno = output['code']
            result = output['result']

            if errno > 0:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, result)
            else:
                return result
        except OSError:
            log.error('Error occurred while running: %s', ' '.join(json))

        return None
