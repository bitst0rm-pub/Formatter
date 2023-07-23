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

from ..lib3.sqlmin import sqlmin

log = logging.getLogger('root')


class SqlminFormatter:
    def __init__(self, view, identifier, region, is_selected):
        self.view = view
        self.identifier = identifier
        self.region = region
        self.is_selected = is_selected
        self.pathinfo = common.get_pathinfo(view.file_name())

    def format(self, text):
        config = common.get_config_path(self.view, self.identifier, self.region, self.is_selected)
        cmd = {}
        if config:
            with open(config, 'r', encoding='utf-8') as file:
                cmd = json.load(file)
            log.debug('Current arguments: %s', cmd)

        try:
            output = sqlmin.minify(text, cmd)
            errno = output['code']
            result = output['result']

            if errno > 0:
                log.error('File not formatted due to an error (errno=%d): "%s"', errno, result)
            else:
                return result
        except OSError:
            log.error('Error occurred while running: %s', ' '.join(cmd))

        return None
