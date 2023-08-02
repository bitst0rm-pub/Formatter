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

from ..lib3.prettytable import prettytable

log = logging.getLogger('__name__')


class PrettytableFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.identifier = kwargs.get('identifier', None)
        self.region = kwargs.get('region', None)
        self.is_selected = kwargs.get('is_selected', False)
        self.pathinfo = common.get_pathinfo(self.view.file_name())

    def read_data(self, text, sep):
        lines = text.splitlines()
        for line in lines:
            yield line.split(sep)

    def make_table(self, data):
        table = prettytable.PrettyTable()
        table.field_names = next(data)

        for row in data:
            if len(row) != len(table.field_names):
                continue
            table.add_row(row)

        return table

    def format(self, text):
        config = common.get_config_path(self.view, self.identifier, self.region, self.is_selected)
        cmd = {}
        if config:
            with open(config, 'r', encoding='utf-8') as file:
                cmd = json.load(file)
            log.debug('Current arguments: %s', cmd)

        style = cmd.get('style', None)
        separator = cmd.get('separator', None)
        align = cmd.get('align', None)
        output_format = cmd.get('output_format', 'text')

        stylemap = [
            ('ALL', prettytable.ALL),
            ('DEFAULT', prettytable.DEFAULT),
            ('DOUBLE_BORDER', prettytable.DOUBLE_BORDER),
            ('FRAME', prettytable.FRAME),
            ('HEADER', prettytable.HEADER),
            ('MARKDOWN', prettytable.MARKDOWN),
            ('MSWORD_FRIENDLY', prettytable.MSWORD_FRIENDLY),
            ('NONE', prettytable.NONE),
            ('ORGMODE', prettytable.ORGMODE),
            ('PLAIN_COLUMNS', prettytable.PLAIN_COLUMNS),
            ('RANDOM', prettytable.RANDOM),
            ('SINGLE_BORDER', prettytable.SINGLE_BORDER)
        ]

        sty = prettytable.DEFAULT
        for name, value in stylemap:
            if name.lower() == style.lower():
                sty = value
                break

        data = self.read_data(text, separator)
        table = self.make_table(data)
        table.set_style(sty)
        table.align = align

        out = table.get_formatted_string(output_format)
        if out:
            return out
        else:
            log.error('File not formatted due to an error.')
        return None
