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
import sublime
from ..core import common
from ..libs.prettytable import prettytable

log = logging.getLogger(__name__)
MODULE_CONFIG = {
    'source': 'https://github.com/jazzband/prettytable',
    'name': 'PrettyTable',
    'uid': 'prettytable',
    'type': 'beautifier',
    'syntaxes': ['csv', 'text'],
    "executable_path": None,
    'args': None,
    'config_path': {
        'default': 'prettytable_rc.json'
    },
    'comment': 'build-in, no executable'
}


class PrettytableFormatter:
    def __init__(self, *args, **kwargs):
        self.view = kwargs.get('view', None)
        self.uid = kwargs.get('uid', None)
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
        config = common.get_config_path(self.view, self.uid, self.region, self.is_selected)
        json = {}
        if config:
            with open(config, 'r', encoding='utf-8') as file:
                data = file.read()
            json = sublime.decode_value(data)
            log.debug('Current arguments: %s', json)

        style = json.get('style', None)
        separator = json.get('separator', None)
        align = json.get('align', None)
        output_format = json.get('output_format', 'text')

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
