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

import os
import importlib
import logging
from . import common

log = logging.getLogger(__name__)


class Formatter:
    def __init__(self, view):
        self.formatter_map = self.load_formatters()

    def load_formatters(self):
        formatter_map = {}
        formatter_prefix = 'formatter_'
        formatter_prefix_len = len(formatter_prefix)

        files = [f for f in os.listdir(os.path.dirname(__file__)) if f.startswith(formatter_prefix) and f.endswith('.py')]
        for f in files:
            module_name = os.path.splitext(f)[0]
            module = importlib.import_module('.' + module_name, package=__package__)
            module_formatter = getattr(module, module_name[formatter_prefix_len:].capitalize() + common.PLUGIN_NAME, None)

            if module_formatter:
                formatter_identifier = module_name[formatter_prefix_len:]
                formatter_map[formatter_identifier] = module_formatter

        return formatter_map

    def run_formatter(self, *args, **kwargs):
        view = kwargs.get('view', None)
        identifier = kwargs.get('identifier', None)
        region = kwargs.get('region', None)
        is_selected = kwargs.get('is_selected', False)
        text = kwargs.get('text', None)

        if view.is_read_only() or not view.window() or view.size () == 0:
            log.error('View is not formattable.')
            return None

        if not text:
            return None

        formatter_class = self.formatter_map.get(identifier)
        if formatter_class:
            syntax = common.get_assigned_syntax(view, identifier, region, is_selected)
            if not syntax:
                common.prompt_error('Syntax out of the scope.', 'ID:' + identifier)
            else:
                file = view.file_name()
                log.debug('Target: %s', file if file else '(view)')
                log.debug('Scope: %s', view.scope_name(0 if not is_selected else region.a))
                log.debug('Syntax: %s', syntax)
                log.debug('Formatter ID: %s', identifier)
                worker = formatter_class(*args, **kwargs)
                result = worker.format(text)
                if result:
                    # Pass the result back to the main thread.
                    args = {'result': result, 'region': [region.a, region.b]}
                    view.run_command('substitute', args)
                    return True
        else:
            log.error('Formatter ID not found: %s', identifier)

        return False
