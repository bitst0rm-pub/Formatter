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
from . import common
from .. import src as modules

log = logging.getLogger(__name__)


class Formatter:
    def __init__(self, view):
        pass

    def run_formatter(self, *args, **kwargs):
        view = kwargs.get('view', None)
        uid = kwargs.get('uid', None)
        region = kwargs.get('region', None)
        is_selected = kwargs.get('is_selected', False)
        text = kwargs.get('text', None)

        if view.is_read_only() or not view.window() or view.size () == 0:
            log.error('View is not formattable.')
            return None

        if not text:
            return None

        formatter_map = modules.__all__
        formatter_plugin = formatter_map.get(uid)
        if formatter_plugin:
            syntax = common.get_assigned_syntax(view, uid, region, is_selected)
            if not syntax:
                common.prompt_error('Syntax out of the scope.', 'ID:' + uid)
            else:
                file = view.file_name()
                log.debug('Target: %s', file if file else '(view)')
                log.debug('Scope: %s', view.scope_name(0 if not is_selected else region.a))
                log.debug('Syntax: %s', syntax)
                log.debug('Formatter ID: %s', uid)
                worker = formatter_plugin['class'](*args, **kwargs)
                result = worker.format(text)
                if result:
                    # Pass the result back to the main thread.
                    args = {'result': result, 'region': [region.a, region.b]}
                    view.run_command('substitute', args)
                    return True
        else:
            log.error('Formatter ID not found: %s', uid)

        return False
