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
from Formatter.modules import common

log = logging.getLogger(__name__)


formatter_map = {}
formatter_prefix = 'formatter_'
formatter_prefix_len = len(formatter_prefix)

module_names = [f[:-3] for f in os.listdir(os.path.dirname(__file__)) if f.startswith(formatter_prefix) and f.endswith('.py')]
for module_name in module_names:
    module = importlib.import_module('.' + module_name, package=__name__)
    formatter_class = getattr(module, module_name[formatter_prefix_len:].capitalize() + common.PACKAGE_NAME, None)

    if formatter_class:
        formatter_uid = module_name[formatter_prefix_len:]
        formatter_map[formatter_uid] = {
            'class': formatter_class,
            'module': module
        }
    else:
        log.error('Either missing or misspelled formatter class in %s.py', module_name)

__all__ = formatter_map
