#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

import os
import sys
import logging
if sys.version_info < (3, 4):
    import imp
else:
    import importlib
from ..core import common

log = logging.getLogger(__name__)


def load_formatter_modules(module_dir):
    formatter_map = {}
    formatter_prefix = 'formatter_'
    formatter_prefix_len = len(formatter_prefix)

    for filename in os.listdir(module_dir):
        if filename.startswith(formatter_prefix) and filename.endswith('.py'):
            module_name = filename[:-3]
            module_path = os.path.join(module_dir, filename)

            try:
                if sys.version_info < (3, 4):
                    module = imp.load_source('Formatter.modules.' + module_name, module_path)
                else:
                    module = importlib.import_module('Formatter.modules.' + module_name, package=__name__)
            except Exception as e:
                log.error('Error loading module %s: %s', module_name, str(e))
                continue

            formatter_class_name = module_name[formatter_prefix_len:].capitalize() + common.PACKAGE_NAME
            formatter_class = getattr(module, formatter_class_name, None)
            formatter_const = {key.lower(): getattr(module, key, None) for key in ['INTERPRETERS', 'EXECUTABLES']}

            if formatter_class:
                formatter_uid = module_name[formatter_prefix_len:]
                formatter_map[formatter_uid] = {
                    'const': formatter_const,
                    'class': formatter_class,
                    'module': module
                }
            else:
                log.error('Either missing or misspelled formatter class in %s.py', module_name)
                continue

    return formatter_map

__all__ = load_formatter_modules(os.path.dirname(__file__))
