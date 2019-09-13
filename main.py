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

import threading
import logging
from pprint import pformat
import sublime
import sublime_plugin
from .src import common
from .src.formatter import Formatter


log = logging.getLogger('root')


def plugin_loaded():
    log.disabled = not common.settings().get('debug', False)
    log.info('%s version: %s', common.PLUGIN_NAME, common.VERSION)
    common.setup_config()
    log.debug('Plugin initialized.')


class ShowVersionCommand(sublime_plugin.WindowCommand):
    @classmethod
    def run(cls):
        sublime.message_dialog(common.PLUGIN_NAME + '\nVersion: ' + common.VERSION)


class OpenConfigFilesCommand(sublime_plugin.WindowCommand):
    def run(self):
        for obj in common.settings().get('formatters', {}).values():
            for path in obj.get('config_path', {}).values():
                if path and isinstance(path, str):
                    path = common.expand_path(path)
                    if common.isfile(path):
                        self.window.open_file(path)


class RunFormatCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        # Edit object is useless here since it gets automatically
        # destroyed before the code is reached in the new thread.
        _unused = edit
        log.debug('Starting a new thread ...')
        runformat_thread = RunFormatThread(self, **kwargs)
        runformat_thread.start()

    def is_enabled(self):
        if self.view.settings().get('is_widget'):
            return False
        return True

    @classmethod
    def is_visible(cls, **kwargs):
        identifier = kwargs.get('identifier', None)
        is_disabled = common.settings().get('formatters', {}).get(identifier, {}).get('disable', True)
        if is_disabled:
            return False
        return True


class RunFormatThread(threading.Thread):
    def __init__(self, cmd, **kwargs):
        self.view = cmd.view
        self.kwargs = kwargs
        self.success = 0
        self.failure = 0
        threading.Thread.__init__(self)
        self.lock = threading.Lock()

    def run(self):
        self.print_environ()
        try:
            with self.lock:
                formatter = Formatter(self.view)
                is_selected = self.has_selection()
                if not is_selected:
                    # Format entire file
                    region = sublime.Region(0, self.view.size())
                    text = self.view.substr(region)
                    is_success = formatter.run_formatter(self.view, text, region, is_selected, **self.kwargs)
                    self.print_status(is_success)
                else:
                    # Format selections
                    for region in self.view.sel():
                        if region.empty():
                            continue
                        text = self.view.substr(region)
                        is_success = formatter.run_formatter(self.view, text, region, is_selected, **self.kwargs)
                        self.print_status(is_success)
        except Exception as error:
            import traceback
            log.error('Error occurred: %s\n%s', error, ''.join(traceback.format_tb(error.__traceback__)))

    def has_selection(self):
        return any(not sel.empty() for sel in self.view.sel())

    @classmethod
    def print_environ(cls):
        if common.settings().get('debug', False):
            log.debug('Environment: %s', pformat(common.update_environ()))

    def print_status(self, is_success):
        if is_success:
            self.success += 1
            log.debug('Formatting successful. 🎉😃🍰')
        else:
            self.failure += 1
            log.debug('Formatting failed. 💣💥😢')

        if common.settings().get('show_statusbar', False):
            self.view.set_status('@' + common.PLUGIN_NAME.lower(), common.PLUGIN_NAME + '(ok:' + str(self.success) + '|fail:' + str(self.failure) + ')')


class SubstituteCommand(sublime_plugin.TextCommand):
    def run(self, edit, result, region):
        log.debug('Replacing text ...')
        self.view.replace(edit, sublime.Region(region[0], region[1]), result)


class RunFormatEventListener(sublime_plugin.EventListener):
    @classmethod
    def on_pre_save_async(cls, view):
        formatter = common.settings().get('formatters', {})
        if formatter and isinstance(formatter, dict):
            for key, value in formatter.items():
                if value.get('format_on_save', False) and self.view.settings().get('syntax') in value.get('syntaxes', []):
                    view.run_command('run_format', {'identifier': key})

    @classmethod
    def on_post_save_async(cls, view):
        _unused = view
        if common.settings().get('debug', False):
            # For debug and development only
            common.reload_modules()
