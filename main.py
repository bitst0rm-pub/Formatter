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
from os.path import (splitext, isfile)
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
        self.cycles = []
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
                    self.cycles.append(is_success)
                    self.print_status(is_success)
                else:
                    # Format selections
                    for region in self.view.sel():
                        if region.empty():
                            continue
                        text = self.view.substr(region)
                        is_success = formatter.run_formatter(self.view, text, region, is_selected, **self.kwargs)
                        self.cycles.append(is_success)
                        self.print_status(is_success)
                if True in self.cycles:
                    self.new_file_on_format()
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
            log.debug('Formatting failed. 💔😢💔')

        if common.settings().get('show_statusbar', False):
            self.view.set_status(common.STATUS_KEY, common.PLUGIN_NAME + ' [ok:' + str(self.success) + '|ko:' + str(self.failure) + ']')

    def new_file_on_format(self):
        formatter = common.settings().get('formatters', {})
        if formatter and isinstance(formatter, dict):
            for key, value in formatter.items():
                suffix = value.get('new_file_on_format', False)
                if suffix and isinstance(suffix, str):
                    file_path = self.view.file_name()
                    if file_path and isfile(file_path):
                        new_path = '{0}.{2}{1}'.format(*splitext(file_path) + (suffix,))
                        self.view.run_command('clone_view', {'path': new_path})
                    else:
                        self.view.run_command('clone_view', {'path': None})
                    sublime.set_timeout(self.undo_history, 1500)

    def undo_history(self):
        c = self.cycles.count(True)
        attempts = 0
        while c > 0:
            self.view.run_command('undo')
            c -= 1
            attempts += 1
            if attempts > 1000:
                log.warning('Seems like undo cycle is endless.')
                raise Exception()


class SubstituteCommand(sublime_plugin.TextCommand):
    def run(self, edit, result, region):
        log.debug('Replacing text ...')
        self.view.replace(edit, sublime.Region(region[0], region[1]), result)


class CloneView(sublime_plugin.TextCommand):
    def run(self, edit, path):
        view = sublime.active_window().new_file()
        view.insert(edit, 0, self.view.substr(sublime.Region(0, self.view.size())))
        view.set_syntax_file(self.view.settings().get('syntax'))

        selections = []
        for selection in self.view.sel():
          selections.append(selection)

        view.sel().clear()
        view.sel().add_all(selections)

        if path:
            view.retarget(path)
            view.set_scratch(True)
            self.save_clone(view, path)
        else:
            view.set_scratch(False)
        self.show_status_on_new_file(view)

    def save_clone(self, view, path):
        allcontent = view.substr(sublime.Region(0, view.size()))
        try:
            with open(path, 'w', encoding='utf-8') as file:
                file.write(allcontent)
        except OSError as e:
            log.error('Could not save file: %s\n%s', path, e)
            common.show_error('Error: Could not save file:\n' + path + '\nError mainly appears due to a lack of necessary permissions.')

    def show_status_on_new_file(self, view):
        if view.is_loading():
            sublime.set_timeout(lambda: self.show_status_on_new_file(view), 250)
        else:
            if common.settings().get('show_statusbar', False):
                view.set_status(common.STATUS_KEY, self.view.get_status(common.STATUS_KEY))


class RunFormatEventListener(sublime_plugin.EventListener):
    @classmethod
    def on_pre_save_async(cls, view):
        is_selected = any(not sel.empty() for sel in view.sel())
        formatter = common.settings().get('formatters', {})
        if formatter and isinstance(formatter, dict):
            for key, value in formatter.items():
                regio = None
                if not is_selected:
                    # entire file
                    regio = sublime.Region(0, view.size())
                else:
                    # selections
                    for region in view.sel():
                        if region.empty():
                            continue
                        regio = region
                syntax = common.get_assign_syntax(view, key, regio, is_selected)
                if value.get('format_on_save', False) and syntax in value.get('syntaxes', []):
                    log.debug('Format-On-Save applied to Formatter ID: %s, with assigned syntax: %s', key, syntax)
                    view.run_command('run_format', {'identifier': key})

    @classmethod
    def on_post_save_async(cls, view):
        _unused = view
        if common.settings().get('debug', False):
            # For debug and development only
            common.reload_modules()
