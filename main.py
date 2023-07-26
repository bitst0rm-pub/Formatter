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
import traceback
from pprint import pformat
import sublime
import sublime_plugin
from .src import common
from .src.formatter import Formatter

log = logging.getLogger('root')


def plugin_loaded():
    common.get_config()
    log.disabled = not common.config.get('debug')
    log.info('%s version: %s', common.PLUGIN_NAME, common.VERSION)
    common.setup_shared_config()
    log.debug('Plugin initialized.')


class ShowVersionCommand(sublime_plugin.WindowCommand):
    @classmethod
    def run(cls):
        sublime.message_dialog(common.PLUGIN_NAME + '\nVersion: ' + common.VERSION)


class OpenConfigFoldersCommand(sublime_plugin.WindowCommand):
    def run(self):
        configdir = common.expand_path('${packages}/User/' + common.ASSETS_DIRECTORY + '/config')
        if common.isdir(configdir):
            self.window.run_command('open_dir', {'dir': configdir})

        for obj in common.config.get('formatters', {}).values():
            for path in obj.get('config_path', {}).values():
                if path and isinstance(path, str):
                    dirpath = common.get_pathinfo(path)[1]
                    if common.isdir(dirpath):
                        self.window.run_command('open_dir', {'dir': dirpath})


class RunFormatCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        # Edit object is useless here since it gets automatically
        # destroyed before the code is reached in the new thread.
        _unused = edit
        log.debug('Starting a new main thread ...')
        format_thread = FormatThread(self, **kwargs)
        format_thread.start()

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    @classmethod
    def is_visible(cls, **kwargs):
        log.disabled = not common.config.get('debug')
        identifier = kwargs.get('identifier', None)
        is_disabled = common.config.get('formatters', {}).get(identifier, {}).get('disable', True)
        return not is_disabled


class FormatThread(threading.Thread):
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
                    # Format entire file using separate threads
                    region = sublime.Region(0, self.view.size())
                    text = self.view.substr(region)
                    is_success = formatter.run_formatter(self.view, text, region, is_selected, **self.kwargs)
                    self.cycles.append(is_success)
                    self.print_status(is_success)
                else:
                    # Format selections in parallel using separate threads
                    threads = []
                    for region in self.view.sel():
                        if region.empty():
                            continue
                        log.debug('Starting a new selection thread ...')
                        thread = SelectionFormatThread(self.view, formatter, region, is_selected, **self.kwargs)
                        threads.append(thread)
                        thread.start()

                    for thread in threads:
                        thread.join()
                        is_success = thread.is_success
                        self.cycles.append(is_success)
                        self.print_status(is_success)

                if True in self.cycles:
                    self.new_file_on_format()
                else:
                    self.open_console_on_failure()
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))

    def has_selection(self):
        return any(not sel.empty() for sel in self.view.sel())

    @classmethod
    def print_environ(cls):
        if common.config.get('debug'):
            log.debug('System environments:\n%s', pformat(common.update_environ()))

    def print_status(self, is_success):
        if is_success:
            self.success += 1
            log.debug('Formatting successful. 🎉😃🍰')
        else:
            self.failure += 1
            log.debug('Formatting failed. 💔😢💔')

        if common.config.get('show_statusbar'):
            self.view.window().set_status_bar_visible(True)
            self.view.set_status(common.STATUS_KEY, common.PLUGIN_NAME + ' [ok:' + str(self.success) + '|ko:' + str(self.failure) + ']')

    def open_console_on_failure(self):
        if common.config.get('open_console_on_failure'):
            self.view.window().run_command('show_panel', {'panel': 'console', 'toggle': True})

    def new_file_on_format(self):
        formatters = common.config.get('formatters')
        for key, value in formatters.items():
            suffix = value.get('new_file_on_format', False)
            if suffix and isinstance(suffix, str):
                file_path = self.view.file_name()
                if file_path and common.isfile(file_path):
                    new_path = '{0}.{2}{1}'.format(*common.splitext(file_path) + (suffix,))
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


class SelectionFormatThread(threading.Thread):
    def __init__(self, view, formatter, region, is_selected, **kwargs):
        self.view = view
        self.formatter = formatter
        self.region = region
        self.is_selected = is_selected
        self.kwargs = kwargs
        self.is_success = False
        threading.Thread.__init__(self)
        self.lock = threading.Lock()

    def run(self):
        try:
            with self.lock:
                text = self.view.substr(self.region)
                self.is_success = self.formatter.run_formatter(self.view, text, self.region, self.is_selected, **self.kwargs)
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))


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
            common.prompt_error('Error: Could not save file:\n' + path + '\nError mainly appears due to a lack of necessary permissions.')

    def show_status_on_new_file(self, view):
        if view.is_loading():
            sublime.set_timeout(lambda: self.show_status_on_new_file(view), 250)
        else:
            if common.config.get('show_statusbar'):
                view.window().set_status_bar_visible(True)
                view.set_status(common.STATUS_KEY, self.view.get_status(common.STATUS_KEY))


class Listener(sublime_plugin.EventListener):
    @classmethod
    def on_pre_save_async(cls, view):
        used = []
        is_selected = any(not sel.empty() for sel in view.sel())
        formatters = common.config.get('formatters')
        for key, value in formatters.items():
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
            syntax = common.get_assigned_syntax(view, key, regio, is_selected)
            if value.get('format_on_save', False) and syntax in value.get('syntaxes', []):
                if syntax in used:
                    break
                log.debug('format_on_save for Formatter ID: %s, using syntax: %s', key, syntax)
                view.run_command('run_format', {'identifier': key})
                used.append(syntax)

    @classmethod
    def on_post_save_async(cls, view):
        _unused = view
        if common.config.get('debug'):
            # For debug and development only
            common.reload_modules()
