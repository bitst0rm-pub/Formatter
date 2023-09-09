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
import traceback
import json
import time
import threading
import sublime
import sublime_plugin
from threading import Event
from .modules import common
from .modules import configurator
from .modules.formatter import Formatter

log = logging.getLogger(__name__)

SYNC_SCROLL = {
    'view_pairs': [],
    'view_src': None,
    'view_dst': None,
    'view_active': None,
    'abort': False
}

RECURSIVE_TARGET = {
    'view': None,
    'kwargs': None,
    'cwd': None,
    'filelist': [],
    'filelist_length': 0,
    'current_index': 0,
    'success_count': 0,
    'failure_count': 0
}


def plugin_loaded():
    ready = configurator.create_package_config_files()
    common.get_config()
    log.disabled = not common.config.get('debug')
    log.info('%s version: %s', common.PACKAGE_NAME, common.VERSION)
    common.setup_shared_config()
    log.debug('Plugin initialization ' + ('succeeded.' if ready else 'failed.'))


class ShowVersionCommand(sublime_plugin.WindowCommand):
    def run(self):
        sublime.message_dialog(common.PACKAGE_NAME + '\nVersion: ' + common.VERSION)


class OpenConfigFoldersCommand(sublime_plugin.WindowCommand):
    def run(self):
        opened_dirs = set()

        configdir = common.expand_path(common.join('${packages}', 'User', common.ASSETS_DIRECTORY, 'config'))
        if common.isdir(configdir):
            self.window.run_command('open_dir', {'dir': configdir})
            opened_dirs.add(configdir)

        for obj in common.config.get('formatters', {}).values():
            for path in obj.get('config_path', {}).values():
                if path and isinstance(path, str):
                    dirpath = common.get_pathinfo(path)['cwd']
                    if common.isdir(dirpath) and dirpath not in opened_dirs:
                        self.window.run_command('open_dir', {'dir': dirpath})
                        opened_dirs.add(dirpath)


class RunFormatCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        # Edit object is useless here since it gets automatically
        # destroyed before the code is reached in the new thread.
        _unused = edit
        uid = kwargs.get('uid', None)

        if common.query(common.config, False, 'formatters', uid, 'recursive_folder_format', 'enable'):
            if self.view.file_name():
                recursive_format_lock = threading.Lock()
                with recursive_format_lock:
                    log.debug('Starting the main thread for recursive folder formattting ...')
                    recursive_format = RecursiveFormat(self.view, **kwargs)
                    recursive_format_thread = threading.Thread(target=recursive_format.run)
                    recursive_format_thread.start()
            else:
                common.prompt_error('ERROR: Failed due to unsaved view. Recursive folder formatting requires an existing file on disk, which must be opened as the starting point.')
        else:
            single_format_lock = threading.Lock()
            with single_format_lock:
                log.debug('Starting the main thread for single file formatting ...')
                single_format = SingleFormat(self.view, **kwargs)
                single_format_thread = threading.Thread(target=single_format.run)
                single_format_thread.start()

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self, **kwargs):
        log.disabled = not common.config.get('debug')
        uid = kwargs.get('uid', None)
        is_disabled = common.query(common.config, True, 'formatters', uid, 'disable')
        return not is_disabled


class SingleFormat:
    def __init__(self, view, **kwargs):
        self.view = view
        self.kwargs = kwargs
        self.success = 0
        self.failure = 0
        self.cycles = []

    def run(self):
        log.debug('System environments:\n%s', json.dumps(common.update_environ(), indent=4))
        try:
            formatter = Formatter(self.view)
            is_selected = self.has_selection()
            self.kwargs['view'] = self.view
            self.kwargs['is_selected'] = is_selected

            if not is_selected:
                # Format entire file
                region = sublime.Region(0, self.view.size())
                text = self.view.substr(region)
                self.kwargs['text'] = text
                self.kwargs['region'] = region
                is_success = formatter.run_formatter(**self.kwargs)
                self.cycles.append(is_success)
                self.print_status(is_success)
            else:
                # Format selections
                for region in self.view.sel():
                    if region.empty():
                        continue
                    text = self.view.substr(region)
                    self.kwargs['text'] = text
                    self.kwargs['region'] = region
                    is_success = formatter.run_formatter(**self.kwargs)
                    self.cycles.append(is_success)
                    self.print_status(is_success)

            if any(self.cycles):
                self.new_file_on_format(self.kwargs.get('uid', None))
            else:
                self.open_console_on_failure()
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))

    def has_selection(self):
        return any(not sel.empty() for sel in self.view.sel())

    def print_status(self, is_success):
        if is_success:
            self.success += 1
            log.debug('Formatting successful. 🎉😃🍰')
        else:
            self.failure += 1
            log.debug('Formatting failed. 💔😢💔')

        if common.config.get('show_statusbar'):
            self.view.window().set_status_bar_visible(True)
            self.view.set_status(common.STATUS_KEY, common.PACKAGE_NAME + ' [ok:' + str(self.success) + '|ko:' + str(self.failure) + ']')

    def open_console_on_failure(self):
        if common.config.get('open_console_on_failure'):
            self.view.window().run_command('show_panel', {'panel': 'console', 'toggle': True})

    def new_file_on_format(self, uid):
        suffix = common.query(common.config, False, 'formatters', uid, 'new_file_on_format')
        if suffix and isinstance(suffix, str):
            if common.want_layout():
                common.setup_layout(self.view)
                self.view.window().focus_group(0)

            file_path = self.view.file_name()
            if file_path and common.isfile(file_path):
                new_path = '{0}.{2}{1}'.format(*common.splitext(file_path) + (suffix,))
                self.view.run_command('transfer_content_view', {'path': new_path})
            else:
                self.view.run_command('transfer_content_view', {'path': None})
            sublime.set_timeout(self.undo_history, 250)

    def undo_history(self):
        c = self.cycles.count(True)
        attempts = 0
        while c > 0:
            self.view.run_command('undo')
            c -= 1
            attempts += 1
            if attempts > 500:
                log.warning('Seems like undo cycle is endless.')
                raise Exception()


class SubstituteCommand(sublime_plugin.TextCommand):
    def run(self, edit, result, region):
        log.debug('Replacing text ...')
        self.view.replace(edit, sublime.Region(region[0], region[1]), result)


class TransferContentViewCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        path = kwargs.get('path', None)
        src_view = self.view

        if path:
            # Reuse the same file
            dst_view = src_view.window().find_open_file(path)
            if dst_view:
                dst_view.run_command('select_all')
                dst_view.run_command('right_delete')
            else:
                if common.want_layout():
                    src_view.window().focus_group(1)
                dst_view = src_view.window().new_file(syntax=src_view.settings().get('syntax', None))
        else:
            src_id = src_view.id()
            dst_view = None
            ref_name = 'untitled-%s' % src_id
            for v in src_view.window().views():
                # Reuse the same view
                if v.name() == ref_name:
                    dst_view = v
                    break

            if dst_view:
                dst_view.run_command('select_all')
                dst_view.run_command('right_delete')
            else:
                if common.want_layout():
                    src_view.window().focus_group(1)
                dst_view = src_view.window().new_file(syntax=src_view.settings().get('syntax', None))
                dst_view.set_name(ref_name)

        dst_view.insert(edit, 0, src_view.substr(sublime.Region(0, src_view.size())))

        selections = []
        for selection in src_view.sel():
          selections.append(selection)

        dst_view.sel().clear()
        dst_view.sel().add_all(selections)

        dst_view.set_viewport_position(src_view.viewport_position(), False)
        src_view.window().focus_view(dst_view)

        SYNC_SCROLL['view_pairs'].append([src_view, dst_view])
        SYNC_SCROLL['view_pairs'] = common.get_unique(SYNC_SCROLL['view_pairs'])

        if path:
            dst_view.retarget(path)
            dst_view.set_scratch(True)
            self.save_dst_content(dst_view, path)
        else:
            dst_view.set_scratch(False)
            log.debug('The view is an unsaved buffer and must be manually saved as file.')
        self.show_status_on_new_file(dst_view)

    def save_dst_content(self, view, path):
        allcontent = view.substr(sublime.Region(0, view.size()))
        try:
            with open(path, 'w', encoding='utf-8') as file:
                file.write(allcontent)
        except OSError as e:
            log.error('Could not save file: %s\n%s', path, e)
            common.prompt_error('ERROR: Could not save file:\n' + path + '\nError mainly appears due to a lack of necessary permissions.')

    def show_status_on_new_file(self, view):
        if view.is_loading():
            sublime.set_timeout(lambda: self.show_status_on_new_file(view), 250)
        else:
            if common.config.get('show_statusbar'):
                view.window().set_status_bar_visible(True)
                view.set_status(common.STATUS_KEY, self.view.get_status(common.STATUS_KEY))


class OpenNextFileCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        index = kwargs.get('index', None)
        view = self.view.window().open_file(RECURSIVE_TARGET['filelist'][index])
        # open_file() is asynchronous. Use EventListener on_load() to catch
        # the returned view when the file is finished loading.
        if not view.is_loading():
            # True = file is ready and currently opened as view
            next_sequence(view, True)
        else:
            RECURSIVE_TARGET['view'] = view


class RecursiveFormat:
    def __init__(self, view, **kwargs):
        self.view = view
        self.kwargs = kwargs

    def run(self):
        log.debug('System environments:\n%s', json.dumps(common.update_environ(), indent=4))
        try:
            cwd = common.get_pathinfo(self.view.file_name())['cwd']
            uid = self.kwargs.get('uid', None)
            x = common.query(common.config, {}, 'formatters', uid, 'recursive_folder_format')
            exclude_dirs_regex = x.get('exclude_folders_regex', [])
            exclude_files_regex = x.get('exclude_files_regex', [])
            exclude_extensions = x.get('exclude_extensions', [])
            filelist = common.get_recursive_filelist(cwd, exclude_dirs_regex, exclude_files_regex, exclude_extensions)

            RECURSIVE_TARGET['kwargs'] = self.kwargs
            RECURSIVE_TARGET['cwd'] = cwd
            RECURSIVE_TARGET['filelist'] = filelist
            RECURSIVE_TARGET['filelist_length'] = len(filelist)
            RECURSIVE_TARGET['current_index'] = 1
            self.view.run_command('open_next_file', {'index': 0})
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))


class SequenceFormatThread(threading.Thread):
    def __init__(self, view, callback, **kwargs):
        self.view = view
        self.callback = callback
        self.kwargs = kwargs
        self.is_success = False
        threading.Thread.__init__(self)
        self.lock = threading.Lock()

    def run(self):
        try:
            with self.lock:
                region = sublime.Region(0, self.view.size())
                uid = self.kwargs.get('uid', None)
                syntax = common.get_assigned_syntax(self.view, uid, region, False)
                exclude_syntaxes = common.query(common.config, [], 'formatters', uid, 'recursive_folder_format', 'exclude_syntaxes')
                if not syntax or syntax in exclude_syntaxes:
                    if not syntax:
                        scope = common.query(common.config, [], 'formatters', uid, 'syntaxes')
                        log.warning('Syntax out of the scope. Plugin scope: %s, ID: %s, File syntax: %s, File: %s', scope, uid, syntax, self.view.file_name())
                    self.callback(False)
                else:
                    formatter = Formatter(self.view)
                    text = self.view.substr(region)
                    self.kwargs['view'] = self.view
                    self.kwargs['text'] = text
                    self.kwargs['region'] = region
                    self.kwargs['is_selected'] = False
                    self.is_success = formatter.run_formatter(**self.kwargs)
                    self.callback(self.is_success)
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))


def post_recursive_format(view, is_success):
    if is_success:
        new_cwd = common.join(RECURSIVE_TARGET['cwd'], common.RECURSIVE_SUCCESS_DIRECTORY)
        RECURSIVE_TARGET['success_count'] += 1
        log.debug('Formatting successful. 🎉😃🍰')
    else:
        new_cwd = common.join(RECURSIVE_TARGET['cwd'], common.RECURSIVE_FAILURE_DIRECTORY)
        RECURSIVE_TARGET['failure_count'] += 1
        log.debug('Formatting failed. 💔😢💔')

    file_path = RECURSIVE_TARGET['filelist'][RECURSIVE_TARGET['current_index'] - 1]
    new_file_path = file_path.replace(RECURSIVE_TARGET['cwd'], new_cwd, 1)

    uid = RECURSIVE_TARGET['kwargs'].get('uid', None)
    suffix = common.query(common.config, False, 'formatters', uid, 'new_file_on_format')
    if suffix and isinstance(suffix, str) and is_success:
        new_file_path = '{0}.{2}{1}'.format(*common.splitext(new_file_path) + (suffix,))

    cwd = common.get_pathinfo(new_file_path)['cwd']
    try:
        common.os.makedirs(cwd, exist_ok=True)
        region = sublime.Region(0, view.size())
        text = view.substr(region)
        with open(new_file_path, 'w', encoding='utf-8') as f:
            f.write(text)
    except OSError as e:
        if e.errno != common.os.errno.EEXIST:
            log.error('Could not create directory: %s', cwd)
            common.prompt_error('ERROR: Could not create directory: %s\nError mainly appears due to a lack of necessary permissions.', cwd)
        else:
            log.error('Could not save file: %s', new_file_path)
            common.prompt_error('ERROR: Could not save file: %s\nError mainly appears due to a lack of necessary permissions.', new_file_path)

        view.set_scratch(True)
        view.close()
        common.sys.exit(1)


def next_sequence(view, is_opened):
    def format_completed(is_success):
        post_recursive_format(view, is_success)

        # Loop files sequentially
        if RECURSIVE_TARGET['current_index'] < RECURSIVE_TARGET['filelist_length']:
            view.run_command('open_next_file', {'index': RECURSIVE_TARGET['current_index']})
            RECURSIVE_TARGET['current_index'] += 1

            if is_opened:
                if is_success:
                    view.run_command('undo')
            else:
                view.set_scratch(True)
                view.close()
        else:
            # Handle the last file
            if is_opened:
                if is_success:
                    view.run_command('undo')
            else:
                view.set_scratch(True)
                view.close()

            if common.config.get('show_statusbar'):
                current_view = sublime.active_window().active_view()
                current_view.window().set_status_bar_visible(True)
                current_view.set_status(common.STATUS_KEY, common.PACKAGE_NAME + ' [total:' + str(RECURSIVE_TARGET['filelist_length']) + '|ok:' + str(RECURSIVE_TARGET['success_count']) + '|ko:' + str(RECURSIVE_TARGET['failure_count']) + ']')

            if common.config.get('open_console_on_failure') and RECURSIVE_TARGET['failure_count'] > 0:
                current_view.window().run_command('show_panel', {'panel': 'console', 'toggle': True})

            sublime.message_dialog('Formatting completed!\n\nPlease check the following folder for the results:\n\n%s' % RECURSIVE_TARGET['cwd'])
            RECURSIVE_TARGET['view'] = None
            RECURSIVE_TARGET['kwargs'] = None
            RECURSIVE_TARGET['cwd'] = None
            RECURSIVE_TARGET['filelist'] = []
            RECURSIVE_TARGET['filelist_length'] = 0
            RECURSIVE_TARGET['current_index'] = 0
            RECURSIVE_TARGET['success_count'] = 0
            RECURSIVE_TARGET['failure_count'] = 0
            # Reset and end

    thread = SequenceFormatThread(view, callback=format_completed, **RECURSIVE_TARGET['kwargs'])
    thread.start()


class Listeners(sublime_plugin.EventListener):
    def __init__(self, *args, **kwargs):
        self.running = threading.Event()
        self.scroll_lock = threading.Lock()
        self.scroll_thread = None

    def on_load(self, view):
        if view == RECURSIVE_TARGET['view']:
            next_sequence(view, False)

    def on_activated(self, view):
        window = view.window()
        if common.query(common.config, False, 'layout', 'sync_scroll'):
            do_run = any(view in view_pair for view_pair in SYNC_SCROLL['view_pairs'])
            self.running.set() if do_run else self.running.clear() # control pause/resume scrolling

            if window and common.want_layout() and window.num_groups() == 2 and len(SYNC_SCROLL['view_pairs']) > 0:
                for view_pair in SYNC_SCROLL['view_pairs']:
                    if view in view_pair:
                        SYNC_SCROLL['view_src'], SYNC_SCROLL['view_dst'] = view_pair
                        SYNC_SCROLL['view_active'] = 'src' if view == SYNC_SCROLL['view_src'] else 'dst'
                        break
                self.start_scroll_thread()

    def start_scroll_thread(self):
        if not self.scroll_thread or not self.scroll_thread.is_alive():
            self.scroll_thread = threading.Thread(target=self.sync_scroll)
            self.scroll_thread.start()
            log.debug('Starting a thread for scroll synchronization.')

    @common.run_once
    def sync_scroll(self, *args, **kwargs):
        with self.scroll_lock:
            self.running.set() # start running
            while not SYNC_SCROLL['abort']:
                if not self.running.is_set():
                    log.debug('Scroll synchronization paused.')
                    self.running.wait() # pause/resume
                if SYNC_SCROLL['view_active'] and SYNC_SCROLL['view_dst'] and SYNC_SCROLL['view_src']:
                    if SYNC_SCROLL['view_active'] == 'src':
                        SYNC_SCROLL['view_dst'].set_viewport_position(SYNC_SCROLL['view_src'].viewport_position(), False)
                    else:
                        SYNC_SCROLL['view_src'].set_viewport_position(SYNC_SCROLL['view_dst'].viewport_position(), False)
                    # log.debug('Time: %s, view_src: %s, view_dst: %s', time.strftime('%H:%M:%S'), SYNC_SCROLL['view_src'], SYNC_SCROLL['view_dst'])
                time.sleep(0.25)

    def set_abort_sync_scroll(self):
        SYNC_SCROLL['abort'] = True
        if self.scroll_thread and self.scroll_thread.is_alive():
            self.running.clear()
            self.scroll_thread = None

    def on_pre_close(self, view):
        window = view.window()
        if window and common.want_layout() and window.num_groups() == 2 and len(SYNC_SCROLL['view_pairs']) > 0:
            if common.query(common.config, False, 'layout', 'sync_scroll'):
                for view_pair in SYNC_SCROLL['view_pairs']:
                    if view in view_pair:
                        # Remove pair for sync scroll
                        SYNC_SCROLL['view_pairs'].remove(view_pair)
                        break

            # Auto switching to single layout upon closing the latest view
            group, _ = window.get_view_index(view)
            if len(window.views_in_group(group)) == 1:
                sublime.set_timeout(lambda: window.set_layout(common.assign_layout('single')), 0)

    def on_pre_save(self, view):
        used = set()
        is_selected = any(not sel.empty() for sel in view.sel())
        formatters = common.config.get('formatters')
        for key, value in formatters.items():
            if common.query(value, False, 'recursive_folder_format', 'enable'):
                log.debug('The "format_on_save" option for %s is currently enabled and cannot be applied in "recursive_folder_format" mode.', key)
                continue

            if not is_selected:
                # Entire file
                region = sublime.Region(0, view.size())
            else:
                # Selections: find the first non-empty region or use the first region if all are empty
                region = next((region for region in view.sel() if not region.empty()), view.sel()[0])
            syntax = common.get_assigned_syntax(view, key, region, is_selected)
            if value.get('format_on_save', False) and syntax in value.get('syntaxes', []) and syntax not in used:
                log.debug('"format_on_save" enabled for ID: %s, using syntax: %s', key, syntax)
                SingleFormat(view, **{'uid': key}).run()
                used.add(syntax)

    def on_post_save(self, view):
        if common.config.get('debug') and common.config.get('dev'):
            # For development only
            self.set_abort_sync_scroll()
            common.reload_modules() # might need hit save twice for legacy Python < 3.4 (upstream imp.reload bug)
            self.sync_scroll.reset_run()
