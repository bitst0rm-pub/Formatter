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

import time
import logging
import traceback
import threading
import sublime
import sublime_plugin
from threading import Event
from .core import common
from .core import configurator
from .core.wcounter import *
from .core.smanager import *
from .core.version import __version__
from .core.formatter import Formatter

log = logging.getLogger(__name__)

SYNC_SCROLL = {
    'view_pairs': [],
    'view_src': None,
    'view_dst': None,
    'view_active': None,
    'abort': False
}


def plugin_loaded():
    api = common.Base()

    api.remove_junk()
    ready = configurator.create_package_config_files()
    if ready:
        api.get_config()
        api.setup_shared_config_files()

        if api.is_quick_options_mode():
            is_enabled = api.query(common.config, False, 'quick_options', 'debug')
        else:
            is_enabled = common.config.get('debug')
        common.enable_logging() if is_enabled else common.disable_logging()
    log.info('%s version: %s (Python %s)', common.PACKAGE_NAME, __version__, '.'.join(map(str, common.sys.version_info[:3])))
    log.debug('Plugin initialization ' + ('succeeded.' if ready else 'failed.'))


class ShowVersionCommand(sublime_plugin.WindowCommand):
    def run(self):
        sublime.message_dialog(common.PACKAGE_NAME + '\nVersion: ' + __version__)


class OpenConfigFoldersCommand(sublime_plugin.WindowCommand, common.Base):
    def run(self):
        seen = set()

        config_dir = common.join(sublime.packages_path(), 'User', common.ASSETS_DIRECTORY, 'config')
        if common.isdir(config_dir):
            self.window.run_command('open_dir', {'dir': config_dir})
            seen.add(config_dir)

        for formatter in common.config.get('formatters', {}).values():
            for path in formatter.get('config_path', {}).values():
                if path and isinstance(path, str):
                    dirpath = self.get_pathinfo(path)['cwd']
                    if common.isdir(dirpath) and dirpath not in seen:
                        self.window.run_command('open_dir', {'dir': dirpath})
                        seen.add(dirpath)


class QuickOptionsCommand(sublime_plugin.WindowCommand, common.Base):
    option_mapping = {
        'debug': 'Enable Debugging',
        'layout': 'Choose Layout',
        'format_on_save': 'Enable Format on Save',
        'new_file_on_format': 'Enable New File on Format',
        'recursive_folder_format': 'Enable Recursive Folder Format',
        'use_user_settings': 'Reset (persistent User Settings use)',
        'save_quick_options': 'Save (persistent Quick Options use)'
    }

    def run(self):
        self.options = []
        config_values = common.config.get('quick_options', {})

        for key, title in self.option_mapping.items():
            option_value = config_values.get(key, False)
            option_status = '[x]' if option_value else '[-]'
            if key == 'use_user_settings':
                option_status = '[-]' if config_values else '[x]'
            if key == 'save_quick_options':
                option_status = '[x]' if config_values and self.load_quick_options() else '[-]'
            if key in ['layout', 'format_on_save', 'new_file_on_format'] and option_value:
                option_label = '{} {}: {}'.format(option_status, title, option_value if isinstance(option_value, str) else ', '.join(option_value))
            else:
                option_label = '{} {}'.format(option_status, title)
            self.options.append(option_label)

        self.show_main_menu()

    def show_main_menu(self):
        self.window.show_quick_panel(self.options, self.on_done)

    def show_layout_menu(self):
        layouts = ['single', '2cols', '2rows', '<< Back']
        self.window.show_quick_panel(layouts, lambda layout_index: self.on_layout_menu_done(layouts, layout_index))

    def on_layout_menu_done(self, layouts, layout_index):
        if layout_index != -1:
            layout_value = layouts[layout_index]
            if layout_value == '<< Back':
                self.show_main_menu()
            else:
                common.config.setdefault('quick_options', {})['layout'] = layout_value
                self.run()

    def show_format_on_save_menu(self):
        uid_list = list(common.config.get('formatters', {}).keys())
        uid_list.append('<< Back')
        self.window.show_quick_panel(uid_list, lambda uid_index: self.on_format_on_save_menu_done(uid_list, uid_index))

    def on_format_on_save_menu_done(self, uid_list, uid_index):
        if uid_index != -1:
            uid_value = uid_list[uid_index]
            if uid_value == '<< Back':
                self.show_main_menu()
            else:
                current_format_on_save = common.config.setdefault('quick_options', {}).get('format_on_save', [])
                if uid_value not in current_format_on_save:
                    current_format_on_save.append(uid_value)
                    common.config.setdefault('quick_options', {})['format_on_save'] = current_format_on_save
                self.run()

    def show_new_file_format_input(self):
        value = self.query(common.config, '', 'quick_options', 'new_file_on_format')
        self.window.show_input_panel(
            'Enter a suffix for "New File on Format" (to disable: false or spaces):',
            value if (value and isinstance(value, str)) else '',
            self.on_new_file_format_input_done, None, None
        )

    def on_new_file_format_input_done(self, user_input):
        if user_input:
            value = False if (user_input.isspace() or user_input.strip().lower() == 'false') else user_input.strip().strip('.').replace('[-]', '').replace('[x]', '')
            common.config.setdefault('quick_options', {})['new_file_on_format'] = value
        self.run()

    def save_quick_options_config(self):
        config_json = common.config.get('quick_options', {})
        self.save_qo_config_file(config_json)

    def on_done(self, index):
        if index != -1:
            selected_option = self.options[index]
            if 'Choose Layout' in selected_option:
                self.show_layout_menu()
            elif 'Enable Format on Save' in selected_option:
                is_rff_on = self.query(common.config, False, 'quick_options', 'recursive_folder_format')
                if is_rff_on:
                    self.prompt_error('ERROR: Format on Save is not compatible with an enabled Recursive Folder Format.')
                    self.run()
                else:
                    self.show_format_on_save_menu()
            elif 'Enable New File on Format' in selected_option:
                self.show_new_file_format_input()
            else:
                self.toggle_option_status(index)

    def toggle_option_status(self, index):
        selected_option = self.options[index]
        if '[-]' in selected_option:
            selected_option = selected_option.replace('[-]', '[x]')
            option_value = True
        else:
            selected_option = selected_option.replace('[x]', '[-]')
            option_value = False

        config_key = list(self.option_mapping.keys())[index]
        if config_key == 'use_user_settings':
            common.config['quick_options'] = {}
            self.save_qo_config_file({})
        elif config_key == 'save_quick_options':
            self.save_quick_options_config()
        else:
            if config_key == 'debug':
                if option_value:
                    common.enable_logging()
                else:
                    common.disable_logging()
            if config_key == 'recursive_folder_format':
                is_fos_on = self.query(common.config, [], 'quick_options', 'format_on_save')
                if option_value and is_fos_on:
                    self.prompt_error('ERROR: Recursive Folder Format is not compatible with an enabled Format on Save.')
                    self.run()
                    return
            common.config.setdefault('quick_options', {})[config_key] = option_value
        self.run()

    def save_qo_config_file(self, json_data):
        file = self.quick_options_config_file()
        with open(file, 'w', encoding='utf-8') as f:
            common.json.dump(json_data, f, ensure_ascii=False, indent=4)


class RunFormatCommand(sublime_plugin.TextCommand, common.Base):
    def run(self, edit, **kwargs):
        # Edit object is useless here since it gets automatically
        # destroyed before the code is reached in the new thread.

        is_recursive = self.is_recursive_formatting_enabled(kwargs.get('uid', None))
        if is_recursive:
            self.run_recursive_formatting(**kwargs)
        else:
            self.run_single_formatting(**kwargs)

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self, **kwargs):
        is_debug_enabled = self.is_debug_enabled()
        common.enable_logging() if is_debug_enabled else common.disable_logging()

        is_disabled = self.query(common.config, True, 'formatters', kwargs.get('uid', None), 'disable')
        return not is_disabled

    def is_recursive_formatting_enabled(self, uid):
        if self.is_quick_options_mode():
            return self.query(common.config, False, 'quick_options', 'recursive_folder_format')
        else:
            return self.query(common.config, False, 'formatters', uid, 'recursive_folder_format', 'enable')

    def run_recursive_formatting(self, **kwargs):
        if self.view.file_name():
            with threading.Lock():
                log.debug('Starting the main thread for recursive folder formatting ...')
                recursive_format = RecursiveFormat(self.view, **kwargs)
                recursive_format_thread = threading.Thread(target=recursive_format.run)
                recursive_format_thread.start()
        else:
            self.prompt_error('ERROR: Please save the file first. Recursive folder formatting requires an existing file on disk, which must be opened as the starting point.')

    def run_single_formatting(self, **kwargs):
        with threading.Lock():
            log.debug('Starting the main thread for single file formatting ...')
            single_format = SingleFormat(self.view, **kwargs)
            single_format_thread = threading.Thread(target=single_format.run)
            single_format_thread.start()

    def is_debug_enabled(self):
        if self.is_quick_options_mode():
            return self.query(common.config, False, 'quick_options', 'debug')
        else:
            return common.config.get('debug')


class SingleFormat(common.Base):
    def __init__(self, view, **kwargs):
        self.view = view
        self.kwargs = kwargs
        self.kwargs.update(view=self.view)
        self.success, self.failure = 0, 0
        self.cycles = []

    def run(self):
        self.print_sysinfo()
        try:
            for region in (self.view.sel() if self.has_selection() else [sublime.Region(0, self.view.size())]):
                self.kwargs.update(region=region)
                super().__init__(**self.kwargs)
                is_success = Formatter(**self.kwargs).run()
                self.cycles.append(is_success)
                self.print_status(is_success)

            if any(self.cycles):
                self.handle_successful_formatting()
            else:
                self.open_console_on_failure()
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))

    def has_selection(self):
        return any(not sel.empty() for sel in self.view.sel())

    def print_status(self, is_success):
        if is_success:
            self.success += 1
            log.debug('Formatting successful. 🎉😃🍰\n')
        else:
            self.failure += 1
            log.debug('Formatting failed. 💔😢💔\n')

        if common.config.get('show_statusbar'):
            self.set_status_bar_text()

    def set_status_bar_text(self):
        status_text = '{}({}) [ok:{}|ko:{}]'.format(common.PACKAGE_NAME, self.get_mode_description(short=True), self.success, self.failure)
        self.view.set_status(common.STATUS_KEY, status_text)

    def open_console_on_failure(self):
        if common.config.get('open_console_on_failure'):
            self.view.window().run_command('show_panel', {'panel': 'console', 'toggle': True})

    def handle_successful_formatting(self):
        uid = self.kwargs.get('uid', None)
        mode = 'qo' if self.is_quick_options_mode() else 'user'
        layout, suffix = self.get_layout_and_suffix(uid, mode)

        if suffix and isinstance(suffix, str):
            window = self.view.window()
            if mode == 'qo':
                window.set_layout(self.assign_layout(layout))
                window.focus_group(0)
            elif self.want_layout():
                self.setup_layout(self.view)
                window.focus_group(0)

            file_path = self.view.file_name()
            new_path = '{0}.{2}{1}'.format(*common.splitext(file_path) + (suffix,)) if file_path and common.isfile(file_path) else None
            self.view.run_command('transfer_content_view', {'path': new_path})
            sublime.set_timeout(self.undo_history, 250)

    def get_layout_and_suffix(self, uid, mode):
        if mode == 'qo':
            return (
                self.query(common.config, False, 'quick_options', 'layout'),
                self.query(common.config, False, 'quick_options', 'new_file_on_format')
            )
        else:
            return (
                self.query(common.config, False, 'layout', 'enable'),
                self.query(common.config, False, 'formatters', uid, 'new_file_on_format')
            )

    def undo_history(self):
        for _ in range(min(500, self.cycles.count(True))):
            self.view.run_command('undo')


class ReplaceContentViewCommand(sublime_plugin.TextCommand):
    def run(self, edit, result, region):
        log.debug('Replacing text ...')
        self.view.replace(edit, sublime.Region(region[0], region[1]), result)


class TransferContentViewCommand(sublime_plugin.TextCommand, common.Base):
    def run(self, edit, **kwargs):
        path = kwargs.get('path', None)
        src_view = self.view

        dst_view = self.create_or_reuse_view(path, src_view)
        self.copy_content_and_selections(edit, src_view, dst_view)
        self.sync_scroll_views(src_view, dst_view)

        if path:
            self.save_dst_content(dst_view, path)
        else:
            log.debug('The view is an unsaved buffer and must be manually saved as a file.')
        self.show_status_on_new_file(dst_view)

    def create_or_reuse_view(self, path, src_view):
        ref_name = 'untitled-%s' % src_view.id()
        window = src_view.window()

        if path:
            # Reuse the same file
            dst_view = window.find_open_file(path)
            if dst_view:
                dst_view.run_command('select_all')
                dst_view.run_command('right_delete')
            else:
                dst_view = self.create_new_file(window, src_view.settings().get('syntax', None))
                dst_view.retarget(path)
                dst_view.set_scratch(True)
        else:
            # Reuse the same view
            dst_view = next((v for v in window.views() if v.name() == ref_name), None)
            if dst_view:
                # Reuse the same view
                dst_view.run_command('select_all')
                dst_view.run_command('right_delete')
            else:
                dst_view = self.create_new_file(window, src_view.settings().get('syntax', None))
                dst_view.set_name(ref_name)
                dst_view.set_scratch(False)

        return dst_view

    def create_new_file(self, window, syntax=None):
        if self.want_layout():
            window.focus_group(1)
        dst_view = window.new_file(syntax=syntax)
        return dst_view

    def copy_content_and_selections(self, edit, src_view, dst_view):
        dst_view.insert(edit, 0, src_view.substr(sublime.Region(0, src_view.size())))

        selections = list(src_view.sel())
        dst_view.sel().clear()
        dst_view.sel().add_all(selections)

        dst_view.set_viewport_position(src_view.viewport_position(), False)
        src_view.window().focus_view(dst_view)

    def sync_scroll_views(self, src_view, dst_view):
        SYNC_SCROLL['view_pairs'].append([src_view, dst_view])
        SYNC_SCROLL['view_pairs'] = self.get_unique(SYNC_SCROLL['view_pairs'])

    def save_dst_content(self, view, path):
        allcontent = view.substr(sublime.Region(0, view.size()))
        try:
            with open(path, 'w', encoding='utf-8') as file:
                file.write(allcontent)
        except OSError as e:
            log.error('Could not save file: %s\n%s', path, e)
            self.prompt_error('ERROR: Could not save file:\n' + path + '\nError mainly appears due to a lack of necessary permissions.')

    def show_status_on_new_file(self, view):
        if view.is_loading():
            sublime.set_timeout(lambda: self.show_status_on_new_file(view), 250)
        else:
            if common.config.get('show_statusbar'):
                view.window().set_status_bar_visible(True)
                view.set_status(common.STATUS_KEY, self.view.get_status(common.STATUS_KEY))


class RecursiveFormat(common.Base):
    CONTEXT = {
        'entry_view': None,
        'new_view': None,
        'kwargs': None,
        'cwd': None,
        'filelist': [],
        'filelist_length': 0,
        'current_index': 0,
        'success_count': 0,
        'failure_count': 0,
        'mode_description': None
    }

    def __init__(self, view, **kwargs):
        self.view = view
        self.kwargs = kwargs

    def run(self):
        self.print_sysinfo()
        try:
            cwd = self.get_current_working_directory()
            filelist = self.get_recursive_files(cwd)

            self.prepare_context(cwd, filelist)
            self.process_files()

        except Exception as e:
            self.handle_error(e)

    def get_current_working_directory(self):
        return self.get_pathinfo(self.view.file_name())['cwd']

    def get_recursive_files(self, cwd):
        items = self.get_recursive_format_items()
        return self.get_recursive_filelist(
            cwd,
            items.get('exclude_folders_regex', []),
            items.get('exclude_files_regex', []),
            items.get('exclude_extensions', [])
        )

    def get_recursive_format_items(self):
        uid = self.kwargs.get('uid', None)
        return self.query(common.config, {}, 'formatters', uid, 'recursive_folder_format')

    def prepare_context(self, cwd, filelist):
        self.CONTEXT.update({
            'entry_view': self.view,
            'new_view': None,
            'kwargs': self.kwargs,
            'cwd': cwd,
            'filelist': filelist,
            'filelist_length': len(filelist),
            'current_index': 0,
            'success_count': 0,
            'failure_count': 0,
            'mode_description': self.get_mode_description(short=True)
        })

    def process_files(self):
        self.open_next_file()

    def open_next_file(self):
        # Loop files sequentially
        if self.CONTEXT['current_index'] < self.CONTEXT['filelist_length']:
            file_path = self.CONTEXT['filelist'][self.CONTEXT['current_index']]
            new_view = self.CONTEXT['entry_view'].window().open_file(file_path)
            self.CONTEXT['current_index'] += 1

            # open_file() is asynchronous. Use EventListener on_load() to catch
            # the returned view when the file is finished loading.
            if new_view.is_loading():
                self.CONTEXT['new_view'] = new_view
            else:
                self.next_thread(new_view, is_ready=True)

    def next_thread(self, new_view, is_ready=False):
        def format_completed(is_success):
            self.post_recursive_format(new_view, is_success)
            if is_ready and is_success:
                new_view.run_command('undo')
            elif self.CONTEXT['entry_view'] != new_view:
                new_view.set_scratch(True)
                new_view.close()

            if self.CONTEXT['current_index'] == self.CONTEXT['filelist_length']:
                # Handle the last file
                self.handle_formatting_completion()

            self.open_next_file()

        thread = SequenceFormatThread(new_view, callback=format_completed, **self.CONTEXT['kwargs'])
        thread.start()

    def post_recursive_format(self, new_view, is_success):
        new_cwd = self.get_post_format_cwd(is_success)
        self.show_result(is_success)
        self.save_formatted_file(new_view, new_cwd, is_success)

    def get_post_format_cwd(self, is_success):
        base_directory = self.CONTEXT['cwd']
        sub_directory = common.RECURSIVE_SUCCESS_DIRECTORY if is_success else common.RECURSIVE_FAILURE_DIRECTORY
        return common.join(base_directory, sub_directory)

    def show_result(self, is_success):
        if is_success:
            self.CONTEXT['success_count'] += 1
            log.debug('Formatting successful. 🎉😃🍰\n')
        else:
            self.CONTEXT['failure_count'] += 1
            log.debug('Formatting failed. 💔😢💔\n')

    def save_formatted_file(self, new_view, new_cwd, is_success):
        file_path = new_view.file_name()
        new_file_path = self.generate_new_file_path(file_path, new_cwd, is_success)
        cwd = self.get_pathinfo(new_file_path)['cwd']

        try:
            common.os.makedirs(cwd, exist_ok=True)
            text = new_view.substr(sublime.Region(0, new_view.size()))
            with open(new_file_path, 'w', encoding='utf-8') as f:
                f.write(text)
        except OSError as e:
            self.handle_error(e, cwd, new_file_path)

    def generate_new_file_path(self, file_path, new_cwd, is_success):
        new_file_path = file_path.replace(self.CONTEXT['cwd'], new_cwd, 1)
        if is_success:
            suffix = self.get_new_file_suffix()
            if suffix and isinstance(suffix, str):
                new_file_path = '{0}.{2}{1}'.format(*common.splitext(new_file_path) + (suffix,))
        return new_file_path

    def get_new_file_suffix(self):
        if self.is_quick_options_mode():
            return self.query(common.config, False, 'quick_options', 'new_file_on_format')
        else:
            uid = self.CONTEXT['kwargs'].get('uid', None)
            return self.query(common.config, False, 'formatters', uid, 'new_file_on_format')

    def handle_formatting_completion(self):
        self.update_status_bar()
        self.open_console_on_failure()
        self.show_completion_message()
        self.reset_context()

    def update_status_bar(self):
        if common.config.get('show_statusbar'):
            current_view = self.get_current_view()
            current_view.window().set_status_bar_visible(True)
            status_text = self.generate_status_text()
            current_view.set_status(common.STATUS_KEY, status_text)

    def get_current_view(self):
        return sublime.active_window().active_view()

    def generate_status_text(self):
        return '{}({}) [total:{}|ok:{}|ko:{}]'.format(
            common.PACKAGE_NAME, self.CONTEXT['mode_description'],
            self.CONTEXT['filelist_length'],
            self.CONTEXT['success_count'],
            self.CONTEXT['failure_count']
        )

    def open_console_on_failure(self):
        if common.config.get('open_console_on_failure') and self.CONTEXT['failure_count'] > 0:
            current_view = get_current_view()
            current_view.window().run_command('show_panel', {'panel': 'console', 'toggle': True})

    def show_completion_message(self):
        success_rate = '{:.2f}'.format((self.CONTEXT['success_count'] / self.CONTEXT['filelist_length']) * 100)
        sublime.message_dialog('Formatting COMPLETED!\n\nSuccess Rate: %s%%\n\nPlease check the results in:\n%s' % (success_rate, self.CONTEXT['cwd']))

    def reset_context(self):
        for key, value in self.CONTEXT.items():
            if isinstance(value, list):
                self.CONTEXT[key] = []
            elif isinstance(value, int):
                self.CONTEXT[key] = 0
            else:
                self.CONTEXT[key] = None
        # Reset and end

    def handle_error(self, error, cwd=None, file_path=None):
        log.error('Error occurred: %s\n%s', error, ''.join(traceback.format_tb(error.__traceback__)))
        if cwd and (error.errno != common.os.errno.EEXIST):
            log.error('Could not create directory: %s', cwd)
            self.prompt_error('ERROR: Could not create directory: %s\nError mainly appears due to a lack of necessary permissions.', cwd)
        if file_path:
            log.error('Could not save file: %s', file_path)
            self.prompt_error('ERROR: Could not save file: %s\nError mainly appears due to a lack of necessary permissions.', file_path)


class SequenceFormatThread(threading.Thread, common.Base):
    def __init__(self, view, callback, **kwargs):
        self.view = view
        self.kwargs = kwargs
        self.callback = callback
        self.is_success = False
        threading.Thread.__init__(self)
        self.lock = threading.Lock()

    def run(self):
        try:
            with self.lock:
                region = sublime.Region(0, self.view.size())
                uid = self.kwargs.get('uid', None)
                syntax = self.get_assigned_syntax(self.view, uid, region)
                exclude_syntaxes = self.query(common.config, [], 'formatters', uid, 'recursive_folder_format', 'exclude_syntaxes')
                if not syntax or syntax in exclude_syntaxes:
                    if not syntax:
                        scope = self.query(common.config, [], 'formatters', uid, 'syntaxes')
                        log.warning('Syntax out of the scope. Plugin scope: %s, ID: %s, File syntax: %s, File: %s', scope, uid, syntax, self.view.file_name())
                    self.callback(False)
                else:
                    self.kwargs.update({
                        'view': self.view,
                        'region': region
                    })
                    self.is_success = Formatter(**self.kwargs).run()
                    self.callback(self.is_success)
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))


class FormatterListener(sublime_plugin.EventListener, common.Base):
    def __init__(self, *args, **kwargs):
        self.running = threading.Event()
        self.scroll_lock = threading.Lock()
        self.scroll_thread = None

    def on_load(self, view):
        if view == RecursiveFormat.CONTEXT['new_view']:
            RecursiveFormat(view).next_thread(view, is_ready=False)

    def on_activated(self, view):
        window = view.window()
        if self.query(common.config, False, 'layout', 'sync_scroll'):
            do_run = any(view in view_pair for view_pair in SYNC_SCROLL['view_pairs'])
            self.running.set() if do_run else self.running.clear()  # control pause/resume scrolling

            if window and self.want_layout() and window.num_groups() == 2 and len(SYNC_SCROLL['view_pairs']) > 0:
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
            self.running.set()  # start running
            while not SYNC_SCROLL['abort']:
                if not self.running.is_set():
                    log.debug('Scroll synchronization paused.')
                    self.running.wait()  # pause/resume
                if SYNC_SCROLL['view_active'] and SYNC_SCROLL['view_dst'] and SYNC_SCROLL['view_src']:
                    if SYNC_SCROLL['view_active'] == 'src':
                        SYNC_SCROLL['view_dst'].set_viewport_position(SYNC_SCROLL['view_src'].viewport_position(), False)
                    else:
                        SYNC_SCROLL['view_src'].set_viewport_position(SYNC_SCROLL['view_dst'].viewport_position(), False)
                time.sleep(0.25)

    def set_abort_sync_scroll(self):
        SYNC_SCROLL['abort'] = True
        if self.scroll_thread and self.scroll_thread.is_alive():
            self.running.clear()
            self.scroll_thread = None

    def on_pre_close(self, view):
        window = view.window()
        if window and self.want_layout() and window.num_groups() == 2 and len(SYNC_SCROLL['view_pairs']) > 0:
            if self.query(common.config, False, 'layout', 'sync_scroll'):
                for view_pair in SYNC_SCROLL['view_pairs']:
                    if view in view_pair:
                        # Remove pair for sync scroll
                        SYNC_SCROLL['view_pairs'].remove(view_pair)
                        break

            # Auto switching to single layout upon closing the latest view
            group, _ = window.get_view_index(view)
            if len(window.views_in_group(group)) == 1:
                sublime.set_timeout(lambda: window.set_layout(self.assign_layout('single')), 0)

    def on_pre_save(self, view):
        used_syntaxes = set()
        is_selected = any(not sel.empty() for sel in view.sel())
        is_qo_mode = self.is_quick_options_mode()
        is_rff_on = self.query(common.config, False, 'quick_options', 'recursive_folder_format')
        formatters = common.config.get('formatters')

        def should_skip_formatter(uid, value):
            if not isinstance(value, dict):
                return True
            if (is_qo_mode and uid not in self.query(common.config, [], 'quick_options', 'format_on_save')) or (not is_qo_mode and not value.get('format_on_save', False)):
                return True
            if (is_qo_mode and is_rff_on) or (not is_qo_mode and self.query(value, False, 'recursive_folder_format', 'enable')):
                mode = 'Quick Options' if is_qo_mode else 'User Settings'
                log.info('%s mode: %s has the "format_on_save" option enabled, which is incompatible with "recursive_folder_format" mode.', mode, uid)
                return True
            return False

        for uid, value in formatters.items():
            if should_skip_formatter(uid, value):
                continue

            if is_selected:
                # Selections: find the first non-empty region or use the first region if all are empty
                region = next((region for region in view.sel() if not region.empty()), view.sel()[0])
            else:
                # Entire file
                region = sublime.Region(0, view.size())
            syntax = self.get_assigned_syntax(view=view, uid=uid, region=region)
            if syntax in value.get('syntaxes', []) and syntax not in used_syntaxes:
                log.debug('"format_on_save" enabled for ID: %s, using syntax: %s', uid, syntax)
                SingleFormat(view, uid=uid).run()
                used_syntaxes.add(syntax)

    def on_post_save(self, view):
        if common.config.get('debug') and common.config.get('dev'):
            # For development only
            self.set_abort_sync_scroll()
            self.reload_modules()  # might need hit save twice for python < 3.4 (imp.reload upstream bug)
            self.sync_scroll.reset_run()
