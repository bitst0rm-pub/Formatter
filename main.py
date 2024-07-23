import os
import sys
import time
import json
import base64
import zipfile
import tempfile
import traceback
import threading
from datetime import datetime
from collections import OrderedDict

import sublime
import sublime_plugin

from . import (
    log,
    enable_logging,
    enable_status,
    disable_logging,
    ConfigHandler,
    CONFIG,
    CleanupHandler,
    DotFileHandler,
    HashHandler,
    InterfaceHandler,
    LayoutHandler,
    MarkdownHandler,
    OptionHandler,
    PathHandler,
    PhantomHandler,
    PrintHandler,
    SyntaxHandler,
    TransformHandler,
    ViewHandler,
    create_package_config_files,
    SESSION_FILE,
    SessionManagerListener,
    WordsCounterListener,
    Formatter,
    __version__,
    import_custom_modules,
    reload_modules
)

from .core.constants import (
    PACKAGE_NAME,
    ASSETS_DIRECTORY,
    RECURSIVE_SUCCESS_DIRECTORY,
    RECURSIVE_FAILURE_DIRECTORY,
    STATUS_KEY,
    GFX_OUT_NAME
)


def entry():
    import_custom_modules()
    # CleanupHandler.remove_junk()
    ready = create_package_config_files()
    if ready:
        ConfigHandler.load_sublime_preferences()
        ConfigHandler.setup_config()
        ConfigHandler.setup_shared_config_files()
        ConfigHandler.set_debug_mode()

    log.info('%s version: %s (Python %s)', PACKAGE_NAME, __version__, '.'.join(map(str, sys.version_info[:3])))
    log.debug('Plugin initialization ' + ('succeeded.' if ready else 'failed.'))

def plugin_loaded():
    ConfigHandler.setup_config()

    def call_entry():
        sublime.set_timeout_async(lambda: entry(), 100)

    try:
        from package_control import events
        if events.install(PACKAGE_NAME) or events.post_upgrade(PACKAGE_NAME):
            call_entry()
        else:
            call_entry()
    except:
        call_entry()


class VersionInfoCommand(sublime_plugin.WindowCommand):
    def run(self):
        sublime.message_dialog('🧜‍♀️ ' + PACKAGE_NAME + '\nVersion: ' + __version__)


class KeyBindingsCommand(sublime_plugin.WindowCommand):
    def run(self):
        sublime.run_command('new_window')
        window = sublime.active_window()
        window.set_layout(LayoutHandler.assign_layout('2cols'))
        window.focus_group(0)
        window.run_command('open_file', {'file': '${packages}/' + PACKAGE_NAME + '/Example.sublime-keymap'})
        window.focus_group(1)
        window.run_command('open_file', {'file': '${packages}/User/Default (${platform}).sublime-keymap'})


class ModulesInfoCommand(sublime_plugin.WindowCommand):
    def __init__(self, *args, **kwargs):
        self.FILE_PATH = self.get_file_path()

    def get_file_path(self):
        return os.path.join(sublime.packages_path(), PACKAGE_NAME, 'modules', '_summary.txt')

    def is_enabled(self):
        return os.path.exists(self.FILE_PATH)

    def is_visible(self):
        return self.is_enabled()

    def run(self):
        if os.path.exists(self.FILE_PATH):
            view = sublime.active_window().open_file(self.FILE_PATH)
            view.settings().set('word_wrap', False)
        else:
            log.error('File does not exist: %s', self.FILE_PATH)


class OpenChangelogCommand(sublime_plugin.WindowCommand):
    def __init__(self, *args, **kwargs):
        self.FILE_PATH = self.get_file_path()

    def get_file_path(self):
        return os.path.join(sublime.packages_path(), PACKAGE_NAME, 'CHANGELOG.md')

    def convert_markdown_file_to_html(self, filepath):
        try:
            with open(filepath, 'r') as f:
                markdown = f.read()

            return MarkdownHandler.markdown_to_html(markdown)
        except Exception as e:
            log.error('Error reading file: %s\n%s', filepath, e)
        return None

    def is_enabled(self):
        return os.path.exists(self.FILE_PATH)

    def is_visible(self):
        return self.is_enabled()

    def run(self):
        if os.path.exists(self.FILE_PATH):
            html = self.convert_markdown_file_to_html(self.FILE_PATH)
            if html:
                view = sublime.active_window().new_file()
                PhantomHandler.style_view(view)
                view.erase_phantoms('changelog')
                view.add_phantom('changelog', sublime.Region(0), html, sublime.LAYOUT_INLINE)
                view.set_name('Changelog')
                view.set_read_only(True)
                view.set_scratch(True)
        else:
            log.error('File does not exist: %s', self.FILE_PATH)


class BrowserConfigsCommand(sublime_plugin.WindowCommand):
    def run(self):
        seen = set()

        config_dir = os.path.join(sublime.packages_path(), 'User', ASSETS_DIRECTORY, 'config')
        if os.path.isdir(config_dir):
            self.window.run_command('open_dir', {'dir': config_dir})
            seen.add(config_dir)

        for formatter in CONFIG.get('formatters', {}).values():
            for path in formatter.get('config_path', {}).values():
                if path and isinstance(path, str):
                    dir_path = os.path.dirname(path)
                    if os.path.isdir(dir_path) and dir_path not in seen:
                        self.window.run_command('open_dir', {'dir': dir_path})
                        seen.add(dir_path)


class BackupManagerCommand(sublime_plugin.WindowCommand):
    backup_temp_dir = None
    USER_PATH = os.path.join(sublime.packages_path(), 'User')

    def get_config_paths_to_zip(self):
        default_keymaps = [
            'Default.sublime-keymap',
            'Default (OSX).sublime-keymap',
            'Default (Linux).sublime-keymap',
            'Default (Windows).sublime-keymap'
        ]

        file_paths_to_zip = [
            ConfigHandler.quick_options_config_file(),
            os.path.join(self.USER_PATH, 'Formatter.sublime-settings'),
            SESSION_FILE
        ] + [os.path.join(self.USER_PATH, keymap) for keymap in default_keymaps]

        config_paths = [
            path for formatter in CONFIG.get('formatters', {}).values()
            for path in formatter.get('config_path', {}).values()
            if path and isinstance(path, str)
        ]

        file_paths_to_zip.extend(config_paths)
        return [path for path in file_paths_to_zip if path and os.path.isfile(path)]

    def cleanup_temp_dir(self):
        if self.backup_temp_dir:
            self.backup_temp_dir.cleanup()
            self.backup_temp_dir = None

    def backup_config(self):
        self.cleanup_temp_dir()

        file_paths_to_zip = self.get_config_paths_to_zip()

        self.backup_temp_dir = tempfile.TemporaryDirectory()
        zip_file_name = 'Formatter_config_{}.zip'.format(datetime.now().strftime('%Y_%m_%d'))
        zip_file_path = os.path.join(self.backup_temp_dir.name, zip_file_name)

        try:
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in file_paths_to_zip:
                    zipf.write(file_path, file_path)
        except Exception as e:
            InterfaceHandler.popup_message('Error during backup: %s' % e)
            self.cleanup_temp_dir()
            return

        self.window.run_command('open_dir', {'dir': self.backup_temp_dir.name})
        InterfaceHandler.popup_message('Your backup file successfully created.', 'INFO', dialog=True)

    def restore_config(self):
        def on_done(file_path):
            file_path = file_path.strip()

            if file_path and file_path.lower().endswith('.zip') and os.path.isfile(file_path):
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall('/')
                except Exception as e:
                    InterfaceHandler.popup_message('Error during restore: %s' % e)
                    return
                InterfaceHandler.popup_message('Restore completed successfully.', 'INFO', dialog=True)
            else:
                InterfaceHandler.popup_message('File not found: %s' % file_path, 'ERROR')

        self.window.show_input_panel('Enter the path to the backup zip file:', '', on_done, None, None)

    def run(self, **kwargs):
        task_type = kwargs.get('type', None)

        if task_type == 'backup':
            self.backup_config()
        elif task_type == 'restore':
            self.restore_config()


class QuickOptionsCommand(sublime_plugin.WindowCommand):
    option_mapping = OrderedDict([
        ('debug', 'Enable Debug'),
        ('layout', 'Choose Layout'),
        ('ignore_config_path', 'Ignore Config Path'),
        ('format_on_save', 'Enable Format on Save'),
        ('format_on_paste', 'Enable Format on Paste'),
        ('new_file_on_format', 'Enable New File on Format'),
        ('recursive_folder_format', 'Enable Recursive Folder Format'),
        ('render_extended', 'Render Extended Graphics'),
        ('use_user_settings', 'Reset'),
        ('save_quick_options', 'Save')
    ])

    def run(self):
        self.options = []
        config_values = CONFIG.get('quick_options', {})
        for key, title in self.option_mapping.items():
            option_label = self.get_option_label(key, title, config_values)
            self.options.append(option_label)
        self.show_main_menu()

    def get_option_label(self, key, title, config_values):
        option_value = config_values.get(key, False)
        option_status = '[x]' if option_value else '[-]'
        if key == 'use_user_settings':
            option_status = '[-]' if config_values else '[x]'
        if key == 'save_quick_options':
            option_status = '[x]' if config_values and ConfigHandler.load_quick_options() else '[-]'
        if key in ['debug', 'layout', 'ignore_config_path', 'format_on_paste', 'format_on_save', 'new_file_on_format', 'render_extended'] and option_value:
            option_label = '{} {}: {}'.format(option_status, title, option_value if isinstance(option_value, str) else ', '.join(option_value))
        else:
            option_label = '{} {}'.format(option_status, title)
        return option_label

    def show_main_menu(self):
        self.window.show_quick_panel(self.options, self.on_done)

    def on_done(self, index):
        if index != -1:
            selected_option = list(self.option_mapping.keys())[index]
            action_method = self.get_action_method(selected_option)
            if action_method:
                action_method()
            else:
                self.toggle_option_status(index)

    def get_action_method(self, selected_option):
        action_methods = {
            'debug': self.show_debug_menu,
            'layout': self.show_layout_menu,
            'ignore_config_path': self.show_ignore_config_path_menu,
            'format_on_paste': self.show_format_on_menu('format_on_paste', 'Format on Paste is not compatible with an enabled Recursive Folder Format.'),
            'format_on_save': self.show_format_on_menu('format_on_save', 'Format on Save is not compatible with an enabled Recursive Folder Format.'),
            'new_file_on_format': self.show_new_file_format_input,
            'render_extended': self.show_render_extended_menu,
        }
        return action_methods.get(selected_option, None)

    def show_format_on_menu(self, option_key, error_message):
        def handler():
            is_on = OptionHandler.query(CONFIG, False, 'quick_options', 'recursive_folder_format')
            if is_on:
                InterfaceHandler.popup_message(error_message, 'ERROR')
                self.run()
            else:
                self.show_format_menu(option_key)

        return handler

    def show_format_menu(self, option_key):
        uid_list = list(CONFIG.get('formatters', {}).keys())
        uid_list.append('<< Back')
        self.window.show_quick_panel(uid_list, lambda uid_index: self.on_format_menu_done(uid_list, uid_index, option_key))

    def on_format_menu_done(self, uid_list, uid_index, option_key):
        if uid_index != -1:
            uid_value = uid_list[uid_index]
            if uid_value == '<< Back':
                self.show_main_menu()
            else:
                current_format_option = CONFIG.setdefault('quick_options', {}).get(option_key, [])
                if uid_value in current_format_option:
                    current_format_option.remove(uid_value)
                else:
                    current_format_option.append(uid_value)
                CONFIG.setdefault('quick_options', {})[option_key] = current_format_option
                self.run()

    def show_debug_menu(self):
        debugs = ['true', 'status', 'false', '<< Back']
        self.window.show_quick_panel(debugs, lambda debug_index: self.on_debug_menu_done(debugs, debug_index))

    def on_debug_menu_done(self, debugs, debug_index):
        if debug_index != -1:
            debug_value = debugs[debug_index]
            if debug_value == '<< Back':
                self.show_main_menu()
            else:
                current_debug_value = CONFIG.setdefault('quick_options', {}).get('debug', False)
                if debug_value == current_debug_value:
                    current_debug_value = False
                else:
                    if debug_value == 'status':
                        enable_status()
                    elif debug_value == 'true':
                        enable_logging()
                    else:
                        disable_logging()
                    current_debug_value = debug_value
                CONFIG.setdefault('quick_options', {})['debug'] = current_debug_value
                self.run()

    def show_layout_menu(self):
        layouts = ['single', '2cols', '2rows', '<< Back']
        self.window.show_quick_panel(layouts, lambda layout_index: self.on_layout_menu_done(layouts, layout_index))

    def on_layout_menu_done(self, layouts, layout_index):
        if layout_index != -1:
            layout_value = layouts[layout_index]
            if layout_value == '<< Back':
                self.show_main_menu()
            else:
                current_layout_value = CONFIG.setdefault('quick_options', {}).get('layout', None)
                if layout_value == current_layout_value:
                    current_layout_value = None
                else:
                    current_layout_value = layout_value
                CONFIG.setdefault('quick_options', {})['layout'] = current_layout_value
                self.run()

    def show_ignore_config_path_menu(self):
        f = CONFIG.get('formatters', {})
        uid_list = [key for key in f.keys() if 'name' not in f.get(key, {}) and 'type' not in f.get(key, {})]  # exclude generic methods
        uid_list.append('<< Back')
        self.window.show_quick_panel(uid_list, lambda uid_index: self.on_ignore_config_path_menu_done(uid_list, uid_index))

    def on_ignore_config_path_menu_done(self, uid_list, uid_index):
        if uid_index != -1:
            uid_value = uid_list[uid_index]
            if uid_value == '<< Back':
                self.show_main_menu()
            else:
                current_ignore_config_path = CONFIG.setdefault('quick_options', {}).get('ignore_config_path', [])
                if uid_value in current_ignore_config_path:
                    current_ignore_config_path.remove(uid_value)
                else:
                    current_ignore_config_path.append(uid_value)
                CONFIG.setdefault('quick_options', {})['ignore_config_path'] = current_ignore_config_path
                self.run()

    def show_new_file_format_input(self):
        value = OptionHandler.query(CONFIG, '', 'quick_options', 'new_file_on_format')
        self.window.show_input_panel(
            'Enter a suffix for "New File on Format" (to disable: false or spaces):',
            value if (value and isinstance(value, str)) else '',
            self.on_new_file_format_input_done, None, None
        )

    def on_new_file_format_input_done(self, user_input):
        if user_input:
            value = False if (user_input.isspace() or user_input.strip().lower() == 'false') else user_input.strip().strip('.').replace('[-]', '').replace('[x]', '')
            CONFIG.setdefault('quick_options', {})['new_file_on_format'] = value
        self.run()

    def show_render_extended_menu(self):
        uid_list = [uid for uid, formatter in CONFIG.get('formatters', {}).items() if 'render_extended' in formatter]
        uid_list.append('<< Back')
        self.window.show_quick_panel(uid_list, lambda uid_index: self.on_render_extended_menu_done(uid_list, uid_index))

    def on_render_extended_menu_done(self, uid_list, uid_index):
        if uid_index != -1:
            uid_value = uid_list[uid_index]
            if uid_value == '<< Back':
                self.show_main_menu()
            else:
                current_render_extended = CONFIG.setdefault('quick_options', {}).get('render_extended', [])
                if uid_value in current_render_extended:
                    current_render_extended.remove(uid_value)
                else:
                    current_render_extended.append(uid_value)
                CONFIG.setdefault('quick_options', {})['render_extended'] = current_render_extended
                self.run()

    def toggle_option_status(self, index):
        selected_option = self.options[index]
        option_value, config_key = self.get_option_status_and_key(selected_option, index)

        if config_key == 'use_user_settings':
            CONFIG['quick_options'] = {}
            self.save_qo_config_file({})
        elif config_key == 'save_quick_options':
            self.save_quick_options_config()
        else:
            if config_key == 'recursive_folder_format':
                if self.check_recursive_folder_format(option_value):
                    return
            CONFIG.setdefault('quick_options', {})[config_key] = option_value
        self.run()

    def get_option_status_and_key(self, selected_option, index):
        if '[-]' in selected_option:
            selected_option = selected_option.replace('[-]', '[x]')
            option_value = True
        else:
            selected_option = selected_option.replace('[x]', '[-]')
            option_value = False
        config_key = list(self.option_mapping.keys())[index]
        return option_value, config_key

    def check_recursive_folder_format(self, option_value):
        a = {'format_on_save': 'Format on Save', 'format_on_paste': 'Format on Paste'}
        for k, v in a.items():
            is_on = OptionHandler.query(CONFIG, [], 'quick_options', k)
            if option_value and is_on:
                InterfaceHandler.popup_message('Recursive Folder Format is not compatible with an enabled %s.' % v, 'ERROR')
                self.run()
                return True
        return False

    def save_quick_options_config(self):
        config_json = CONFIG.get('quick_options', {})
        self.save_qo_config_file(config_json)

    def save_qo_config_file(self, json_data):
        file = ConfigHandler.quick_options_config_file()
        with open(file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=4)


class RunFormatCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        CleanupHandler.clear_console()

        is_recursive = self.is_recursive_formatting_enabled(kwargs.get('uid', None))
        if is_recursive:
            if kwargs.get('type', None) == 'graphic':
                log.info('Recursive formatting is not supported for plugins of type: graphic')
            else:
                self.run_recursive_formatting(**kwargs)
        else:
            self.run_single_formatting(**kwargs)

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self, **kwargs):
        ConfigHandler.set_debug_mode()
        return self.is_plugin_enabled(kwargs.get('uid', None))

    def is_plugin_enabled(self, uid):
        if not ViewHandler(view=self.view).is_view_formattable():
            return False

        formatter = OptionHandler.query(CONFIG, {}, 'formatters', uid)
        if 'disable' in formatter and not formatter.get('disable', True):
            return True
        elif 'enable' in formatter and formatter.get('enable', False):
            return True
        else:
            return False

    def is_recursive_formatting_enabled(self, uid):
        if ConfigHandler.is_quick_options_mode():
            return OptionHandler.query(CONFIG, False, 'quick_options', 'recursive_folder_format')
        else:
            return OptionHandler.query(CONFIG, False, 'formatters', uid, 'recursive_folder_format', 'enable')

    def run_recursive_formatting(self, **kwargs):
        if self.view.file_name():
            with threading.Lock():
                log.debug('Starting recursive formatting ...')
                recursive_format = RecursiveFormat(self.view, **kwargs)
                recursive_format_thread = threading.Thread(target=recursive_format.run)
                recursive_format_thread.start()
        else:
            InterfaceHandler.popup_message('Please save the file first. Recursive folder formatting requires an existing file on disk, which must be opened as the starting point.', 'ERROR')

    def run_single_formatting(self, **kwargs):
        with threading.Lock():
            log.debug('Starting file formatting ...')
            single_format = SingleFormat(self.view, **kwargs)
            single_format_thread = threading.Thread(target=single_format.run)
            single_format_thread.start()


class AutoFormatFileCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        CleanupHandler.clear_console()

        auto_format_args = DotFileHandler(view=self.view).get_auto_format_args()
        if auto_format_args:
            with threading.Lock():
                log.debug('Starting auto formatting ...')
                single_format = SingleFormat(self.view, **auto_format_args)
                single_format_thread = threading.Thread(target=single_format.run)
                single_format_thread.start()

    def is_enabled(self):
        return not bool(self.view.settings().get('is_widget', False))

    def is_visible(self):
        ConfigHandler.set_debug_mode()
        return bool(DotFileHandler(view=self.view).get_auto_format_config()) or bool(OptionHandler.query(CONFIG, {}, 'auto_format'))


class SingleFormat:
    def __init__(self, view, **kwargs):
        self.view = view
        self.kwargs = kwargs
        self.kwargs.update(view=self.view)
        self.temp_dir = None
        self.success, self.failure = 0, 0
        self.cycles = []

    def run(self):
        self.create_graphic_temp_dir()
        PrintHandler.print_sysinfo(pretty=True)

        try:
            for region in (self.view.sel() if self.has_selection() else [sublime.Region(0, self.view.size())]):
                self.kwargs.update(region=region)
                is_success = Formatter(**self.kwargs).run()
                self.cycles.append(is_success)
                self.print_status(is_success)

            if any(self.cycles):
                self.close_console_on_success()
                self.handle_successful_formatting()
            else:
                self.open_console_on_failure()
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))

    def create_graphic_temp_dir(self):
        if self.kwargs.get('type', None) == 'graphic':
            self.temp_dir = tempfile.TemporaryDirectory()
            self.kwargs.update(temp_dir=self.temp_dir.name)

    def has_selection(self):
        return any(not sel.empty() for sel in self.view.sel())

    def print_status(self, is_success):
        if is_success:
            self.success += 1
            log.status('🎉 Formatting successful. 🥳✨\n')
        else:
            self.failure += 1
            log.status('❌ Formatting failed. 😢💔\n')

        if CONFIG.get('show_statusbar'):
            self.set_status_bar_text()

    def set_status_bar_text(self):
        status_text = '{}({}) [ok:{}|ko:{}]'.format(PACKAGE_NAME[0], ConfigHandler.get_mode_description(short=True), self.success, self.failure)
        self.view.set_status(STATUS_KEY, status_text)

    def open_console_on_failure(self):
        if CONFIG.get('open_console_on_failure'):
            self.view.window().run_command('show_panel', {'panel': 'console'})

    def close_console_on_success(self):
        if CONFIG.get('close_console_on_success'):
            self.view.window().run_command('hide_panel', {'panel': 'console'})

    def handle_successful_formatting(self):
        if self.kwargs.get('type', None) == 'graphic':
            self.handle_graphic_formatting()
        else:
            self.handle_text_formatting()

    def handle_graphic_formatting(self):
        window = self.view.window()
        window.focus_group(0)
        layout = OptionHandler.query(CONFIG, '2cols', 'layout', 'enable')
        layout = layout if layout in ['2cols', '2rows'] else '2cols'
        window.set_layout(LayoutHandler.assign_layout(layout))
        self.create_or_reuse_view()

    def handle_text_formatting(self):
        uid = self.kwargs.get('uid', None)
        mode = 'qo' if ConfigHandler.is_quick_options_mode() else 'user'
        layout, suffix = self.get_layout_and_suffix(uid, mode)

        if suffix and isinstance(suffix, str):
            window = self.view.window()
            window.focus_group(0)

            if mode == 'qo':
                window.set_layout(LayoutHandler.assign_layout(layout))
            elif LayoutHandler.want_layout():
                LayoutHandler.setup_layout(self.view)

            file_path = self.view.file_name()
            new_path = '{0}.{2}{1}'.format(*os.path.splitext(file_path) + (suffix,)) if file_path and os.path.isfile(file_path) else None
            self.view.run_command('transfer_view_content', {'path': new_path})
            sublime.set_timeout(self.undo_history, 250)

    def create_or_reuse_view(self):
        path = self.view.file_name()
        src_window = self.view.window()
        gfx_vref = self.view.id()

        dst_view = next((v for window in sublime.windows() for v in window.views() if v.settings().get('gfx_vref', None) == gfx_vref), None)

        if dst_view:
            dst_view.window().focus_view(dst_view)
            dst_view.set_read_only(False)
            self.set_graphic_phantom(dst_view)
        else:
            src_window.focus_group(1)
            dst_view = src_window.new_file(flags=sublime.TRANSIENT, syntax=self.view.settings().get('syntax', None))
            dst_view.run_command('append', {'characters': ''})  # magic to assign a tab
            dst_view.settings().set('gfx_vref', gfx_vref)
            self.set_graphic_phantom(dst_view)
            dst_view.set_scratch(True)
            if path:
                dst_view.retarget(path)

        dst_view.set_read_only(True)

    def get_extended_data(self):
        uid = self.kwargs.get('uid', None)

        if ConfigHandler.is_quick_options_mode():
            if uid not in OptionHandler.query(CONFIG, [], 'quick_options', 'render_extended'):
                return {}

        try:
            extended_data = {}
            image_extensions = ['svg'] if not ConfigHandler.is_generic_method(uid) else list(OptionHandler.query(CONFIG, {}, 'formatters', uid, 'args_extended').keys())

            for ext in image_extensions:
                ext = ext.strip().lower()
                image_path = os.path.join(self.temp_dir.name, GFX_OUT_NAME + '.' + ext)
                if os.path.exists(image_path):
                    with open(image_path, 'rb') as image_file:
                        extended_data[ext] = base64.b64encode(image_file.read()).decode('utf-8')

            return extended_data
        except Exception as e:
            return {}

    def set_graphic_phantom(self, dst_view):
        try:
            image_path = os.path.join(self.temp_dir.name, GFX_OUT_NAME + '.png')
            with open(image_path, 'rb') as image_file:
                data = image_file.read()
                image_width, image_height = PhantomHandler.get_image_size(data)
                image_data = base64.b64encode(data).decode('utf-8')

            fit_image_width, fit_image_height = PhantomHandler.image_scale_fit(dst_view, image_width, image_height)
            extended_data = self.get_extended_data()

            html = PhantomHandler.set_html_phantom(dst_view, image_data, image_width, image_height, fit_image_width, fit_image_height, extended_data)
            data = {'dst_view_id': dst_view.id(), 'image_data': image_data, 'image_width': image_width, 'image_height': image_height, 'extended_data': extended_data}

            dst_view.erase_phantoms('graphic')
            dst_view.add_phantom('graphic', sublime.Region(0), html, sublime.LAYOUT_INLINE, on_navigate=lambda href: self.on_navigate(href, data, dst_view))
        except Exception as e:
            log.error('Error creating phantom: %s', e)
        finally:
            self.temp_dir.cleanup()

    def on_navigate(self, href, data, dst_view):
        if href == 'zoom_image':
            dst_view.window().run_command('zoom', data)
        else:
            stem = PathHandler(view=dst_view).get_pathinfo()['stem'] or GFX_OUT_NAME
            save_path = os.path.join(PhantomHandler.get_downloads_folder(), stem + '.' + href.split('/')[1].split(';')[0])

            try:
                mime_type, base64_data = href.split(',', 1)
                decoded_data = base64.b64decode(base64_data)
                with open(save_path, 'wb') as f:
                    f.write(decoded_data)

                InterfaceHandler.popup_message('Image successfully saved to:\n%s' % save_path, 'INFO', dialog=True)
            except Exception as e:
                InterfaceHandler.popup_message('Could not save file:\n%s\nError: %s' % (save_path, e), 'ERROR')

    def get_layout_and_suffix(self, uid, mode):
        if mode == 'qo':
            return (
                OptionHandler.query(CONFIG, False, 'quick_options', 'layout'),
                OptionHandler.query(CONFIG, False, 'quick_options', 'new_file_on_format')
            )
        else:
            return (
                OptionHandler.query(CONFIG, False, 'layout', 'enable'),
                OptionHandler.query(CONFIG, False, 'formatters', uid, 'new_file_on_format')
            )

    def undo_history(self):
        for _ in range(min(500, self.cycles.count(True))):
            self.view.run_command('undo')


class ReplaceViewContentCommand(sublime_plugin.TextCommand):
    def run(self, edit, result, region):
        self.view.replace(edit, sublime.Region(region[0], region[1]), result)


class ZoomCommand(sublime_plugin.WindowCommand):
    ZOOM_LEVELS = ['Fit', '10%', '25%', '50%', '75%', '100%', '125%', '150%', '175%', '200%', '225%', '250%', '275%', '300%', '325%', '350%', '375%', '400%']

    def run(self, **kwargs):
        self.window.show_quick_panel(self.ZOOM_LEVELS, lambda index: self.on_done(index, **kwargs))

    def on_done(self, index, **kwargs):
        if index != -1:
            zoom_level = self.ZOOM_LEVELS[index]
            if zoom_level == 'Fit' or zoom_level == '100%' or zoom_level == '-100%':
                zoom_factor = 1.0
            else:
                zoom_factor = float(zoom_level[:-1]) / 100

            dst_view_id = kwargs.get('dst_view_id')
            image_data = kwargs.get('image_data')
            image_width = kwargs.get('image_width')
            image_height = kwargs.get('image_height')
            extended_data = kwargs.get('extended_data')

            dst_view = self.find_view_by_id(dst_view_id) or self.window.active_view()
            if zoom_level == 'Fit':
                fit_image_width, fit_image_height = PhantomHandler.image_scale_fit(dst_view, image_width, image_height)
            else:
                fit_image_width = image_width * zoom_factor
                fit_image_height = image_height * zoom_factor

            try:
                html = PhantomHandler.set_html_phantom(dst_view, image_data, image_width, image_height, fit_image_width, fit_image_height, extended_data)
                data = {'dst_view_id': dst_view.id(), 'image_data': image_data, 'image_width': image_width, 'image_height': image_height, 'extended_data': extended_data}

                dst_view.erase_phantoms('graphic')
                dst_view.add_phantom('graphic', sublime.Region(0), html, sublime.LAYOUT_INLINE, on_navigate=lambda href: self.on_navigate(href, data, dst_view))
            except Exception as e:
                log.error('Error creating phantom: %s', e)

    def on_navigate(self, href, data, dst_view):
        if href == 'zoom_image':
            dst_view.window().run_command('zoom', data)
        else:
            stem = os.path.splitext(os.path.basename(dst_view.file_name() or GFX_OUT_NAME))[0]
            save_path = os.path.join(PhantomHandler.get_downloads_folder(), stem + '.' + href.split('/')[1].split(';')[0])

            try:
                mime_type, base64_data = href.split(',', 1)
                decoded_data = base64.b64decode(base64_data)
                with open(save_path, 'wb') as f:
                    f.write(decoded_data)

                InterfaceHandler.popup_message('Image successfully saved to:\n%s' % save_path, 'INFO', dialog=True)
            except Exception as e:
                InterfaceHandler.popup_message('Could not save file:\n%s\nError: %s' % (save_path, e), 'ERROR')

    def find_view_by_id(self, dst_view_id):
        for window in sublime.windows():
            for view in window.views():
                if view.id() == dst_view_id:
                    return view
        return None


class TransferViewContentCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        path = kwargs.get('path', None)
        src_view = self.view

        dst_view = self.create_or_reuse_view(path, src_view)
        self.copy_content_and_selections(edit, src_view, dst_view)

        if path:
            self.save_dst_content(dst_view, path)
        else:
            log.debug('The view is an unsaved buffer and must be manually saved as a file.')
        self.show_status_on_new_file(dst_view)

    def create_or_reuse_view(self, path, src_view):
        src_window = src_view.window()
        txt_vref = src_view.id()

        dst_view = next((v for window in sublime.windows() for v in window.views() if v.settings().get('txt_vref', None) == txt_vref), None)

        if dst_view:
            dst_view.window().focus_view(dst_view)
            dst_view.run_command('select_all')
            dst_view.run_command('right_delete')
        else:
            src_window.focus_group(1)
            dst_view = src_window.new_file(flags=sublime.TRANSIENT, syntax=src_view.settings().get('syntax', None))
            dst_view.run_command('append', {'characters': ''})  # magic to assign a tab
            dst_view.settings().set('txt_vref', txt_vref)
            if path:
                dst_view.retarget(path)
                dst_view.set_scratch(True)
            else:
                dst_view.set_scratch(False)

        return dst_view

    def copy_content_and_selections(self, edit, src_view, dst_view):
        # edit is broken in ST4166+:
        # dst_view.insert(edit, 0, src_view.substr(sublime.Region(0, src_view.size())))
        dst_view.run_command('append', {'characters': src_view.substr(sublime.Region(0, src_view.size()))})

        selections = list(src_view.sel())
        dst_view.sel().clear()
        dst_view.sel().add_all(selections)

        dst_view.set_viewport_position(src_view.viewport_position(), False)
        dst_view.window().focus_view(dst_view)

    def save_dst_content(self, view, path):
        allcontent = view.substr(sublime.Region(0, view.size()))
        try:
            with open(path, 'w', encoding='utf-8') as file:
                file.write(allcontent)
        except OSError as e:
            log.error('Could not save file: %s\n%s', path, e)
            InterfaceHandler.popup_message('Could not save file:\n' + path + '\nError mainly appears due to a lack of necessary permissions.', 'ERROR')

    def show_status_on_new_file(self, view):
        if view.is_loading():
            sublime.set_timeout(lambda: self.show_status_on_new_file(view), 250)
        else:
            if CONFIG.get('show_statusbar'):
                view.window().set_status_bar_visible(True)
                view.set_status(STATUS_KEY, self.view.get_status(STATUS_KEY))


class RecursiveFormat():
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
        try:
            cwd = self.get_current_working_directory()
            filelist = self.get_recursive_files(cwd)

            self.prepare_context(cwd, filelist)
            self.process_files()

        except Exception as e:
            self.handle_error(e)

    def get_current_working_directory(self):
        return PathHandler(view=self.view).get_pathinfo(self.view.file_name())['cwd']

    def get_recursive_files(self, cwd):
        items = self.get_recursive_format_items()
        return TransformHandler.get_recursive_filelist(
            cwd,
            items.get('exclude_folders_regex', []),
            items.get('exclude_files_regex', []),
            items.get('exclude_extensions', [])
        )

    def get_recursive_format_items(self):
        uid = self.kwargs.get('uid', None)
        return OptionHandler.query(CONFIG, {}, 'formatters', uid, 'recursive_folder_format')

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
            'mode_description': ConfigHandler.get_mode_description(short=True)
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
        sub_directory = RECURSIVE_SUCCESS_DIRECTORY if is_success else RECURSIVE_FAILURE_DIRECTORY
        return os.path.join(base_directory, sub_directory)

    def show_result(self, is_success):
        if is_success:
            self.CONTEXT['success_count'] += 1
            log.status('🎉 Formatting successful. 🥳✨\n')
        else:
            self.CONTEXT['failure_count'] += 1
            log.status('❌ Formatting failed. 😢💔\n')

    def save_formatted_file(self, new_view, new_cwd, is_success):
        file_path = new_view.file_name()
        new_file_path = self.generate_new_file_path(file_path, new_cwd, is_success)
        cwd = PathHandler(view=new_view).get_pathinfo(new_file_path)['cwd']

        try:
            os.makedirs(cwd, exist_ok=True)
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
                new_file_path = '{0}.{2}{1}'.format(*os.path.splitext(new_file_path) + (suffix,))
        return new_file_path

    def get_new_file_suffix(self):
        if ConfigHandler.is_quick_options_mode():
            return OptionHandler.query(CONFIG, False, 'quick_options', 'new_file_on_format')
        else:
            uid = self.CONTEXT['kwargs'].get('uid', None)
            return OptionHandler.query(CONFIG, False, 'formatters', uid, 'new_file_on_format')

    def handle_formatting_completion(self):
        self.update_status_bar()
        self.open_console_on_failure()
        self.show_completion_message()
        self.reset_context()

    def update_status_bar(self):
        if CONFIG.get('show_statusbar'):
            current_view = self.get_current_view()
            current_view.window().set_status_bar_visible(True)
            status_text = self.generate_status_text()
            current_view.set_status(STATUS_KEY, status_text)

    def get_current_view(self):
        return sublime.active_window().active_view()

    def generate_status_text(self):
        return '{}({}) [total:{}|ok:{}|ko:{}]'.format(
            PACKAGE_NAME[0], self.CONTEXT['mode_description'],
            self.CONTEXT['filelist_length'],
            self.CONTEXT['success_count'],
            self.CONTEXT['failure_count']
        )

    def open_console_on_failure(self):
        if CONFIG.get('open_console_on_failure') and self.CONTEXT['failure_count'] > 0:
            current_view = self.get_current_view()
            current_view.window().run_command('show_panel', {'panel': 'console', 'toggle': True})

    def show_completion_message(self):
        ok = self.CONTEXT['success_count']
        ko = self.CONTEXT['failure_count']
        total = self.CONTEXT['filelist_length']
        InterfaceHandler.popup_message('Formatting COMPLETED!\n\nOK: %s\nKO: %s\nTotal: %s\n\nPlease check the results in:\n%s' % (ok, ko, total, self.CONTEXT['cwd']), 'INFO', dialog=True)

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
        if cwd and (error.errno != os.errno.EEXIST):
            log.error('Could not create directory: %s', cwd)
            InterfaceHandler.popup_message('Could not create directory: %s\nError mainly appears due to a lack of necessary permissions.' % cwd, 'ERROR')
        if file_path:
            log.error('Could not save file: %s', file_path)
            InterfaceHandler.popup_message('Could not save file: %s\nError mainly appears due to a lack of necessary permissions.' % file_path, 'ERROR')


class SequenceFormatThread(threading.Thread):
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
                uid, syntax = SyntaxHandler(view=self.view, uid=uid, region=region, auto_format_config=None).get_assigned_syntax(self.view, uid, region)
                exclude_syntaxes = OptionHandler.query(CONFIG, [], 'formatters', uid, 'recursive_folder_format', 'exclude_syntaxes')
                if not syntax or syntax in exclude_syntaxes:
                    if not syntax:
                        scope = OptionHandler.query(CONFIG, [], 'formatters', uid, 'syntaxes')
                        log.warning('Syntax out of the scope. Plugin scope: %s, UID: %s, File syntax: %s, File: %s', scope, uid, syntax, self.view.file_name())
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


class FormatterListener(sublime_plugin.EventListener):
    def __init__(self, *args, **kwargs):
        self.sync_scroll_lock = threading.Lock()
        self.sync_scroll_running = False
        self.sync_scroll_thread = None

    def on_load(self, view):
        if view == RecursiveFormat.CONTEXT['new_view']:
            RecursiveFormat(view).next_thread(view, is_ready=False)

    def on_activated(self, view):
        ConfigHandler.update_project_config_overwrites_config()

        if OptionHandler.query(CONFIG, False, 'layout', 'sync_scroll') and LayoutHandler.want_layout():
            self.stop_sync_scroll()

            src_view = self._find_src_view_by_dst_view(view)
            if src_view:
                self.start_sync_scroll('src', view, src_view)
            else:
                dst_view = self._find_dst_view_by_src_view(view)
                if dst_view:
                    self.start_sync_scroll('dst', view, dst_view)

    def _find_src_view_by_dst_view(self, dst_view):
        src_view_id = dst_view.settings().get('txt_vref')
        if src_view_id:
            for window in sublime.windows():
                for view in window.views():
                    if view.id() == src_view_id:
                        return view
        return None

    def _find_dst_view_by_src_view(self, src_view):
        src_view_id = src_view.id()
        for window in sublime.windows():
            for view in window.views():
                if view.settings().get('txt_vref') == src_view_id:
                    return view
        return None

    def start_sync_scroll(self, target_type, active_view, target_view):
        with self.sync_scroll_lock:
            if not self.sync_scroll_running:
                self.sync_scroll_running = True
                self.sync_scroll_thread = threading.Thread(target=self.sync_scroll, args=(target_type, active_view, target_view))
                self.sync_scroll_thread.start()

    def stop_sync_scroll(self):
        with self.sync_scroll_lock:
            self.sync_scroll_running = False
            if self.sync_scroll_thread and self.sync_scroll_thread.is_alive():
                self.sync_scroll_thread.join(timeout=0.4)
                if self.sync_scroll_thread.is_alive():
                    self.sync_scroll_thread = None

    def sync_scroll(self, target_type, active_view, target_view):
        while self.sync_scroll_running:
            #log.debug('Sync scroll target: %s', target_type)
            target_view.set_viewport_position(active_view.viewport_position(), False)
            time.sleep(0.25)

    def on_pre_close(self, view):
        def _set_single_layout(window, view):
            # Auto-switch to single layout upon closing the latest view
            group, _ = window.get_view_index(view)
            if len(window.views_in_group(group)) == 1:
                sublime.set_timeout(lambda: window.set_layout(LayoutHandler.assign_layout('single')), 0)

        window = view.window()
        if window and LayoutHandler.want_layout() and window.num_groups() == 2:
            _set_single_layout(window, view)

    def on_post_text_command(self, view, command_name, args):
        if command_name in ['paste', 'paste_and_indent']:
            self.apply_formatting(view, 'format_on_paste')
            return None

    def on_pre_save(self, view):
        self.apply_formatting(view, 'format_on_save')

    def apply_formatting(self, view, operation):
        path = view.file_name()
        if path:
            if os.path.splitext(path)[1] in ['.sublime-settings']:
                return  # exclude

            auto_format_user_config = DotFileHandler(view=view).get_auto_format_user_config(active_file_path=path)
            auto_format_user_operation = OptionHandler.query(auto_format_user_config, False, operation)
            auto_format_config_operation = OptionHandler.query(CONFIG, False, 'auto_format', 'config', operation)
            if (auto_format_user_config and auto_format_user_operation) or auto_format_config_operation:
                get_auto_format_args = DotFileHandler(view=view).get_auto_format_args(active_file_path=path)
                if get_auto_format_args:
                    CleanupHandler.clear_console()

                    SingleFormat(view, **get_auto_format_args).run()
                    return

        self._on_paste_or_save(view, opkey=operation)

    def _on_paste_or_save(self, view, opkey=None):
        if not opkey:
            return None

        unique = CONFIG.get('format_on_priority', None) or CONFIG.get('format_on_unique', None)
        if unique and isinstance(unique, dict) and unique.get('enable', False):
            self._on_paste_or_save__unique(view, unique, opkey)
        else:
            self._on_paste_or_save__regular(view, opkey)

    def _on_paste_or_save__unique(self, view, unique, opkey):
        def are_unique_values(unique):
            flat_values = [value for key, values_list in unique.items() if key != 'enable' for value in values_list]
            return (len(flat_values) == len(set(flat_values)))

        formatters = CONFIG.get('formatters')

        if are_unique_values(unique):
            for uid, value in unique.items():
                if uid == 'enable':
                    continue

                v = OptionHandler.query(formatters, None, uid)
                if self._on_paste_or_save__should_skip_formatter(uid, v, opkey):
                    continue

                syntax = self._on_paste_or_save__get_syntax(view, uid)
                if syntax in value:
                    CleanupHandler.clear_console()

                    SingleFormat(view=view, uid=uid, type=value.get('type', None)).run()
                    break
        else:
            InterfaceHandler.popup_message('There are duplicate syntaxes in your "format_on_priority" option. Please sort them out.', 'ERROR')

    def _on_paste_or_save__regular(self, view, opkey):
        seen = set()
        formatters = CONFIG.get('formatters')

        for uid, value in formatters.items():
            if self._on_paste_or_save__should_skip_formatter(uid, value, opkey):
                continue

            syntax = self._on_paste_or_save__get_syntax(view, uid)
            if syntax in value.get('syntaxes', []) and syntax not in seen:
                CleanupHandler.clear_console()

                log.debug('"%s" (UID: %s | Syntax: %s)', opkey, uid, syntax)
                SingleFormat(view=view, uid=uid, type=value.get('type', None)).run()
                seen.add(syntax)

    def _on_paste_or_save__should_skip_formatter(self, uid, value, opkey):
        is_qo_mode = ConfigHandler.is_quick_options_mode()
        is_rff_on = OptionHandler.query(CONFIG, False, 'quick_options', 'recursive_folder_format')

        if not isinstance(value, dict) or ('disable' in value and value.get('disable', True)) or ('enable' in value and not value.get('enable', False)):
            return True

        if (is_qo_mode and uid not in OptionHandler.query(CONFIG, [], 'quick_options', opkey)) or (not is_qo_mode and not value.get(opkey, False)):
            return True

        if (is_qo_mode and is_rff_on) or (not is_qo_mode and OptionHandler.query(value, False, 'recursive_folder_format', 'enable')):
            mode = 'Quick Options' if is_qo_mode else 'User Settings'
            log.info('%s mode: %s has the "%s" option enabled, which is incompatible with "recursive_folder_format" mode.', mode, uid, opkey)
            return True

        return False

    def _on_paste_or_save__get_syntax(self, view, uid):
        is_selected = any(not sel.empty() for sel in view.sel())

        if is_selected:
            # Selections: find the first non-empty region or use the first region if all are empty
            region = next((region for region in view.sel() if not region.empty()), view.sel()[0])
        else:
            # Entire file
            region = sublime.Region(0, view.size())

        uid, syntax = SyntaxHandler(view=view, uid=uid, region=region, auto_format_config=None).get_assigned_syntax(view=view, uid=uid, region=region)
        return syntax

    def on_post_save(self, view):
        if CONFIG.get('debug') and CONFIG.get('dev'):
            # For development only
            self.stop_sync_scroll()
            reload_modules(print_tree=False)
