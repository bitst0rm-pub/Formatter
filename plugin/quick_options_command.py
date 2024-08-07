import json
from collections import OrderedDict

import sublime_plugin

from ..core import (CONFIG, ConfigHandler, InterfaceHandler, OptionHandler,
                    disable_logging, enable_logging, enable_status)


class QuickOptionsCommand(sublime_plugin.WindowCommand):
    option_mapping = OrderedDict([
        ('debug', 'Enable Debug'),
        ('layout', 'Choose Layout'),
        ('ignore_config_path', 'Ignore Config Path'),
        ('format_on_save', 'Enable Format on Save'),
        ('format_on_paste', 'Enable Format on Paste'),
        ('new_file_on_format', 'Enable New File on Format'),
        ('dir_format', 'Enable Dir Format'),
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
            'format_on_paste': self.show_format_on_menu('format_on_paste', 'Format on Paste is not compatible with an enabled Dir Format.'),
            'format_on_save': self.show_format_on_menu('format_on_save', 'Format on Save is not compatible with an enabled Dir Format.'),
            'new_file_on_format': self.show_new_file_format_input,
            'render_extended': self.show_render_extended_menu,
        }
        return action_methods.get(selected_option, None)

    def show_format_on_menu(self, option_key, error_message):
        def handler():
            is_on = OptionHandler.query(CONFIG, False, 'quick_options', 'dir_format')
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
            if config_key == 'dir_format':
                if self.check_dir_format(option_value):
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

    def check_dir_format(self, option_value):
        a = {'format_on_save': 'Format on Save', 'format_on_paste': 'Format on Paste'}
        for k, v in a.items():
            is_on = OptionHandler.query(CONFIG, [], 'quick_options', k)
            if option_value and is_on:
                InterfaceHandler.popup_message('Dir Format is not compatible with an enabled %s.' % v, 'ERROR')
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
