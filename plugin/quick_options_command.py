import json
from collections import OrderedDict

import sublime_plugin

from ..core import (CONFIG, ConfigHandler, InterfaceHandler, OptionHandler,
                    disable_logging, enable_logging, enable_status)


class QuickOptionsCommand(sublime_plugin.WindowCommand):
    OPTION_MAPPING = OrderedDict([
        ('debug', 'Enable Debug'),
        ('layout', 'Choose Layout'),
        ('new_file_on_format', 'Enable New File on Format'),
        ('ignore_dotfiles', 'Ignore Config Dotfiles'),
        ('format_on_save', 'Enable Format on Save'),
        ('format_on_paste', 'Enable Format on Paste'),
        ('dir_format', 'Enable Dir Format'),
        ('render_extended', 'Render Extended Graphics'),
        ('use_user_settings', 'Reset'),
        ('save_quick_options', 'Save')
    ])

    ON = '[x]'
    OFF = '[-]'
    NA = '[ ]'
    BACK_OPTION = '<< Back'

    def run(self):
        qo_config = CONFIG.get('quick_options', {})
        is_dir_format_enabled = qo_config.get('dir_format', False)
        self.options = [self.get_option_label(key, title, qo_config, is_dir_format_enabled)
                        for key, title in self.OPTION_MAPPING.items()]

        self.show_main_menu()

    def get_option_label(self, key, title, qo_config, is_dir_format_enabled):
        if self.is_option_unavailable(key, is_dir_format_enabled, qo_config):
            return '{} {} (Unavailable)'.format(self.NA, title)

        option_value = qo_config.get(key, False)
        option_status = self.ON if option_value else self.OFF

        if key == 'use_user_settings':
            option_status = self.OFF if qo_config else self.ON
        if key == 'save_quick_options':
            option_status = self.ON if qo_config and ConfigHandler.load_quick_options() else self.OFF

        if isinstance(option_value, (list, str)):
            return '{} {}: {}'.format(option_status, title, ', '.join(option_value) if isinstance(option_value, list) else option_value)
        return '{} {}'.format(option_status, title)

    def is_option_unavailable(self, key, is_dir_format_enabled, qo_config):
        if key in ['layout', 'format_on_save', 'format_on_paste', 'render_extended'] and is_dir_format_enabled:
            return True
        if key == 'dir_format' and self.is_dir_format_disabled(qo_config):
            return True
        return False

    @staticmethod
    def is_dir_format_disabled(qo_config):
        return any(qo_config.get(opt, False) for opt in ['layout', 'format_on_save', 'format_on_paste', 'render_extended'])

    def show_main_menu(self):
        self.window.show_quick_panel(self.options, self.on_done)

    def on_done(self, index):
        if index != -1:
            selected_option = list(self.OPTION_MAPPING.keys())[index]

            if self.NA in self.options[index]:  # skip unavailable option
                self.run()
                return

            action_method = self.get_action_method(selected_option)
            if action_method:
                action_method()
            else:
                self.toggle_option_status(index)

    def get_action_method(self, selected_option):
        return {
            'debug': self.show_debug_menu,
            'layout': self.show_layout_menu,
            'ignore_dotfiles': self.show_ignore_dotfiles_menu,
            'format_on_paste': lambda: self.show_format_menu('format_on_paste'),
            'format_on_save': lambda: self.show_format_menu('format_on_save'),
            'new_file_on_format': self.show_new_file_format_input,
            'render_extended': self.show_render_extended_menu,
        }.get(selected_option, None)

    def show_debug_menu(self):
        debugs = ['true', 'status', 'false', self.BACK_OPTION]
        self.window.show_quick_panel(debugs, lambda debug_index: self.on_debug_menu_done(debugs, debug_index))

    def on_debug_menu_done(self, debugs, debug_index):
        if debug_index != -1:
            debug_value = debugs[debug_index]
            if debug_value == self.BACK_OPTION:
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
        layouts = ['single', '2cols', '2rows', self.BACK_OPTION]
        self.window.show_quick_panel(layouts, lambda layout_index: self.on_layout_menu_done(layouts, layout_index))

    def on_layout_menu_done(self, layouts, layout_index):
        if layout_index != -1:
            layout_value = layouts[layout_index]
            if layout_value == self.BACK_OPTION:
                self.show_main_menu()
            else:
                current_layout_value = CONFIG.setdefault('quick_options', {}).get('layout', None)
                if layout_value == current_layout_value:
                    current_layout_value = None
                else:
                    current_layout_value = layout_value
                CONFIG.setdefault('quick_options', {})['layout'] = current_layout_value
                self.run()

    def show_ignore_dotfiles_menu(self):
        f = CONFIG.get('formatters', {})
        uid_list = [key for key in f.keys() if 'name' not in f.get(key, {}) and 'type' not in f.get(key, {})] + [self.BACK_OPTION]  # exclude generic methods
        self.window.show_quick_panel(uid_list, lambda uid_index: self.on_ignore_dotfiles_menu_done(uid_list, uid_index))

    def on_ignore_dotfiles_menu_done(self, uid_list, uid_index):
        if uid_index != -1:
            uid_value = uid_list[uid_index]
            if uid_value == self.BACK_OPTION:
                self.show_main_menu()
            else:
                current_ignore_dotfiles = CONFIG.setdefault('quick_options', {}).get('ignore_dotfiles', [])
                if uid_value in current_ignore_dotfiles:
                    current_ignore_dotfiles.remove(uid_value)
                else:
                    current_ignore_dotfiles.append(uid_value)
                CONFIG.setdefault('quick_options', {})['ignore_dotfiles'] = current_ignore_dotfiles
                self.run()

    def show_format_menu(self, option_key):
        uid_list = list(CONFIG.get('formatters', {}).keys()) + [self.BACK_OPTION]
        self.window.show_quick_panel(uid_list, lambda uid_index: self.on_format_menu_done(uid_list, uid_index, option_key))

    def on_format_menu_done(self, uid_list, uid_index, option_key):
        if uid_index != -1:
            uid_value = uid_list[uid_index]
            if uid_value == self.BACK_OPTION:
                self.show_main_menu()
            else:
                current_format_option = CONFIG.setdefault('quick_options', {}).get(option_key, [])
                if uid_value in current_format_option:
                    current_format_option.remove(uid_value)
                else:
                    current_format_option.append(uid_value)
                CONFIG.setdefault('quick_options', {})[option_key] = current_format_option
                self.run()

    def show_new_file_format_input(self):
        value = OptionHandler.query(CONFIG, '', 'quick_options', 'new_file_on_format')
        self.window.show_input_panel(
            'Enter a suffix (to disable: false or spaces):',
            value if (value and isinstance(value, str)) else '',
            self.on_new_file_format_input_done, None, None
        )

    def on_new_file_format_input_done(self, user_input):
        if user_input:
            value = False if (user_input.isspace() or user_input.strip().lower() == 'false') else user_input.strip().strip('.').replace(self.OFF, '').replace(self.ON, '')
            CONFIG.setdefault('quick_options', {})['new_file_on_format'] = value
        self.run()

    def show_render_extended_menu(self):
        uid_list = [uid for uid, formatter in CONFIG.get('formatters', {}).items() if 'render_extended' in formatter] + [self.BACK_OPTION]
        self.window.show_quick_panel(uid_list, lambda uid_index: self.on_render_extended_menu_done(uid_list, uid_index))

    def on_render_extended_menu_done(self, uid_list, uid_index):
        if uid_index != -1:
            uid_value = uid_list[uid_index]
            if uid_value == self.BACK_OPTION:
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

        if self.NA in selected_option:  # skip unavailable option
            return

        option_value, config_key = self.get_option_status_and_key(selected_option, index)

        if config_key == 'use_user_settings':
            CONFIG['quick_options'] = {}
            self.save_qo_config_file({})
        elif config_key == 'save_quick_options':
            self.save_quick_options_config()
        else:
            CONFIG.setdefault('quick_options', {})[config_key] = option_value
        self.run()

    def get_option_status_and_key(self, selected_option, index):
        option_value = self.OFF in selected_option
        selected_option = selected_option.replace(self.OFF, self.ON) if option_value else selected_option.replace(self.ON, self.OFF)
        config_key = list(self.OPTION_MAPPING.keys())[index]
        return option_value, config_key

    def save_quick_options_config(self):
        config_json = CONFIG.get('quick_options', {})
        self.save_qo_config_file(config_json)

    @staticmethod
    def save_qo_config_file(json_data):
        file = ConfigHandler.quick_options_config_file()
        try:
            with open(file, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, ensure_ascii=False, indent=4)
        except Exception as e:
            InterfaceHandler.popup_message('Error saving Quick Options file: %s' % e, 'ERROR')
