import os
import tempfile
import zipfile
from datetime import datetime

import sublime
import sublime_plugin

from ..core import CONFIG, SESSION_FILE, ConfigHandler, InterfaceHandler


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
