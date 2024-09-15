import re

from ..core import Module

EXECUTABLES = ['R']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/yihui/formatR',
    'name': 'FormatR',
    'uid': 'formatr',
    'type': 'beautifier',
    'syntaxes': ['r'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/R',
    'args': None,
    'config_path': {
        'default': 'formatr_rc.cfg'
    }
}


class FormatrFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def remove_comments(self, text):
        # Pattern to match comments
        pattern = r'#.*?(?=\n|$)|(\'.*?\'|".*?")'
        # Remove single comments #
        text_without_comments = re.sub(pattern, lambda x: x.group(1) if x.group(1) else '', text)
        return text_without_comments

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        text = None
        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                text = file.read()
                text = self.remove_comments(text)
                text = ''.join(char for char in text if not char.isspace())

        ops = ', ' + text if text else ''
        cmd.extend(['--slave', '--no-restore', '--no-save', '-e', 'formatR::tidy_source("stdin"' + ops + ')'])

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
