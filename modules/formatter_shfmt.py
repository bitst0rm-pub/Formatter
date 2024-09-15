import sublime

from ..core import Module

EXECUTABLES = ['shfmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/mvdan/sh',
    'name': 'Shfmt',
    'uid': 'shfmt',
    'type': 'beautifier',
    'syntaxes': ['bash'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/shfmt',
    'args': None,
    'config_path': {
        'default': 'shfmt_rc.json'
    }
}


class ShfmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(self.get_config(path))

        cmd.extend(['-'])

        return cmd

    def get_config(self, path):
        # shfmt does not have an option to
        # read external config file. We build one.
        with open(path, 'r', encoding='utf-8') as file:
            data = file.read()
        json = sublime.decode_value(data)

        result = []
        for key, value in json.items():
            if type(value) is int:
                result.extend(['--' + key, '%d' % value])
            elif type(value) is bool and value:
                result.extend(['--' + key])
            elif type(value) is str:
                result.extend(['--' + key, '%s' % value])

        return result

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
