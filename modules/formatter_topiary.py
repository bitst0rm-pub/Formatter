from ..core import Module

EXECUTABLES = ['topiary']
DOTFILES = ['languages.toml']
MODULE_CONFIG = {
    'source': 'https://github.com/tweag/topiary',
    'name': 'Topiary',
    'uid': 'topiary',
    'type': 'beautifier',
    'syntaxes': ['json', 'nickel', 'ocaml', 'ocamllex', 'toml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/topiary',
    'args': None,
    'config_path': {
        'default': 'topiary_rc.toml'
    }
}


class TopiaryFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'format']

        cmd.extend(['--language', self.get_assigned_syntax()])

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--configuration', path])

        cmd.extend(['--'])

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
