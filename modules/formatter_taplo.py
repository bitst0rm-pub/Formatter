from ..core import Module

EXECUTABLES = ['taplo']
DOTFILES = ['.taplo.toml', 'taplo.toml']
MODULE_CONFIG = {
    'source': 'https://github.com/tamasfe/taplo',
    'name': 'Taplo',
    'uid': 'taplo',
    'type': 'beautifier',
    'syntaxes': ['toml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/taplo',
    'args': None,
    'config_path': {
        'default': 'taplo_rc.toml'
    }
}


class TaploFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'format']

        cmd.extend(self.get_args())

        cmd.extend(['--colors', 'never'])

        path = self.get_config_path()
        if path:
            cmd.extend(['--no-auto-config', '--config', path])

        file = self.get_pathinfo()['path']
        dummy = file or 'dummy.' + self.get_assigned_syntax()
        cmd.extend(['--stdin-filepath', dummy])

        cmd.extend(['-'])

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
