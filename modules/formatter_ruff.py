from ..core import Module

EXECUTABLES = ['ruff']
DOTFILES = ['.ruff.toml', 'ruff.toml', 'pyproject.toml']
MODULE_CONFIG = {
    'source': 'https://github.com/astral-sh/ruff',
    'name': 'Ruff',
    'uid': 'ruff',
    'type': 'beautifier',
    'syntaxes': ['python'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/ruff',
    'args': None,
    'config_path': {
        'default': 'ruff_rc.toml'
    }
}


class RuffFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'format']

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

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
