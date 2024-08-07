from ..core.common import Module

INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['black']
DOTFILES = ['pyproject.toml', '.black']
MODULE_CONFIG = {
    'source': 'https://github.com/psf/black',
    'name': 'Black',
    'uid': 'black',
    'type': 'beautifier',
    'syntaxes': ['python'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/black',
    'args': None,
    'config_path': {
        'default': 'black_rc.toml'
    },
    'comment': 'requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}. requires python on PATH if omit interpreter_path'
}


class BlackFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

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
