from ..core import Module

INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['isort']
DOTFILES = ['.isort.cfg', 'pyproject.toml', 'setup.cfg', 'tox.ini', '.editorconfig']
MODULE_CONFIG = {
    'source': 'https://github.com/PyCQA/isort',
    'name': 'Isort',
    'uid': 'isort',
    'type': 'beautifier',
    'syntaxes': ['python'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/isort',
    'args': None,
    'config_path': {
        'default': 'isort_rc.toml'
    },
    'comment': 'Requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}. Omit "interpreter_path" if python already on PATH.'
}


class IsortFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--settings-path', path])

        cmd.extend(['--stdout', '-'])

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
