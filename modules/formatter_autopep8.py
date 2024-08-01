from ..core.common import Module

INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['autopep8']
DOTFILES = ['.pycodestyle', 'setup.cfg', 'tox.ini', '.pep8', '.flake8']
MODULE_CONFIG = {
    'source': 'https://github.com/hhatto/autopep8',
    'name': 'Autopep8',
    'uid': 'autopep8',
    'type': 'beautifier',
    'syntaxes': ['python'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/autopep8',
    'args': None,
    'config_path': {
        'default': 'autopep8_rc.cfg'
    },
    'comment': 'requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}. requires python on PATH if omit interpreter_path'
}


class Autopep8Formatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--global-config', path])

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
        except OSError:
            self.print_oserr(cmd)

        return None
