from .. import log
from ..core.common import Module


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
    'comment': 'requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}. requires python on PATH if omit interpreter_path'
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
            cmd.extend(['--sp', path])

        cmd.extend(['-stdout', '-'])

        log.debug('Command: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
