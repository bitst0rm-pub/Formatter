from .. import log
from ..core.common import Module


INTERPRETERS = ['perl']
EXECUTABLES = ['perltidy', 'perltidy.pl']
DOTFILES = ['.perltidyrc']
MODULE_CONFIG = {
    'source': 'https://github.com/perltidy/perltidy',
    'name': 'Perltidy',
    'uid': 'perltidy',
    'type': 'beautifier',
    'syntaxes': ['perl'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/perltidy or /path/to/perltidy.pl',
    'args': None,
    'config_path': {
        'default': 'perltidy_rc.cfg'
    },
    'comment': 'requires perl on PATH if omit interpreter_path'
}


class PerltidyFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='perl')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--profile=' + path])

        cmd.extend(['--standard-output', '--standard-error-output', '--warning-output'])

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
