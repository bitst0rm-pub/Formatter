from .. import log
from ..core import common

INTERPRETERS = ['node']
EXECUTABLES = ['csscomb']
DOTFILES = ['.csscomb.json']
MODULE_CONFIG = {
    'source': 'https://github.com/csscomb/csscomb.js',
    'name': 'CSScomb',
    'uid': 'csscomb',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'sass', 'less'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/csscomb',
    'args': None,
    'config_path': {
        'default': 'csscomb_rc.json'
    },
    'comment': 'requires node on PATH if omit interpreter_path'
}


class CsscombFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        cmd.extend(['-'])

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
