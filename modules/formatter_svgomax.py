import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['svgo']
DOTFILES = ['svgo.config.mjs']
MODULE_CONFIG = {
    'source': 'https://github.com/svg/svgo',
    'name': 'SVGO',
    'uid': 'svgomax',
    'type': 'beautifier',
    'syntaxes': ['svg'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/svgo',
    'args': None,
    'config_path': {
        'default': 'svgomax_rc.js'
    },
    'comment': 'requires node on PATH if omit interpreter_path'
}


class SvgomaxFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        cmd.extend(['--pretty', '--no-color', '-'])

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
