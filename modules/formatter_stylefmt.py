from .. import log
from ..core import common

INTERPRETERS = ['node']
EXECUTABLES = ['stylefmt']
DOTFILES = ['.stylelintrc']
MODULE_CONFIG = {
    'source': 'https://github.com/masaakim/stylefmt',
    'name': 'Stylefmt',
    'uid': 'stylefmt',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'sass', 'less'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/stylefmt',
    'args': ['--config-basedir', '/path/to/javascript/node_modules'],
    'config_path': {
        'default': 'stylefmt_rc.json'
    },
    'comment': 'requires node on PATH if omit interpreter_path'
}


class StylefmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        file = self.get_pathinfo()['path']
        dummy = file if file else 'dummy.' + self.get_assigned_syntax()
        cmd.extend(['--stdin-filename', dummy, '--'])

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
