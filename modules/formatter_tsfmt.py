from .. import log
from ..core import common

INTERPRETERS = ['node']
EXECUTABLES = ['tsfmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/vvakame/typescript-formatter',
    'name': 'TSfmt',
    'uid': 'tsfmt',
    'type': 'beautifier',
    'syntaxes': ['ts', 'tsx'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/tsfmt',
    'args': None,
    'config_path': {
        'default': 'tsfmt.json'
    },
    'comment': 'hardcoded config file name (tsfmt.json). requires node on PATH if omit interpreter_path'
}


class TsfmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path and '--baseDir' not in cmd:
            cmd.extend(['--baseDir', self.get_pathinfo(path)['cwd']])

        cmd.extend(['--stdin', '--'])

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
                return stdout.replace('\r', '')  # hack <0x0d>
        except OSError:
            self.print_oserr(cmd)

        return None
