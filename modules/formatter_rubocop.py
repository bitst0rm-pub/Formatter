import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['ruby']
EXECUTABLES = ['rubocop']
MODULE_CONFIG = {
    'source': 'https://github.com/rubocop-hq/rubocop',
    'name': 'RuboCop',
    'uid': 'rubocop',
    'type': 'beautifier',
    'syntaxes': ['ruby'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/rubocop',
    'args': None,
    'config_path': {
        'default': 'rubocop_rc.yml'
    },
    'comment': 'requires "environ": {"GEM_PATH": ["/path/to/dir/ruby"]}. requires ruby on PATH if omit interpreter_path'
}


class RubocopFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='ruby')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        base = self.get_pathinfo()['base']
        cmd.extend(['--autocorrect', '--stdin', base if base else 'untitled', '--stderr'])

        log.debug('Current arguments: %s', cmd)
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
                log.debug('Success (exitcode=%d): "%s"', exitcode, stderr)
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
