import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['d2']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/terrastruct/d2',
    'name': 'D2-fmt',
    'uid': 'd2fmt',
    'type': 'beautifier',
    'syntaxes': ['d2'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/d2',
    'args': None,
    'config_path': None,
    'comment': 'opinionated, no config'
}


class D2fmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        cmd.extend(self.get_args())

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
