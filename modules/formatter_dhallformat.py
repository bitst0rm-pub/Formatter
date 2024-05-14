import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['dhall']
MODULE_CONFIG = {
    'source': 'https://github.com/dhall-lang/dhall-haskell',
    'name': 'Dhall format',
    'uid': 'dhallformat',
    'type': 'beautifier',
    'syntaxes': ['dhall'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/dhall',
    'args': None,
    'config_path': None,
    'comment': 'opinionated, no config'
}


class DhallformatFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        cmd.extend(['format', '--plain', '--'])

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
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
