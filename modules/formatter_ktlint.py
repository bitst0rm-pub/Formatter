from .. import log
from ..core import common

INTERPRETERS = ['java']
EXECUTABLES = ['ktlint']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/pinterest/ktlint',
    'name': 'Ktlint',
    'uid': 'ktlint',
    'type': 'beautifier',
    'syntaxes': ['kotlin'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/java.exe',
    'executable_path': '/path/to/bin/ktlint or path/to/ktlint.bat',
    'args': None,
    'comment': 'opinionated, no config. requires java on PATH if omit interpreter_path.'
}


class KtlintFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        if common.IS_WINDOWS:
            executable = self.get_executable(runtime_type=None)
            if executable.endswith('bat'):
                cmd = [executable]

                cmd.extend(self.get_args())
            else:
                cmd = self.get_combo_cmd(runtime_type=None)
                cmd[1:1] = ['-jar']
        else:
            cmd = self.get_combo_cmd(runtime_type=None)
            cmd[1:1] = ['-jar']

        if not self.is_valid_cmd(cmd):
            return None

        cmd.extend(['--format', '--stdin', '-'])

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
