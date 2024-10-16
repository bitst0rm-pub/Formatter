from ..core import IS_WINDOWS, Module

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
    'comment': 'Opinionated, no config. Omit "interpreter_path" if java already on PATH.'
}


class KtlintFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        if IS_WINDOWS:
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

        cmd.extend(['--format', '--stdin', '-'])

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
