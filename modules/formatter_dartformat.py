from ..core import Module

EXECUTABLES = ['dart']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://dart.dev/tools/dart-format',
    'name': 'DartFormat',
    'uid': 'dartformat',
    'type': 'beautifier',
    'syntaxes': ['dart'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/dart',
    'args': None,
    'config_path': None,
    'comment': 'Opinionated, no config.'
}


class DartformatFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type='dart')
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        cmd.extend(['format'])

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
