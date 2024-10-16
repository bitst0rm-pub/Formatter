from ..core import Module

EXECUTABLES = ['d2']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/terrastruct/d2',
    'name': 'D2Fmt',
    'uid': 'd2fmt',
    'type': 'beautifier',
    'syntaxes': ['d2'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/d2',
    'args': None,
    'config_path': None,
    'comment': 'Opinionated, no config.'
}


class D2fmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        cmd.extend(self.get_args())

        cmd.extend(['-'])

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
