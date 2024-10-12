from ..core import Module

EXECUTABLES = ['swift-format']
DOTFILES = ['.swift-format']
MODULE_CONFIG = {
    'source': 'https://github.com/apple/swift-format',
    'name': 'AppleSwiftFormat',
    'uid': 'appleswiftformat',
    'type': 'beautifier',
    'syntaxes': ['swift'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/swift-format',
    'args': None,
    'config_path': {
        'default': 'apple_swift_format_rc.json'
    }
}


class AppleswiftformatFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'format']

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--configuration', path])

        file = self.get_pathinfo()['path']
        dummy = file or 'dummy.' + self.get_assigned_syntax()
        cmd.extend(['--assume-filename', dummy])

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode != 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
