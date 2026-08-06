from ..core import Module

EXECUTABLES = ['alejandra']
DOTFILES = ['alejandra.toml']
MODULE_CONFIG = {
    'source': 'https://github.com/kamadorueda/alejandra',
    'name': 'Alejandra',
    'uid': 'alejandra',
    'type': 'beautifier',
    'syntaxes': ['nix'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/alejandra',
    'args': None,
    'config_path': {
        'default': 'alejandra_rc.toml'
    },
    'comment': 'Requires alejandra 4.0.0 or newer for "config_path", which is experimental and limited to "indentation".'
}


class AlejandraFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--experimental-config', path])

        cmd.extend(['--quiet', '-'])

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
