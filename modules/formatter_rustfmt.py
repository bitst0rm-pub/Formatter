from ..core import Module

EXECUTABLES = ['rustfmt']
DOTFILES = ['.rustfmt.toml', 'rustfmt.toml']
MODULE_CONFIG = {
    'source': 'https://github.com/rust-lang/rustfmt',
    'name': 'Rustfmt',
    'uid': 'rustfmt',
    'type': 'beautifier',
    'syntaxes': ['rust'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/rustfmt',
    'args': None,
    'config_path': {
        'default': 'rustfmt_rc.toml'
    }
}


class RustfmtFormatter(Module):
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
            cmd.extend(['--config-path', path])

        cmd.extend(['--color', 'never'])

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
