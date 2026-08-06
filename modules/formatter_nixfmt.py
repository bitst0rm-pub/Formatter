from ..core import Module

EXECUTABLES = ['nixfmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/NixOS/nixfmt',
    'name': 'Nixfmt',
    'uid': 'nixfmt',
    'type': 'beautifier',
    'syntaxes': ['nix'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/nixfmt',
    'args': None,
    'config_path': None,
    'comment': 'Requires nixfmt 0.6.0 or newer. No config, use "args" instead, e.g. ["--width", "100", "--indent", "2", "--strict"].'
}


class NixfmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

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
