from ..core import Module

EXECUTABLES = ['yamlfmt']
DOTFILES = ['.yamlfmt', '.yamlfmt.yaml', '.yamlfmt.yml', 'yamlfmt.yml', 'yamlfmt.yaml']
MODULE_CONFIG = {
    'source': 'https://github.com/google/yamlfmt',
    'name': 'YAMLfmt',
    'uid': 'yamlfmt',
    'type': 'beautifier',
    'syntaxes': ['yaml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/yamlfmt',
    'args': None,
    'config_path': {
        'default': 'yamlfmt_rc.yaml'
    }
}


class YamlfmtFormatter(Module):
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
            cmd.extend(['-conf', path])

        cmd.extend(['-no_global_conf', '-in', '--'])

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
