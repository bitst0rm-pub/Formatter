from ..core import Module

EXECUTABLES = ['raco']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/sorawee/fmt',
    'name': 'Racofmt',
    'uid': 'racofmt',
    'type': 'beautifier',
    'syntaxes': ['racket'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/raco',
    'args': ['--width', '102', '--limit', '120', '--max-blank-lines', '1', '--indent', '0'],
    'config_path': '',
    'comment': 'Undocumented --config <config_path>, use "args" instead. "config_path" can be still used in place of --config.'
}


class RacofmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

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
