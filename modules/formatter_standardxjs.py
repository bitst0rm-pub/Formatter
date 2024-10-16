from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['standardx']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/standard/standardx',
    'name': 'StandardxJS',
    'uid': 'standardxjs',
    'type': 'beautifier',
    'syntaxes': ['js'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/standardx(.cmd on windows)',
    'args': None,
    'config_path': None,
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node. Opinionated, no config.'
}


class StandardxjsFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        cmd.extend(['--fix', '--stdin', '-'])

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
