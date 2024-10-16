from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['stylefmt']
DOTFILES = ['.stylelintrc']
MODULE_CONFIG = {
    'source': 'https://github.com/masaakim/stylefmt',
    'name': 'Stylefmt',
    'uid': 'stylefmt',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'sass', 'less'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/stylefmt(.cmd on windows)',
    'args': ['--config-basedir', '/path/to/javascript/node_modules'],
    'config_path': {
        'default': 'stylefmt_rc.json'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class StylefmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        file = self.get_pathinfo()['path']
        dummy = file or 'dummy.' + self.get_assigned_syntax()
        cmd.extend(['--stdin-filename', dummy, '--'])

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
