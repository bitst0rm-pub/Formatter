from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['terser']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/terser-js/terser',
    'name': 'Terser',
    'uid': 'terser',
    'type': 'minifier',
    'syntaxes': ['js'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/terser(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'terser_rc.json'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class TerserFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config-file', path])

        cmd.extend(['--compress', '--mangle', '--'])

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
