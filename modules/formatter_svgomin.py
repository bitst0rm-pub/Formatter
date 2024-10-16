from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['svgo']
DOTFILES = ['svgo.config.mjs']
MODULE_CONFIG = {
    'source': 'https://github.com/svg/svgo',
    'name': 'SVGO',
    'uid': 'svgomin',
    'type': 'minifier',
    'syntaxes': ['svg'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/svgo(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'svgomin_rc.js'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class SvgominFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        cmd.extend(['--no-color', '-'])

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
