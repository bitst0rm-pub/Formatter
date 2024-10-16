from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['biome']
DOTFILES = ['biome.json', 'biome.jsonc']
MODULE_CONFIG = {
    'source': 'https://github.com/biomejs/biome',
    'name': 'Biome',
    'uid': 'biome',
    'type': 'beautifier',
    'syntaxes': ['js', 'jsx', 'ts', 'tsx', 'json'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/biome (standalone binary) or /path/to/node_modules/.bin/biome(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'biome_rc.json'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class BiomeFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        cmd.extend(['format', '--colors', 'off'])

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config-path', path])

        file = self.get_pathinfo()['path']
        dummy = file or 'dummy.' + self.get_assigned_syntax()
        cmd.extend(['--stdin-file-path', dummy])

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
