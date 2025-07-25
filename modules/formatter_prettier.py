from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['prettier']
DOTFILES = ['.prettierrc', '.prettierrc.json', '.prettierrc.yml', '.prettierrc.yaml', '.prettierrc.json5', '.prettierrc.js', 'prettier.config.js', '.prettierrc.mjs', 'prettier.config.mjs', '.prettierrc.cjs', 'prettier.config.cjs', '.prettierrc.toml']
MODULE_CONFIG = {
    'source': 'https://github.com/prettier/prettier',
    'name': 'Prettier',
    'uid': 'prettier',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'less', 'js', 'jsx', 'json', 'html', 'graphql', 'markdown', 'ts', 'tsx', 'vue', 'yaml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/prettier(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'prettier_rc.json'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class PrettierFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        cmd.extend(['--no-color'])

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])
        else:
            cmd.extend(['--no-config'])

        file = self.get_pathinfo()['path']
        dummy = file or 'dummy.' + self.get_assigned_syntax()
        cmd.extend(['--stdin-filepath', dummy])

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
