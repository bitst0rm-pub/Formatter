from ..core.common import Module
from ..core.constants import IS_WINDOWS

INTERPRETERS = ['node']
EXECUTABLES = ['prettier.cmd', 'bin-prettier.js', 'prettier']
DOTFILES = ['.prettierrc', '.prettierrc.json', '.prettierrc.yml', '.prettierrc.yaml', '.prettierrc.json5', '.prettierrc.js', 'prettier.config.js', '.prettierrc.mjs', 'prettier.config.mjs', '.prettierrc.cjs', 'prettier.config.cjs', '.prettierrc.toml']
MODULE_CONFIG = {
    'source': 'https://github.com/prettier/prettier',
    'name': 'Prettier',
    'uid': 'prettier',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'less', 'js', 'jsx', 'json', 'html', 'graphql', 'markdown', 'ts', 'tsx', 'vue', 'yaml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/prettier or /path/to/node_modules/.bin/bin-prettier.js',
    'args': None,
    'config_path': {
        'default': 'prettier_rc.json'
    },
    'comment': 'requires node on PATH if omit interpreter_path'
}


class PrettierFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        if IS_WINDOWS:
            executable = self.get_executable(runtime_type='node')
            if not executable.endswith('js'):
                cmd = [executable]

                cmd.extend(self.get_args())
            else:
                cmd = self.get_combo_cmd(runtime_type='node')
        else:
            cmd = self.get_combo_cmd(runtime_type='node')

        cmd.extend(['--no-color'])

        path = self.get_config_path()
        if path:
            cmd.extend(['--no-config', '--config', path])

        file = self.get_pathinfo()['path']
        dummy = file if file else 'dummy.' + self.get_assigned_syntax()
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
