import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['prettierd']
DOTFILES = ['.prettierrc', '.prettierrc.json', '.prettierrc.yml', '.prettierrc.yaml', '.prettierrc.json5', '.prettierrc.js', 'prettier.config.js', '.prettierrc.mjs', 'prettier.config.mjs', '.prettierrc.cjs', 'prettier.config.cjs', '.prettierrc.toml']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/fsouza/prettierd',
    'name': 'Prettierd',
    'uid': 'prettierd',
    'type': 'beautifier',
    'syntaxes': ['css', 'scss', 'less', 'js', 'jsx', 'json', 'html', 'graphql', 'markdown', 'ts', 'tsx', 'vue', 'yaml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/prettierd',
    'args': None,
    'config_path': {
        'default': 'prettierd_rc.json'
    },
    'comment': 'requires node on PATH if omit interpreter_path. use config_path instead of PRETTIERD_DEFAULT_CONFIG'
}


class PrettierdFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        cmd.extend(['--no-color'])

        path = self.get_config_path()
        if path:
            cmd.extend(['--no-config'])
            common.config.get('environ').update({'PRETTIERD_DEFAULT_CONFIG': [path]})

        file = self.get_pathinfo()['path']
        dummy = file if file else 'dummy.' + self.get_assigned_syntax()
        cmd.extend(['--stdin-filepath', dummy])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
