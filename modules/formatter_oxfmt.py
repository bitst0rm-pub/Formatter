from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['oxfmt']
DOTFILES = ['.oxfmtrc.json', '.oxfmtrc.jsonc', 'oxfmt.config.ts', 'oxfmt.config.mts']
MODULE_CONFIG = {
    'source': 'https://github.com/oxc-project/oxc',
    'name': 'Oxfmt',
    'uid': 'oxfmt',
    'type': 'beautifier',
    'syntaxes': ['js', 'jsx', 'ts', 'tsx', 'json', 'css', 'scss', 'less', 'graphql', 'toml', 'html', 'vue', 'markdown', 'yaml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/oxfmt (standalone binary) or /path/to/node_modules/.bin/oxfmt(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'oxfmt_rc.json'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class OxfmtFormatter(Module):
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
        # Never omit "--stdin-filepath": without it oxfmt formats the whole
        # working directory in place instead of reading from stdin.
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
