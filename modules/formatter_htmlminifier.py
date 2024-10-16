from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['html-minifier']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/kangax/html-minifier',
    'name': 'HTMLMinifier',
    'uid': 'htmlminifier',
    'type': 'minifier',
    'syntaxes': ['html', 'xml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/html-minifier(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'htmlminifier_rc.json'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class HtmlminifierFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config-file', path])

        cmd.extend(['--file-ext', self.get_assigned_syntax()])

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
