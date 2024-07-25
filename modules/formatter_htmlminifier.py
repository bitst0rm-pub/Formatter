from .. import log
from ..core.common import Module


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
    'executable_path': '/path/to/node_modules/.bin/html-minifier',
    'args': None,
    'config_path': {
        'default': 'htmlminifier_rc.json'
    },
    'comment': 'requires node on PATH if omit interpreter_path'
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

        log.debug('Command: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
