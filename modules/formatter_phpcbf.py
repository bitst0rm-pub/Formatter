from ..core.common import Module

INTERPRETERS = ['php']
EXECUTABLES = ['phpcbf.phar']
DOTFILES = ['.phpcs.xml', 'phpcs.xml', '.phpcs.xml.dist', 'phpcs.xml.dist']
MODULE_CONFIG = {
    'source': 'https://github.com/squizlabs/PHP_CodeSniffer',
    'name': 'PHP CodeSniffer',
    'uid': 'phpcbf',
    'type': 'beautifier',
    'syntaxes': ['php'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/phpcbf.phar',
    'args': None,
    'config_path': {
        'default': 'phpcbf_rc.xml'
    },
    'comment': 'use phpcbf.phar, not phpcs.phar. requires php on PATH if omit interpreter_path'
}


class PhpcbfFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type=None)
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--standard=' + path])

        cmd.extend(['-'])

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode not in [0, 1]:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
