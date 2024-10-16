from ..core import Module, log

INTERPRETERS = ['ruby']
EXECUTABLES = ['standardrb']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/standardrb/standard',
    'name': 'StandardRB',
    'uid': 'standardrb',
    'type': 'beautifier',
    'syntaxes': ['ruby'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/standardrb',
    'args': None,
    'config_path': None,
    'comment': 'Requires "environ": {"GEM_PATH": ["/path/to/dir/ruby"]}. Opinionated, no config. Omit "interpreter_path" if ruby already on PATH.'
}


class StandardrbFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='ruby')
        if not cmd:
            return None

        base = self.get_pathinfo()['base']
        cmd.extend(['--fix', '--stdin', base or 'untitled', '--stderr'])

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                log.debug('Success (exitcode=%d): "%s"', exitcode, stderr)
                return stdout
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
