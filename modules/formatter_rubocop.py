from ..core import Module, log

INTERPRETERS = ['ruby']
EXECUTABLES = ['rubocop']
DOTFILES = ['.rubocop.yml']
MODULE_CONFIG = {
    'source': 'https://github.com/rubocop-hq/rubocop',
    'name': 'RuboCop',
    'uid': 'rubocop',
    'type': 'beautifier',
    'syntaxes': ['ruby'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/rubocop',
    'args': None,
    'config_path': {
        'default': 'rubocop_rc.yml'
    },
    'comment': 'Requires "environ": {"GEM_PATH": ["/path/to/dir/ruby"]}. Omit "interpreter_path" if ruby already on PATH.'
}


class RubocopFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='ruby')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        base = self.get_pathinfo()['base']
        cmd.extend(['--autocorrect', '--stdin', base if base else 'untitled', '--stderr'])

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
