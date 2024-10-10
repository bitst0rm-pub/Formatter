from ..core import Module

EXECUTABLES = ['floskell']
DOTFILES = ['.floskell.json', 'floskell.json']
MODULE_CONFIG = {
    'source': 'https://github.com/ennocramer/floskell',
    'name': 'Floskell',
    'uid': 'floskell',
    'type': 'beautifier',
    'syntaxes': ['haskell'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/.cabal/bin/floskell',
    'args': None,
    'config_path': {
        'default': 'floskell_rc.json'
    }
}


class FloskellFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type='haskell')
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        cmd.extend(['--'])

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
