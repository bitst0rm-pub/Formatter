from .. import log
from ..core.common import Module


EXECUTABLES = ['cabal-fmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/phadej/cabal-fmt',
    'name': 'Cabal-fmt',
    'uid': 'cabalfmt',
    'type': 'beautifier',
    'syntaxes': ['cabal'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/.cabal/bin/cabal-fmt',
    'args': ['--tabular', '--indent', '4'],
    'config_path': None,
    'comment': 'requires haskell. use args instead of config_path'
}


class CabalfmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        cmd.extend(['--stdout', '--'])

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
