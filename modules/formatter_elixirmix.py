import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['mix']
DOTFILES = ['.formatter.exs']
MODULE_CONFIG = {
    'source': 'https://github.com/elixir-lang/elixir',
    'name': 'Elixir mix',
    'uid': 'elixirmix',
    'type': 'beautifier',
    'syntaxes': ['elixir'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/elixir/bin/mix',
    'args': None,
    'config_path': {
        'default': 'elixirmix_rc.exs'
    },
    'comment': 'no interpreter_path, instead use "environ": {"PATH": ["/path/to/erlang@22/bin:$PATH", "$PATH:/path/to/elixir/bin"]}'
}


class ElixirmixFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'format']

        path = self.get_config_path()
        if path:
            cmd.extend(['--dot-formatter', path])

        cmd.extend(['-'])

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
