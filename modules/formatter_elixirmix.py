from ..core import Module

EXECUTABLES = ['mix']
DOTFILES = ['.formatter.exs']
MODULE_CONFIG = {
    'source': 'https://github.com/elixir-lang/elixir',
    'name': 'ElixirMix',
    'uid': 'elixirmix',
    'type': 'beautifier',
    'syntaxes': ['elixir'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/elixir/bin/mix',
    'args': None,
    'config_path': {
        'default': 'elixirmix_rc.exs'
    },
    'comment': 'No "interpreter_path", instead use "environ": {"PATH": ["/path/to/erlang@22/bin:$PATH", "$PATH:/path/to/elixir/bin"]}.'
}


class ElixirmixFormatter(Module):
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
