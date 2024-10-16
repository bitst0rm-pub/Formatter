from os.path import basename

from ..core import Module

EXECUTABLES = ['rebar3', 'erlfmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/WhatsApp/erlfmt',
    'name': 'Erlfmt',
    'uid': 'erlfmt',
    'type': 'beautifier',
    'syntaxes': ['erlang'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/erlfmt (standalone bin) or /path/to/rebar3',
    'args': None,
    'config_path': None,
    'comment': 'Opinionated, no config.'
}


class ErlfmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        if basename(executable) == 'rebar3':
            cmd = [executable, 'fmt']
        else:
            cmd = [executable]

        cmd.extend(self.get_args())

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
