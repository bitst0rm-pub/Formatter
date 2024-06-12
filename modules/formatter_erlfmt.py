import logging
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['rebar3', 'erlfmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/WhatsApp/erlfmt',
    'name': 'Erlang erlfmt',
    'uid': 'erlfmt',
    'type': 'beautifier',
    'syntaxes': ['erlang'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/erlfmt (standalone bin) or /path/to/rebar3',
    'args': None,
    'config_path': None,
    'comment': 'opinionated, no config'
}


class ErlfmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        if common.basename(executable) == 'rebar3':
            cmd = [executable, 'fmt']
        else:
            cmd = [executable]

        cmd.extend(self.get_args())

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
