import logging
from ..core import common

log = logging.getLogger(__name__)
#EXECUTABLES = ['rebar3', 'efmt']  # No rebar3 support right now, @see #55
EXECUTABLES = ['efmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/sile/efmt',
    'name': 'Erlang efmt',
    'uid': 'efmt',
    'type': 'beautifier',
    'syntaxes': ['erlang'],
    'exclude_syntaxes': None,
    #'executable_path': '/path/to/bin/efmt (standalone bin) or /path/to/rebar3',
    'executable_path': '/path/to/bin/efmt (standalone bin)',
    'args': None,
    'config_path': None,
    #'comment': 'opinionated, no config'
    'comment': 'opinionated, no config. no rebar3 upstream support, use efmt standalone instead. requires efmt on PATH if omit interpreter_path'
}


class EfmtFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        '''
        Disabled: No rebar3 support right now, @see:
        https://github.com/bitst0rm-pub/Formatter/issues/55
        https://github.com/sile/efmt/issues/94

        if common.basename(executable) == 'rebar3':
            cmd = [executable, 'efmt']
        else:
            cmd = [executable]
        '''

        cmd = [executable]

        cmd.extend(self.get_args())

        cmd.extend(['-'])

        log.debug('Command: %s', cmd)
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
