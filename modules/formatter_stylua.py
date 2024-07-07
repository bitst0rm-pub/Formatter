from .. import log
from ..core import common

EXECUTABLES = ['stylua']
DOTFILES = ['.stylua.toml', 'stylua.toml']
MODULE_CONFIG = {
    'source': 'https://github.com/JohnnyMorganz/StyLua',
    'name': 'StyLua',
    'uid': 'stylua',
    'type': 'beautifier',
    'syntaxes': ['lua'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/stylua',
    'args': None,
    'config_path': {
        'default': 'stylua_rc.toml'
    }
}


class StyluaFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config-path', path])

        cmd.extend(['--color', 'Never', '-'])

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
