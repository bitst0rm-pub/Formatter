from ..core import Module

EXECUTABLES = ['lua-format']
DOTFILES = ['.lua-format']
MODULE_CONFIG = {
    'source': 'https://github.com/Koihik/LuaFormatter',
    'name': 'LuaFormatter',
    'uid': 'luaformatter',
    'type': 'beautifier',
    'syntaxes': ['lua'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/lua-format',
    'args': None,
    'config_path': {
        'default': 'luaformatter_rc.yaml'
    }
}


class LuaformatterFormatter(Module):
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
