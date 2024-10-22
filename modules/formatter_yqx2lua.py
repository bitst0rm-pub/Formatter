from ..core import Module

EXECUTABLES = ['yq']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/mikefarah/yq',
    'name': 'Yq X->LUA',
    'uid': 'yqx2lua',
    'type': 'converter',
    'syntaxes': ['yaml', 'json', 'csv', 'tsv', 'xml', 'toml', 'lua', 'text'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/yq',
    'args': None,
    'config_path': None,
    'comment': 'No "config_path", use "args" instead.'
}


class Yqx2luaFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        assigned_syntax = self.get_assigned_syntax()
        syntax = assigned_syntax if assigned_syntax in ['yaml', 'json', 'csv', 'tsv', 'xml', 'toml', 'lua'] else 'auto'
        cmd.extend(['--no-colors', '--input-format', syntax, '--output-format', 'lua', '--'])

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
