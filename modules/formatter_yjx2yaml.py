from ..core import Module

EXECUTABLES = ['yj']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/sclevine/yj',
    'name': 'Yj X->YAML',
    'uid': 'yjx2yaml',
    'type': 'converter',
    'syntaxes': ['yaml', 'json', 'toml', 'hcl'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/yj',
    'args': None,
    'config_path': None,
    'comment': 'No "config_path", use "args" instead.'
}


class Yjx2yamlFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        syntax = self.get_assigned_syntax()
        if syntax in ['yaml', 'json', 'toml', 'hcl']:
            char = syntax[1] if syntax == 'hcl' else syntax[0]
            cmd.extend(['-' + char + 'y', '-'])
        else:
            cmd = None

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not cmd:
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
