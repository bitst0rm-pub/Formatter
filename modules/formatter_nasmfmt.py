from ..core import Module
from ..libs import yaml

EXECUTABLES = ['nasmfmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/yamnikov-oleg/nasmfmt',
    'name': 'NASMfmt',
    'uid': 'nasmfmt',
    'type': 'beautifier',
    'syntaxes': ['asm'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/nasmfmt',
    'args': None,
    'config_path': {
        'default': 'nasmfmt_rc.yaml'
    }
}


class NasmfmtFormatter(Module):
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
            with open(path, 'r', encoding='utf-8') as file:
                cfg_dict = yaml.safe_load(file)

                # nasmfmt does not have an option to
                # read external config file. We build one.
                flattened_list = [item for key, value in cfg_dict.items() for item in (('--' + key, 'null') if value is None else ('-' + key, str(value).lower()))]
                cmd.extend(flattened_list)

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
