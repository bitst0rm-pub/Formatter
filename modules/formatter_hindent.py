from ..core import Module
from ..libs import yaml

EXECUTABLES = ['hindent']
DOTFILES = ['.hindent.yaml']
MODULE_CONFIG = {
    'source': 'https://github.com/mihaimaruseac/hindent',
    'name': 'Hindent',
    'uid': 'hindent',
    'type': 'beautifier',
    'syntaxes': ['haskell'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/hindent',
    'args': None,
    'config_path': {
        'default': 'hindent_rc.yaml'
    }
}


class HindentFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type='haskell')
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                cfg_dict = yaml.safe_load(file)

                # Hindent does not have an option to
                # read external config file. We build one.
                flattened_list = []

                for key, value in cfg_dict.items():
                    if key.isupper() and isinstance(value, list):
                        for item in value:
                            flattened_list.extend(['-' + key, item])
                    elif value is None:
                        flattened_list.extend(['--' + key, 'null'])
                    elif isinstance(value, bool):
                        if value:
                            flattened_list.append('--' + key)
                    else:
                        flattened_list.extend(['--' + key, str(value)])

                cmd.extend(flattened_list)

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
