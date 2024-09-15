from ..core import Module
from ..libs import yaml

EXECUTABLES = ['fourmolu']
DOTFILES = ['fourmolu.yaml']
MODULE_CONFIG = {
    'source': 'https://github.com/fourmolu/fourmolu',
    'name': 'Fourmolu',
    'uid': 'fourmolu',
    'type': 'beautifier',
    'syntaxes': ['haskell'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/fourmolu',
    'args': None,
    'config_path': {
        'default': 'fourmolu_rc.yaml'
    }
}


class FourmoluFormatter(Module):
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

                # Fourmolu does not have an option to
                # read external config file. We build one.
                flattened_list = [item for key, value in cfg_dict.items() for item in (('--' + key, 'null') if value is None else ('--' + key, str(value).lower()))]
                cmd.extend(flattened_list)

        cmd.extend(['--color', 'never', '--stdin-input-file', '-'])

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
