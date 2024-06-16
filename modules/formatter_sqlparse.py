import logging
from ..libs import yaml
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['sqlformat']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/andialbrecht/sqlparse',
    'name': 'SQLparse',
    'uid': 'sqlparse',
    'type': 'beautifier',
    'syntaxes': ['sql'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/sqlformat',
    'args': None,
    'config_path': {
        'default': 'sqlparse_rc.yaml'
    },
    'comment': 'requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}. requires python on PATH if omit interpreter_path'
}


class SqlparseFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                cfg_dict = yaml.safe_load(file)

                # sqlparse does not have an option to
                # read external config file. We build one.
                flattened_list = []
                for key, value in cfg_dict.items():
                    if isinstance(value, bool):
                        if value:
                            flattened_list.extend(['--' + key])
                        else:
                            continue
                    else:
                        flattened_list.extend(['--' + key, str(value).lower()])

                cmd.extend(flattened_list)

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
