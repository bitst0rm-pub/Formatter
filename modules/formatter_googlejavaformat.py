from ..libs import yaml
from .. import log
from ..core import common

INTERPRETERS = ['java']
EXECUTABLES = ['google-java-format-all-deps.jar']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/google/google-java-format',
    'name': 'Google Java Format',
    'uid': 'googlejavaformat',
    'type': 'beautifier',
    'syntaxes': ['java'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/java.exe',
    'executable_path': '/path/to/bin/google-java-format-all-deps.jar',
    'args': None,
    'config_path': {
        'default': 'google_java_format_rc.yaml'
    },
    'comment': 'requires java on PATH if omit interpreter_path'
}


class GooglejavaformatFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type=None)
        if not cmd:
            return None

        cmd[1:1] = ['-jar']

        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                cfg_dict = yaml.safe_load(file)

                # google-java-format does not have an option to
                # read external config file. We build one.
                for key, value in cfg_dict.items():
                    if isinstance(value, bool):
                        if value:
                            cmd.append('--' + key)
                    else:
                        cmd.extend(['--' + key, str(value)])

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
