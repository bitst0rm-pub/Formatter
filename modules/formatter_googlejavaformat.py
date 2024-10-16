from ..core import Module
from ..libs import yaml

INTERPRETERS = ['java']
EXECUTABLES = ['google-java-format-all-deps.jar']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/google/google-java-format',
    'name': 'GoogleJavaFormat',
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
    'comment': 'Omit "interpreter_path" if java already on PATH.'
}


class GooglejavaformatFormatter(Module):
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
