from ..core import Module

INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['nginxfmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/slomkowski/nginx-config-formatter',
    'name': 'NGINXfmt',
    'uid': 'nginxfmt',
    'type': 'beautifier',
    'syntaxes': ['nginx'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/nginxfmt',
    'args': ['--indent', '4'],
    'config_path': None,
    'comment': 'Requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}. No config, use "args" instead. Omit "interpreter_path" if python already on PATH.'
}


class NginxfmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

        cmd.extend(['--pipe', '--'])

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
