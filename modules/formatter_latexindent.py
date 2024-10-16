from ..core import Module

INTERPRETERS = ['perl', 'perl5']
EXECUTABLES = ['latexindent.pl', 'latexindent', 'latexindent-macos', 'latexindent-linux']
DOTFILES = ['.indentconfig.yaml', 'indentconfig.yaml']
MODULE_CONFIG = {
    'source': 'https://github.com/cmhughes/latexindent.pl',
    'name': 'LaTeXindent',
    'uid': 'latexindent',
    'type': 'beautifier',
    'syntaxes': ['tex', 'latex'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/latexindent or /path/to/latexindent.pl',
    'args': None,
    'config_path': {
        'default': 'latexindent_rc.yaml'
    },
    'comment': 'Omit "interpreter_path" if perl already on PATH.'
}


class LatexindentFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        interpreter = self.get_interpreter()
        executable = self.get_executable(runtime_type=None)
        if interpreter and executable and executable.endswith('.pl'):
            cmd = [interpreter, executable]
        elif executable:
            cmd = [executable]
        else:
            return None

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--local', path])

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
