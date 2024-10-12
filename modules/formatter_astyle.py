from ..core import Module

EXECUTABLES = ['AStyle', 'astyle']
DOTFILES = ['.astylerc', '_astylerc']
MODULE_CONFIG = {
    'source': 'https://sourceforge.net/projects/astyle',
    'name': 'ArtisticStyle',
    'uid': 'astyle',
    'type': 'beautifier',
    'syntaxes': ['c', 'c++', 'cs', 'objc', 'objc++', 'java', 'js'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/astyle',
    'args': None,
    'config_path': {
        'java': 'artistic_style_java_rc.ini',
        'default': 'artistic_style_astyle_rc.ini'
    }
}


class AstyleFormatter(Module):
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
            cmd.extend(['--options=' + path])

        syntax_mapping = {'c++': 'c', 'objc++': 'objc'}
        syntax = self.get_assigned_syntax()
        language = syntax_mapping.get(syntax, syntax)

        cmd.extend(['--mode=' + language])

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
