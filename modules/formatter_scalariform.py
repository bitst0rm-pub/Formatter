from os.path import basename

from ..core import Module

INTERPRETERS = ['java']
EXECUTABLES = ['scalariform']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/scala-ide/scalariform',
    'name': 'Scalariform',
    'uid': 'scalariform',
    'type': 'beautifier',
    'syntaxes': ['scala'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/java.exe or just omit',
    'executable_path': '/path/to/bin/scalariform or /path/to/bin/scalariform.jar',
    'args': None,
    'config_path': {
        'default': 'scalariform_rc.cfg'
    }
}


class ScalariformFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        interpreter = self.get_interpreter()
        if interpreter:
            interpreter_base = basename(interpreter).lower()
            if 'java' in interpreter_base and executable.endswith('jar'):
                cmd = [interpreter, '-jar', executable]
            else:
                cmd = [executable]
        else:
            cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--preferenceFile=' + path])

        cmd.extend(['--stdin'])

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
