from os.path import basename

from ..core import Module

INTERPRETERS = ['java']
EXECUTABLES = ['cljfmt']
DOTFILES = ['.cljfmt.edn', '.cljfmt.clj', 'cljfmt.edn', 'cljfmt.clj']
MODULE_CONFIG = {
    'source': 'https://github.com/weavejester/cljfmt',
    'name': 'CLJfmt',
    'uid': 'cljfmt',
    'type': 'beautifier',
    'syntaxes': ['clojure'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/java.exe or /path/to/bin/lein',
    'executable_path': '/path/to/bin/cljfmt',
    'args': None,
    'config_path': {
        'default': 'cljfmt_rc.edn'
    },
    'comment': 'Omit "interpreter_path" if "executable_path" is set to the standalone version of cljfmt.'
}


class CljfmtFormatter(Module):
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
            elif 'lein' in interpreter_base:
                cmd = [interpreter, executable]
            else:
                cmd = [executable]
        else:
            cmd = [executable]

        cmd.extend(['fix'])

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

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
