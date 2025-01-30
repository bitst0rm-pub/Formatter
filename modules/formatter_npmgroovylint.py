from ..core import Module

INTERPRETERS = ['node']
EXECUTABLES = ['npm-groovy-lint']
DOTFILES = ['.groovylintrc.json', '.groovylintrc.js', '.groovylintrc.yml']
MODULE_CONFIG = {
    'source': 'https://github.com/nvuillam/npm-groovy-lint',
    'name': 'GroovyLint',
    'uid': 'npmgroovylint',
    'type': 'beautifier',
    'syntaxes': ['groovy', 'gradle'],
    'executable_path': '/path/to/node_modules/.bin/npm-groovy-lint(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'groovylint_rc.json'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node. If "--fix" param is needed, use "fix_commands": [["--format", "--fix", 3, 0, 3]]'
}


class NpmgroovylintFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        cmd.extend(['--format', '-'])

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
