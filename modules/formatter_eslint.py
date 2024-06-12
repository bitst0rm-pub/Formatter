import logging
import sublime
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['node']
EXECUTABLES = ['eslint', 'eslint.js']
DOTFILES = ['.eslintrc', '.eslintrc.js', '.eslintrc.cjs', '.eslintrc.yaml', '.eslintrc.yml', '.eslintrc.json']
MODULE_CONFIG = {
    'source': 'https://github.com/eslint/eslint',
    'name': 'ESLint',
    'uid': 'eslint',
    'type': 'beautifier',
    'syntaxes': ['js'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/eslint or /path/to/node_modules/.bin/eslint.js',
    'args': ['--resolve-plugins-relative-to', '/path/to/javascript/node_modules'],
    'config_path': {
        'default': 'eslint_rc.json'
    },
    'comment': 'requires node on PATH if omit interpreter_path'
}


class EslintFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--no-eslintrc', '--config', path])

        cmd.extend(['--no-color', '--stdin', '--fix-dry-run', '--format=json'])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 1:
                self.print_exiterr(exitcode, stderr)
            else:
                obj = sublime.decode_value(stdout)[0]
                if 'output' in obj:
                    return obj.get('output', None)
                self.print_exiterr(exitcode, stderr)
                for i in obj.get('messages', []):
                    print(i)
        except OSError:
            self.print_oserr(cmd)

        return None
