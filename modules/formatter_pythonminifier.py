import logging
import sublime
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['python3', 'python']
EXECUTABLES = ['pyminify']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/dflook/python-minifier',
    'name': 'Python Minifier',
    'uid': 'pythonminifier',
    'type': 'minifier',
    'syntaxes': ['python'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/pyminify',
    'args': None,
    'config_path': {
        'default': 'python_minifier_rc.json'
    },
    'comment': 'requires "environ": {"PYTHONPATH": ["/lib/python3.7/site-packages"]}. requires python on PATH if omit interpreter_path'
}


class PythonminifierFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='python')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            # pythonminifier does not have an option to
            # read external config file. We build one.
            params = [
                '--no-combine-imports',
                '--no-remove-pass',
                '--remove-literal-statements',
                '--no-remove-annotations',
                '--no-remove-variable-annotations',
                '--no-remove-return-annotations',
                '--no-remove-argument-annotations',
                '--remove-class-attribute-annotations',
                '--no-hoist-literals',
                '--no-rename-locals',
                '--preserve-locals',
                '--rename-globals',
                '--preserve-globals',
                '--no-remove-object-base',
                '--no-convert-posargs-to-args',
                '--no-preserve-shebang',
                '--remove-asserts',
                '--remove-debug',
                '--no-remove-explicit-return-none',
                '--no-remove-builtin-exception-brackets'
            ]

            with open(path, 'r', encoding='utf-8') as file:
                data = file.read()
            json = sublime.decode_value(data)

            for k, v in json.items():
                no_param = '--no-' + k
                param = '--' + k
                if no_param in params and isinstance(v, bool) and not v:
                        cmd.extend([no_param])
                if param in params:
                    if isinstance(v, bool) and v:
                        cmd.extend([param])
                    if isinstance(v, list) and v:
                        cmd.extend([param, ', '.join(v)])

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
