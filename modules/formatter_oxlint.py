from ..core import Module, log

INTERPRETERS = ['node']
EXECUTABLES = ['oxlint']
DOTFILES = ['.oxlintrc.json', '.oxlintrc.jsonc', 'oxlint.config.ts', 'oxlint.config.mts']
MODULE_CONFIG = {
    'source': 'https://github.com/oxc-project/oxc',
    'name': 'Oxlint',
    'uid': 'oxlint',
    'type': 'beautifier',
    'syntaxes': ['js', 'jsx', 'ts', 'tsx', 'vue'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/oxlint (standalone binary) or /path/to/node_modules/.bin/oxlint(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'oxlint_rc.json'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node. Limited autofix, no formatting capability.'
}


class OxlintFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None, None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        # Oxlint has no stdin support, so the buffer is linted as a temporary
        # file, which "--fix" rewrites in place. "--no-ignore" keeps that file
        # from being skipped by any .eslintignore of the surrounding project.
        tmp_file = self.create_tmp_file(autodel=True)
        cmd.extend(['--fix', '--no-ignore', tmp_file])

        return cmd, tmp_file

    def format(self):
        cmd, tmp_file = self.get_cmd()
        if not cmd:
            return None

        result = None

        try:
            exitcode, stdout, stderr = self.exec_com(cmd)

            if exitcode > 1 or stdout is None:  # stdout is None on timeout or execution failure
                self.print_exiterr(exitcode, stderr)
            else:
                if exitcode == 1:  # unfixable issues remain, fixable ones are already applied
                    log.debug('Remaining Oxlint issues:\n%s', stdout)

                with open(tmp_file, 'r', encoding='utf-8') as file:
                    result = file.read()
        except Exception as e:
            self.print_oserr(cmd, e)

        return result
