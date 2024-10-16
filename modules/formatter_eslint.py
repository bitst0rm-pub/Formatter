from distutils.version import LooseVersion

import sublime

from ..core import Module, log

INTERPRETERS = ['node']
EXECUTABLES = ['eslint']
DOTFILES = ['eslint.config.js', 'eslint.config.mjs', 'eslint.config.cjs', 'eslint.config.ts', 'eslint.config.mts', 'eslint.config.cts', '.eslintrc', '.eslintrc.js', '.eslintrc.cjs', '.eslintrc.yaml', '.eslintrc.yml', '.eslintrc.json']
MODULE_CONFIG = {
    'source': 'https://github.com/eslint/eslint',
    'name': 'ESLint',
    'uid': 'eslint',
    'type': 'beautifier',
    'syntaxes': ['js'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/eslint(.cmd on windows)',
    'args': ['--resolve-plugins-relative-to', '/path/to/eslintv8/javascript/node_modules'],
    'config_path': {
        'default': 'eslint_rc.json_(v8)_or_eslint_config_rc.mjs_(v9)'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class EslintFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def compat(self):
        cmd = self.get_iprexe_cmd(runtime_type='node')
        if not cmd:
            return None, None

        _, version, _ = self.exec_cmd(cmd + ['--version'])

        version = version.strip().split(' ')[-1]
        log.debug('Eslint version: %s', version)

        return cmd, LooseVersion(version) < LooseVersion('v8.57.0')

    def remove_deprecated_flag_and_next(self, cmd):
        for flag in ['--resolve-plugins-relative-to', '--rulesdir', '--ext']:
            if flag in cmd:
                index = cmd.index(flag)
                cmd.pop(index)  # Remove the flag
                if index < len(cmd):  # Ensure there is an element to remove after it
                    cmd.pop(index)  # Remove the next element

        return cmd

    def get_cmd(self):
        cmd, isv8 = self.compat()
        if not cmd:
            return None

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            lookup = '--no-eslintrc' if isv8 else '--no-config-lookup'
            cmd.extend([lookup, '--config', path])

        cmd.extend(['--no-color', '--stdin', '--fix-dry-run', '--format=json'])

        file = self.get_pathinfo()['path']
        dummy = file or 'dummy.' + self.get_assigned_syntax()
        cmd.extend(['--stdin-filename', dummy])

        if not isv8:
            cmd = self.remove_deprecated_flag_and_next(cmd)

        return cmd

    def format(self):
        cmd = self.get_cmd()

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
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
