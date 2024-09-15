from ..core import Module

EXECUTABLES = ['dprint']
DOTFILES = ['.dprint.json', '.dprint.jsonc', 'dprint.json', 'dprint.jsonc']
MODULE_CONFIG = {
    'source': 'https://github.com/dprint/dprint',
    'name': 'Dprint',
    'uid': 'dprint',
    'type': 'beautifier',
    'syntaxes': ['js', 'jsx', 'ts', 'tsx', 'json', 'markdown', 'toml'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/dprint',
    'args': None,
    'config_path': {
        'default': 'dprint_rc.json'
    }
}


class DprintFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', path])

        syntax_mapping = {'markdown': 'md'}
        syntax = self.get_assigned_syntax()
        ext = syntax_mapping.get(syntax, syntax)
        cmd.extend(['--stdin', 'dummy.' + ext, '--'])

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
