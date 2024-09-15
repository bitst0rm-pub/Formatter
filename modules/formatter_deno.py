from ..core import Module

EXECUTABLES = ['deno']
DOTFILES = ['deno.json', 'deno.jsonc']
MODULE_CONFIG = {
    'source': 'https://github.com/denoland/deno',
    'name': 'Deno',
    'uid': 'deno',
    'type': 'beautifier',
    'syntaxes': ['js', 'jsx', 'ts', 'tsx', 'json', 'markdown', 'ipynb'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/deno',
    'args': None,
    'config_path': {
        'default': 'deno_rc.json'
    }
}


class DenoFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        syntax_mapping = {'markdown': 'md'}
        syntax = self.get_assigned_syntax()
        language = syntax_mapping.get(syntax, syntax)
        cmd.extend(['--ext', language])

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
