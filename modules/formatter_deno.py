import logging
from ..core import common

log = logging.getLogger(__name__)
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


class DenoFormatter(common.Module):
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
