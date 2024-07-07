import os
import tempfile
from .. import log
from ..core import common

INTERPRETERS = ['node']
EXECUTABLES = ['prettydiff']
DOTFILES = ['.prettydiffrc']
MODULE_CONFIG = {
    'source': 'https://github.com/prettydiff/prettydiff',
    'name': 'Pretty Diff',
    'uid': 'prettydiffmin',
    'type': 'minifier',
    'syntaxes': ['css', 'scss', 'less', 'js', 'jsx', 'json', 'html', 'asp', 'xml', 'tsx'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/prettydiff',
    'args': None,
    'config_path': {
        'default': 'prettydiffmin_rc.json'
    },
    'comment': 'requires node on PATH if omit interpreter_path'
}


class PrettydiffminFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        cmd.extend(['minify'])

        path = self.get_config_path()
        if path:
            cmd.extend(['config', path])

        file = self.get_pathinfo()['path']
        tmp_file = None
        if file:
            cmd.extend(['source', file])
        else:
            tmp_file = self.create_tmp_file()
            cmd.extend(['source', tmp_file])

        log.debug('Command: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd, tmp_file

    def format(self):
        cmd, tmp_file = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            self.remove_tmp_file(tmp_file)
            return None

        try:
            exitcode, stdout, stderr = self.exec_com(cmd)

            self.remove_tmp_file(tmp_file)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.remove_tmp_file(tmp_file)
            self.print_oserr(cmd)

        return None
