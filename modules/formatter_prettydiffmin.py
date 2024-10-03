from ..core import Module

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


class PrettydiffminFormatter(Module):
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

        tmp_file = self.create_tmp_file()
        cmd.extend(['source', tmp_file])

        return cmd, tmp_file

    def format(self):
        cmd, tmp_file = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_com(cmd)

            self.remove_tmp_file(tmp_file)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except Exception as e:
            self.remove_tmp_file(tmp_file)
            self.print_oserr(cmd, e)

        return None
