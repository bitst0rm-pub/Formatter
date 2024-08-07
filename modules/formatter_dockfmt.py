from ..core.common import Module

EXECUTABLES = ['dockfmt']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/jessfraz/dockfmt',
    'name': 'Dockfmt',
    'uid': 'dockfmt',
    'type': 'beautifier',
    'syntaxes': ['dockerfile'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/dockfmt',
    'args': None,
    'config_path': None,
    'comment': 'opinionated, no config'
}


class DockfmtFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable, 'fmt']

        cmd.extend(self.get_args())

        file = self.get_pathinfo()['path']
        tmp_file = None
        if file:
            cmd.extend([file])
        else:
            tmp_file = self.create_tmp_file()
            cmd.extend([tmp_file])

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
