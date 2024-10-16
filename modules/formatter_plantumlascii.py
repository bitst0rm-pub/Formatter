from ..core import Module

INTERPRETERS = ['java']
EXECUTABLES = ['plantuml.jar']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/plantuml/plantuml',
    'name': 'PlantumlASCII',
    'uid': 'plantumlascii',
    'type': 'beautifier',
    'syntaxes': ['plantuml'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/java.exe',
    'executable_path': '/path/to/bin/plantuml.jar',
    'args': None,
    'comment': 'No config, use "args" instead. Omit "interpreter_path" if java already on PATH. Tips: enable "layout" + "new_file_on_format" in Formatter settings for dual-panes-view.'
}


class PlantumlasciiFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type=None)
        if not cmd:
            return None

        cmd[1:1] = ['-jar']

        cmd.extend(['-pipe', '-failfast2', '-tutxt'])

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
