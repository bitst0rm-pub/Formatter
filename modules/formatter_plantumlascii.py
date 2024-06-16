import logging
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['java']
EXECUTABLES = ['plantuml.jar']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/plantuml/plantuml',
    'name': 'Plantuml ASCII',
    'uid': 'plantumlascii',
    'type': 'beautifier',
    'syntaxes': ['plantuml'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/java.exe',
    'executable_path': '/path/to/bin/plantuml.jar',
    'args': None,
    'comment': 'requires java on PATH if omit interpreter_path. no config, use "args" instead. tips: enable "layout" in Formatter settings for dual-panes-view.'
}


class PlantumlasciiFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type=None)
        if not cmd:
            return None

        cmd[1:1] = ['-jar']

        cmd.extend(['-pipe', '-failfast2', '-tutxt'])

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
