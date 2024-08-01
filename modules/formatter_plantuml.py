from .. import log
from ..core.common import Module

INTERPRETERS = ['java']
EXECUTABLES = ['plantuml.jar']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/plantuml/plantuml',
    'name': 'Plantuml',
    'uid': 'plantuml',
    'type': 'graphic',
    'syntaxes': ['plantuml'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/java.exe',
    'executable_path': '/path/to/bin/plantuml.jar',
    'args': None,
    'comment': 'requires java on PATH if omit interpreter_path. no config, use args instead.'
}


class PlantumlFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type=None)
        if not cmd:
            return None

        cmd[1:1] = ['-jar']

        cmd.extend(['-pipe', '-failfast2', '-tpng'])

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            outfile = self.get_output_image()
            exitcode, stdout, stderr = self.exec_cmd(cmd, outfile=outfile)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                if self.is_render_extended():
                    try:
                        cmd = self.all_png_to_svg_cmd(cmd)
                        out = outfile.replace('png', 'svg')
                        exitcode, stdout, stderr = self.exec_cmd(cmd, outfile=out)
                        log.debug('Current extended arguments: %s Outfile: %s', cmd, out)
                    except Exception as e:
                        log.error('An error occurred while executing extended cmd: %s Details: %s', cmd, e)

                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
