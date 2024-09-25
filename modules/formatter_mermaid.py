from ..core import Module, log

EXECUTABLES = ['mmdc']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/mermaid-js/mermaid-cli',
    'name': 'Mermaid',
    'uid': 'mermaid',
    'type': 'graphic',
    'syntaxes': ['mermaid'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/mmdc',
    'args': ['--width', '800', '--height', '600', '--backgroundColor', 'white'],
    'config_path': {
        'default': 'mermaid_rc.json'
    }
}


class MermaidFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--configFile', path])

        cmd.extend(['--input', '-', '--outputFormat', 'png', '--output', self.get_output_image()])

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                if self.is_render_extended():
                    try:
                        cmd = self.all_png_to_svg_cmd(cmd)
                        self.exec_cmd(cmd)
                        log.debug('Current extended arguments: %s', cmd)
                    except Exception as e:
                        log.error('Error while executing extended cmd: %s Details: %s', cmd, e)

                return stdout
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
