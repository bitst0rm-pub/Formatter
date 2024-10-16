from ..core import Module, log
from ..libs import yaml

EXECUTABLES = ['d2']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/terrastruct/d2',
    'name': 'D2',
    'uid': 'd2',
    'type': 'graphic',
    'syntaxes': ['d2'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/d2',
    'args': None,
    'config_path': {
        'default': 'd2_rc.yaml'
    },
    'comment': 'Uses headless browser to convert images; no dark theme for PNG.'
}


class D2Formatter(Module):
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
            with open(path, 'r', encoding='utf-8') as file:
                cfg_dict = yaml.safe_load(file)

                # d2 does not have an option to
                # read external config file. We build one.
                flattened_list = []
                for key, value in cfg_dict.items():
                    if isinstance(value, bool):
                        if value:
                            flattened_list.extend(['--' + key])
                        else:
                            continue
                    else:
                        flattened_list.extend(['--' + key, str(value).lower()])

                cmd.extend(flattened_list)

        cmd.extend(['-', self.get_output_image()])

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
                        cmd = self.ext_png_to_svg_cmd(cmd)
                        self.exec_cmd(cmd)
                        log.debug('Current extended arguments: %s', cmd)
                    except Exception as e:
                        log.error('Error while executing extended cmd: %s Details: %s', cmd, e)

                return stdout
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
