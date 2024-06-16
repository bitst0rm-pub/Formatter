# @install      https://scrossoracle.medium.com/building-graphviz-from-source-on-macos-b6a846d73949

import logging
from ..libs import yaml
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['dot']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://gitlab.com/graphviz/graphviz',
    'name': 'Graphviz',
    'uid': 'graphviz',
    'type': 'graphic',
    'syntaxes': ['graphviz'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/dot',
    'args': None,
    'config_path': {
        'default': 'graphviz_rc.yaml'
    },
}


class GraphvizFormatter(common.Module):
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

                # graphviz does not have an option to
                # read external config file. We build one.
                flattened_list = []
                for key, value in cfg_dict.items():
                    if value:
                        if isinstance(value, bool):
                            flattened_list.append('-' + key)
                        else:
                            flattened_list.append('-' + key + '=' + str(value))

                cmd.extend(flattened_list)

        cmd.extend(['-Tpng', '-o', self.get_output_image()])

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
                if self.is_render_extended():
                    try:
                        cmd = self.all_png_to_svg_cmd(cmd)
                        self.exec_cmd(cmd)
                        log.debug('Current extended arguments: %s', cmd)
                    except Exception as e:
                        log.error('An error occurred while executing extended cmd: %s Details: %s', cmd, e)

                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
