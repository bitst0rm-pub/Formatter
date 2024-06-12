import logging
from ..libs import yaml
from ..core import common

log = logging.getLogger(__name__)
EXECUTABLES = ['drawio', 'draw.io']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/jgraph/drawio-desktop',
    'name': 'Drawio',
    'uid': 'drawio',
    'type': 'graphic',
    'syntaxes': ['drawio'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/draw.io',
    'args': None,
    'config_path': {
        'default': 'drawio_rc.yaml'
    },
    'comment': 'executable_path for macosx is /Applications/draw.io.app/Contents/MacOS/draw.io, no dark-theme for png.'
}


class DrawioFormatter(common.Module):
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

                # drawio does not have an option to
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

        tmp_file = None
        file = self.view.file_name()
        if file:
            input_file = file
        else:
            tmp_file = self.create_tmp_file()
            input_file = tmp_file

        cmd.extend(['--export', '--format', 'png', '--output', self.get_output_image(), input_file])

        log.debug('Current arguments: %s', cmd)
        cmd = self.fix_cmd(cmd)

        return cmd, tmp_file

    def format(self):
        cmd, tmp_file = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            self.remove_tmp_file(tmp_file)
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

                self.remove_tmp_file(tmp_file)
                return stdout
        except OSError:
            self.print_oserr(cmd)

        self.remove_tmp_file(tmp_file)
        return None
