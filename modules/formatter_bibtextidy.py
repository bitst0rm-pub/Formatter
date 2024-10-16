from ..core import Module
from ..libs import yaml

INTERPRETERS = ['node']
EXECUTABLES = ['bibtex-tidy']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/FlamingTempura/bibtex-tidy',
    'name': 'BibTeXTidy',
    'uid': 'bibtextidy',
    'type': 'beautifier',
    'syntaxes': ['bibtex'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/node_modules/.bin/bibtex-tidy(.cmd on windows)',
    'args': None,
    'config_path': {
        'default': 'bibtex_tidy_rc.yaml'
    },
    'comment': 'Omit "interpreter_path" as files in /node_modules/.bin/ already point to node.'
}


class BibtextidyFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type='node')
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                cfg_dict = yaml.safe_load(file)

                # bibtex-tidy does not have an option to
                # read external config file. We build one.
                flattened_list = ['--v2', '--no-modify']
                for key, value in cfg_dict.items():
                    if key in ['v2', 'no-modify']:
                        continue
                    if value:
                        if isinstance(value, bool):
                            flattened_list.append('--' + key)
                        elif isinstance(value, int):
                            flattened_list.append('--' + key + '=' + str(value))
                        elif isinstance(value, list):
                            flattened_list.append('--' + key + '=' + ','.join(value))
                        elif isinstance(value, str):
                            flattened_list.append('--' + key + '=' + value)
                    else:
                        if key in ['curly', 'numeric', 'tab', 'align', 'blank-lines', 'sort', 'merge', 'escape', 'strip-comments', 'trailing-commas', 'encode-urls', 'tidy-comments', 'remove-empty-fields', 'remove-dupe-fields', 'wrap']:
                            flattened_list.append('--no-' + key)

                cmd.extend(flattened_list)

        cmd.extend(['-'])

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
