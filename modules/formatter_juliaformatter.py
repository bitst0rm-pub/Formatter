import logging
from ..libs import toml
from ..core import common

log = logging.getLogger(__name__)
INTERPRETERS = ['julia']
EXECUTABLES = []
MODULE_CONFIG = {
    'source': 'https://github.com/domluna/JuliaFormatter.jl',
    'name': 'JuliaFormatter',
    'uid': 'juliaformatter',
    'type': 'beautifier',
    'syntaxes': ['julia'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/julia.exe',
    'args': None,
    'config_path': {
        'default': 'juliaformatter_rc.toml'
    },
    'comment': 'install: julia> using Pkg; Pkg.add("JuliaFormatter"). no executable_path. no args. requires julia on PATH if omit interpreter_path'
}


class JuliaformatterFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        interpreter = self.get_interpreter()
        if not interpreter:
            return None

        text = self.get_text_from_region(self.region)
        config_arg = ''

        path = self.get_config_path()
        if path:
            try:
                config = toml.dumps(toml.load(path))

                processed_lines = []
                for line in config.splitlines():
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        if key == 'style':
                            style_mapping = {
                                'default': 'DefaultStyle()',
                                'blue': 'BlueStyle()',
                                'yas': 'YASStyle()',
                                'sciml': 'SciMLStyle()',
                                'minimal': 'MinimalStyle()'
                            }
                            v = value.strip('\'"')
                            if v in style_mapping:
                                value = style_mapping[v]
                            else:
                                continue
                        processed_lines.append(key + '=' + value)
                    else:
                        processed_lines.append(line)

                config_arg = ', ' + ','.join(processed_lines)
            except Exception as e:
                log.error('Error reading or processing the config file: %s', e)
                return None

        arg = 'using JuliaFormatter; println(format_text(raw"""{}"""{})); exit()'.format(text.replace('"""', '\\"""'), config_arg)

        cmd = [interpreter, '-e', arg]

        log.debug('Current arguments: %s', [interpreter, '-e', 'using JuliaFormatter; println(format_text(raw"""text"""' + config_arg + ')); exit()'])

        return cmd

    def format(self):
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):
            return None

        try:
            exitcode, stdout, stderr = self.exec_com(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except OSError:
            self.print_oserr(cmd)

        return None
