from ..core import Module

EXECUTABLES = ['ocp-indent']
DOTFILES = ['.ocp-indent', 'ocp-indent.conf']
MODULE_CONFIG = {
    'source': 'https://github.com/OCamlPro/ocp-indent',
    'name': 'OCPIndent',
    'uid': 'ocpindent',
    'type': 'beautifier',
    'syntaxes': ['ocaml', 'ocamlyacc', 'ocamllex'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/ocp-indent',
    'args': None,
    'config_path': {
        'default': 'ocpindent_rc.cfg'
    }
}


class OcpindentFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def parse_config(self, path):
        # OCP-indent CLI does not have an option to
        # read external config file. We build one.
        config = []
        with open(path, 'r', encoding='utf-8') as file:
            for line in file:
                original_line = line.strip()
                line_parts = original_line.split('#', 1)
                line = line_parts[0].strip()  # Extract key-value pair, ignoring comments
                if line:
                    if '=' in line:
                        key, value = map(str.strip, line.split('='))
                        config.append(key + '=' + value)
                    else:
                        config.append(line)

        return ','.join(config)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', self.parse_config(path)])

        cmd.extend(['--'])

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
