from ..core import Module

EXECUTABLES = ['ocamlformat']
DOTFILES = ['.ocamlformat']
MODULE_CONFIG = {
    'source': 'https://github.com/ocaml-ppx/ocamlformat',
    'name': 'OCamlformat',
    'uid': 'ocamlformat',
    'type': 'beautifier',
    'syntaxes': ['ocaml', 'ocamlyacc', 'ocamllex'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/ocamlformat',
    'args': None,
    'config_path': {
        'default': 'ocamlformat_rc.cfg'
    }
}


class OcamlformatFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def parse_config(self, path):
        # Ocamlformat CLI does not have an option to
        # read external config file. We build one.
        config = []
        with open(path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):  # Ignore empty lines and comments
                    key, value = map(str.strip, line.split('='))
                    config.append(key + '=' + value)

        return ','.join(config)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(['--enable-outside-detected-project'])

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(['--config', self.parse_config(path)])

        p = self.get_pathinfo()['path']
        cmd.extend(['--name', p if p else 'dummy.ml', '-'])

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
