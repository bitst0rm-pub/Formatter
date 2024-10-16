from ..core import Module

EXECUTABLES = ['clang-format']
DOTFILES = ['.clang-format']
MODULE_CONFIG = {
    'source': 'https://clang.llvm.org/docs/ClangFormat.html',
    'name': 'ClangFormat',
    'uid': 'clangformat',
    'type': 'beautifier',
    'syntaxes': ['c', 'cs', 'c++', 'objc', 'objc++', 'js', 'tsx', 'jsx', 'json', 'java', 'proto', 'protodevel', 'td', 'sv', 'svh', 'v', 'vh', 'glsl'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/clang-format',
    'args': None,
    'config_path': {
        'default': 'clang_format_llvm_rc.yaml'
    },
    'comment': 'Requires clang+llvm-14.0.0-rc1 or newer (clang-format >= 14.0.0).'
}


class ClangformatFormatter(Module):
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
            cmd.extend(['--style=file:' + path])

        extmap = {
            # (sublime, clang)
            'c++': 'cpp',
            'objc': 'm',
            'objc++': 'mm',
            'tsx': 'ts',
            'jsx': 'mjs'
        }
        syntax = self.get_assigned_syntax()
        syntax = extmap.get(syntax, syntax)

        cmd.extend(['--assume-filename=dummy.' + syntax, '--'])

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
