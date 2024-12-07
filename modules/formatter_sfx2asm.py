from os.path import abspath, join

from ..core import Module

INTERPRETERS = ['node']
DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->ASM',
    'uid': 'sfx2asm',
    'type': 'converter',
    'syntaxes': ['*'],
    'interpreter_path': ['/path/to/node'],
    'executable_path': None,
    'args': ['--arch', 'arm', '--mode', 'arm,v8', '--endian', 'little', '--offset', '0x10000', '--bytes_per_line', 24, '--uppercase', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", requires node as "interpreter_path". Set "--arch" to "arm", "arm64", "x86". Set "--mode" to "16", "32", "64", "arm", "thumb", "v8". Set "--endian" to "little", "big".'
}


class Sfx2asmFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        interpreter = self.get_interpreter()
        if not interpreter:
            return None

        script = join(abspath(join(__file__, '../../')), 'libs', 'stone', 'keystone', 'asm.mjs')

        cmd = [interpreter, script]
        cmd.extend(self.get_args())

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
