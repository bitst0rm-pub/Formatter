import binascii

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->CRC32',
    'uid': 'sfx2crc32',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path". Use "args" with "lower" true for lowercase or false for UPPERCASE.'
}


class Sfx2crc32Formatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.get_args()
            crc = binascii.crc32(text.encode('utf-8')) & 0xffffffff
            return format(crc, '08x' if args and len(args) == 2 and args[0] == 'lower' and args[1].lower() == 'true' else '08X')
        except Exception as e:
            log.status('File not formatted due to error: "%s"', e)

        return None
