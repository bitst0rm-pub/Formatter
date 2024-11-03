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
    'args': ['--lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class Sfx2crc32Formatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            crc = binascii.crc32(text.encode('utf-8')) & 0xffffffff
            return format(crc, '08x' if args.get('--lower', True) else '08X')
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
