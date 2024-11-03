import binascii
import re

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf HEXDUMP (decode)',
    'uid': 'sfhexdumpdec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args".'
}


class SfhexdumpdecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            hex_pairs = re.findall(r'\b([0-9A-Fa-f]{2})\b', text)
            hex_string = ''.join(hex_pairs)
            byte_array = binascii.unhexlify(hex_string)
            return byte_array.decode('utf-8', errors='ignore')
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
