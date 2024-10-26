import binascii

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf HEXSTR->STR',
    'uid': 'sfhex2str',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args".'
}


class Sfhex2strFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)

            cleaned_hex = ''
            for char in text:
                if char in '0123456789abcdefABCDEF':
                    cleaned_hex += char

            if len(cleaned_hex) % 2 != 0:
                log.error('Input hex string must have an even length.')
                return None

            return binascii.unhexlify(cleaned_hex).decode('utf-8')
        except Exception as e:
            log.status('File not formatted due to error: "%s"', e)

        return None