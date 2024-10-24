import binascii

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->HEX',
    'uid': 'sfx2hex',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path". Use "args" with "lower" true for lowercase or UPPERCASE if false.'
}


class Sfx2hexFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.get_args()
            t = binascii.hexlify(text.encode('utf-8')).decode('utf-8')
            return t if args and len(args) == 2 and args[0] == 'lower' and args[1].lower() == 'true' else t.upper()
        except ValueError as e:
            log.status('File not formatted due to ValueError: "%s"', e)

        return None
