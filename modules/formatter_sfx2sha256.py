import hashlib

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->SHA256',
    'uid': 'sfx2sha256',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path". Use "args" with "lower" true for lowercase or false for UPPERCASE.'
}


class Sfx2sha256Formatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.get_args()
            t = hashlib.sha256(text.encode('utf-8')).hexdigest()
            return t if args and len(args) == 2 and args[0] == 'lower' and args[1].lower() == 'true' else t.upper()
        except Exception as e:
            log.status('File not formatted due to error: "%s"', e)

        return None
