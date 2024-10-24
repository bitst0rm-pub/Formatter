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
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args".'
}


class Sfx2sha256Formatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            return hashlib.sha256(text.encode('utf-8')).hexdigest()
        except Exception as e:
            log.status('File not formatted due to error: "%s"', e)

        return None
