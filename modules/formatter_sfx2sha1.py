import hashlib

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->SHA1',
    'uid': 'sfx2sha1',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class Sfx2sha1Formatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            t = hashlib.sha1(text.encode('utf-8')).hexdigest()
            return t if args.get('--lower', True) else t.upper()
        except Exception as e:
            log.status('File not formatted due to error: %s', e)

        return None
