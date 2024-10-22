import base64

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->BASE64 (decode)',
    'uid': 'sfx2base64dec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args".'
}


class Sfx2base64decFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            return base64.b64decode(text + '=' * (-len(text) % 4)).decode('utf8')  # padding 4 chars
        except ValueError as e:
            log.status('File not formatted due to ValueError: "%s"', e)

        return None
