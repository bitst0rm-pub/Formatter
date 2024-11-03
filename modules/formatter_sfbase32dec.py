import base64

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf BASE32 (decode)',
    'uid': 'sfbase32dec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args".'
}


class Sfbase32decFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            return base64.b32decode(text + '=' * (-len(text) % 8)).decode('utf8')  # padding 8 chars
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
