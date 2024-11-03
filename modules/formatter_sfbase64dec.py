import base64

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf BASE64 (decode)',
    'uid': 'sfbase64dec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args".'
}


class Sfbase64decFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            return base64.b64decode(text + '=' * (-len(text) % 4)).decode('utf8')  # padding 4 chars
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
