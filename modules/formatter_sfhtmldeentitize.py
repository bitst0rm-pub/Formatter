from html.parser import HTMLParser

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf HTML (deentitize)',
    'uid': 'sfhtmldeentitize',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args".'
}


class SfhtmldeentitizeFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            return HTMLParser().unescape(text)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
