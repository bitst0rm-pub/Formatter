import re

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf REGEX (unescape)',
    'uid': 'sfregexunescape',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args". To unescape special chars within regex pattern.'
}


class SfregexunescapeFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            special_chars = r'^$.*\\+?{}[]|()'
            return re.sub(r'\\([{}])'.format(re.escape(special_chars)), r'\1', text)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
