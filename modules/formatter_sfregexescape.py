from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf REGEX (escape)',
    'uid': 'sfregexescape',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args". To escape special chars within regex pattern.'
}


class SfregexescapeFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            special_chars = r'^$.*\\+?{}[]|()'
            return ''.join(('\\' + char) if char in special_chars else char for char in text)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
