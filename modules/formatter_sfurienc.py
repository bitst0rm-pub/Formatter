from urllib.parse import quote, quote_plus

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf URI (encode)',
    'uid': 'sfurienc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--percent', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path". Use "args" with "--percent" true for %20 or + if false.'
}


class SfuriencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            return quote(text) if args.get('--percent', True) else quote_plus(text)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
