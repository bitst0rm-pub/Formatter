from urllib.parse import unquote, unquote_plus

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->URI (decode)',
    'uid': 'sfx2uridec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['percent', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path". Use "args" with "percent" true for %20 or + if false.'
}


class Sfx2uridecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.get_args()
            return unquote(text) if args and len(args) == 2 and args[0] == 'percent' and args[1].lower() == 'true' else unquote_plus(text)
        except Exception as e:
            log.status('File not formatted due to error: "%s"', e)

        return None
