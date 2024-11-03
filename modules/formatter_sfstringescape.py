import json

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf STRING (escape)',
    'uid': 'sfstringescape',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--escape_quote', 'double'],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. Set "--escape_quote" to "double" or "single".'
}


class SfstringescapeFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            escape_quote = args.get('--escape_quote', 'double')

            escaped_text = json.dumps(text)[1:-1]
            if escape_quote == 'single':
                escaped_text = escaped_text.replace('\\"', '"').replace("'", "\\'")

            return escaped_text
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
