import json

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf STRING (unescape)',
    'uid': 'sfstringunescape',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--escape_quote', 'double'],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. Set "--escape_quote" to "double" or "single".'
}


class SfstringunescapeFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            escape_quote = args.get('--escape_quote', 'double')

            if escape_quote == 'double':
                output_text = json.loads('"' + text + '"')
            elif escape_quote == 'single':
                output_text = text.replace("\\'", "'")
                output_text = output_text.replace('\\"', '"')
                output_text = output_text.encode().decode('unicode_escape')
            else:
                log.status('Unsupported escape_quote value: %s', escape_quote)
                return None

            return output_text
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
