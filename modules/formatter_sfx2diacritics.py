import unicodedata

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->Diacritics',
    'uid': 'sfx2diacritics',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--custom_replacements', {'ü': 'ue', 'Ü': 'Ue', 'ä': 'ae', 'Ä': 'Ae', 'ö': 'oe', 'Ö': 'Oe', 'ß': 'ss'}],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class Sfx2diacriticsFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            custom_replacements = args.get('--custom_replacements', {}) or {}

            for char, replacement in custom_replacements.items():
                text = text.replace(char, replacement)

            normalized_text = unicodedata.normalize('NFD', text)

            result = ''.join(
                char for char in normalized_text
                if unicodedata.category(char) != 'Mn'
            )

            return unicodedata.normalize('NFC', result)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
