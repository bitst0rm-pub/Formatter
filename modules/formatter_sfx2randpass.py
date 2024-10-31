import random
import string

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->RANDPASS',
    'uid': 'sfx2randpass',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--length', 18, '--separator', '-', '--separator_in_range', 5, '--format', 'lower,upper,digit,special'],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class Sfx2randpassFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def build_charset(self, format_flags):
        char_set = ''
        if 'lower' in format_flags:
            char_set += string.ascii_lowercase
        if 'upper' in format_flags:
            char_set += string.ascii_uppercase
        if 'digit' in format_flags:
            char_set += string.digits
        if 'special' in format_flags:
            char_set += string.punctuation
        return char_set if char_set else string.ascii_letters + string.digits

    def insert_separators(self, text, separator, interval):
        if interval <= 0:
            return text
        return separator.join(text[i:i + interval] for i in range(0, len(text), interval))

    def format(self):
        try:
            # text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            length = int(args.get('--length', 18))
            if length <= 0:
                raise ValueError('Length must be a positive integer.')
            separator = args.get('--separator', '-') or ''
            separator_in_range = int(args.get('--separator_in_range', 5))
            format_flags = args.get('--format', '').split(',')

            char_set = self.build_charset(format_flags)
            random_string = ''.join(random.choice(char_set) for _ in range(length))
            if not separator:
                return random_string
            return self.insert_separators(random_string, separator, separator_in_range)
        except Exception as e:
            log.status('File not formatted due to error: %s', e)

        return None
