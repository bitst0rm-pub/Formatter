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
    'args': ['--length', 20, '--separator', '-', '--separator_every', 6, '--format', 'lower,upper,digit,special'],
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
            length = int(args.get('--length', 20))
            if length <= 0:
                raise ValueError('Length must be a positive integer.')
            separator = args.get('--separator', '-') or ''
            separator_every = int(args.get('--separator_every', 6))
            format_flags = [flag.strip().lower() for flag in args.get('--format', '').split(',')]

            char_set = self.build_charset(format_flags)

            # Calculate how many separators will be added
            num_separators = (length - 1) // separator_every if separator else 0

            # Adjust the length of the random string to account for separators
            adjusted_length = length - num_separators

            if adjusted_length < 0:
                raise ValueError("Adjusted length cannot be negative. Please adjust the input parameters.")

            # Generate the random string
            random_string = ''.join(random.choice(char_set) for _ in range(adjusted_length))

            if not separator:
                return random_string

            # Insert separators into the generated random string
            final_result = self.insert_separators(random_string, separator, separator_every)

            # Ensure the final length matches the requested length
            while len(final_result) < length:
                # If length is still less, add random characters until it matches
                final_result += random.choice(char_set)

            return final_result[:length]
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
