from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf CHARCODE (encode)',
    'uid': 'sfcharcodeenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--separator', ' ', '--base', 16, '--lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. "--base" must be between 2 and 36.'
}


class SfcharcodeencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_base_n(self, number, base, lower_case=True):
        if number == 0:
            return '0'

        digits = "0123456789abcdefghijklmnopqrstuvwxyz" if lower_case else "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if base > len(digits):
            raise ValueError('Base too large; --base argument must be between 2 and 36')

        result = []

        while number > 0:
            result.append(digits[number % base])
            number //= base

        return ''.join(reversed(result))

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            separator = args.get('--separator', ' ') or ' '
            base = args.get('--base', 16)
            lower_case = args.get('--lower', True)

            if not (2 <= base <= 36):
                raise ValueError('Invalid base; --base argument must be between 2 and 36')

            encoded_chars = []
            for char in text:
                codepoint = ord(char)
                if base in (16, 10):
                    encoded_char = ('%x' if lower_case else '%X') % codepoint if base == 16 else '%d' % codepoint
                else:
                    encoded_char = self.to_base_n(codepoint, base, lower_case)
                encoded_chars.append(encoded_char)

            return separator.join(encoded_chars)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
