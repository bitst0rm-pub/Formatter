from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf ROMAN NUM (encode)',
    'uid': 'sfromannumeralenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--direct_encode', True, '--separator', ' '],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfromannumeralencFormatter(Module):
    roman_numerals = {
        1: 'I',
        4: 'IV',
        5: 'V',
        9: 'IX',
        10: 'X',
        40: 'XL',
        50: 'L',
        90: 'XC',
        100: 'C',
        400: 'CD',
        500: 'D',
        900: 'CM',
        1000: 'M'
    }

    roman_values = sorted(roman_numerals.keys(), reverse=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_roman(self, decimal):
        result = ''
        for value in self.roman_values:
            while decimal >= value:
                result += self.roman_numerals[value]
                decimal -= value
        return result

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            direct_encode = args.get('--direct_encode', True)
            separator = args.get('--separator', ' ') or ' '

            if direct_encode:
                try:
                    decimal_values = map(int, text.split(separator))
                    roman_numerals = [self.to_roman(decimal) for decimal in decimal_values]
                    return separator.join(roman_numerals)
                except ValueError:
                    raise ValueError('Direct encoding failed: input contains non-integer values')
            else:
                roman_numerals = []
                for char in text:
                    ascii_value = ord(char)
                    roman_numeral = self.to_roman(ascii_value)
                    roman_numerals.append(roman_numeral)

                return separator.join(roman_numerals)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)
            return None
