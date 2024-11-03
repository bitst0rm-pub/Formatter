from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf ROMAN NUM (decode)',
    'uid': 'sfromannumeraldec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--direct_decode', True, '--separator', ' '],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfromannumeraldecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.roman_numerals = {
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

    def interpret_roman(self, content):
        decimal = 0
        previous_highest_roman_numeral = 1001
        error = False

        while content and not error:
            highest_roman_numeral = 0

            for roman_value, roman_char in self.roman_numerals.items():
                if content.startswith(roman_char):
                    highest_roman_numeral = max(highest_roman_numeral, roman_value)

            if highest_roman_numeral and highest_roman_numeral <= previous_highest_roman_numeral:
                decimal += highest_roman_numeral
                content = content[len(self.roman_numerals[highest_roman_numeral]):]
                previous_highest_roman_numeral = highest_roman_numeral
            else:
                error = True

        return decimal if not error else None

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            direct_decode = args.get('--direct_decode', True)
            separator = args.get('--separator', ' ') or ' '

            roman_numerals = text.split(separator)
            decimal_values = []

            if direct_decode:
                for numeral in roman_numerals:
                    decimal_value = self.interpret_roman(numeral.strip())
                    if decimal_value is not None:
                        decimal_values.append(str(decimal_value))
                    else:
                        raise ValueError('Direct decoding failed: input is not a valid Roman numeral')
                return separator.join(decimal_values)
            else:
                for numeral in roman_numerals:
                    decimal_value = self.interpret_roman(numeral)
                    if decimal_value is not None:
                        decimal_values.append(decimal_value)

                return ''.join(chr(value) for value in decimal_values)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)
            return None
