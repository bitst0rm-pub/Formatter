from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf BASE (encode)',
    'uid': 'sfbaseenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--radix', 36],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. "--radix" must be between 2 and 36.'
}


class SfbaseencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def int_to_base(self, number, base):
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"
        if number == 0:
            return digits[0]

        result = []
        while number > 0:
            result.append(digits[number % base])
            number //= base
        result.reverse()
        return ''.join(result)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            radix = args.get('--radix', 36)

            if not (2 <= radix <= 36):
                raise ValueError('Invalid radix value; --radix argument must be between 2 and 36.')

            return self.int_to_base(int(text), radix)
        except Exception as e:
            log.status('File not formatted due to error: "%s"', e)

        return None
