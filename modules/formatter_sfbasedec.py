from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf BASE (decode)',
    'uid': 'sfbasedec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--radix', 16],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. "--radix" must be between 2 and 36.'
}


class SfbasedecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            radix = args.get('--radix', 16)

            if not (2 <= radix <= 36):
                raise ValueError('Invalid radix value; --radix argument must be between 2 and 36.')

            result = int(text, radix)
            if result is None:
                return None

            return str(result)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
