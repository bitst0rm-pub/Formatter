from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf OCTAL (encode)',
    'uid': 'sfoctalenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--separator', ' '],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfoctalencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            separator = args.get('--separator', ' ') or ' '

            octal_strings = []
            utf8_bytes = text.encode('utf-8')

            for byte in utf8_bytes:
                octal_char = format(byte, 'o')
                octal_strings.append(octal_char)

            return separator.join(octal_strings)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
