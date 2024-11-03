from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf BINARY (encode)',
    'uid': 'sfbinaryenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--byte_length', 8, '--separator', ' '],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfbinaryencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            byte_length = args.get('--byte_length', 8)
            separator = args.get('--separator', ' ') or ''

            binary_strings = []
            utf8_bytes = text.encode('utf-8')

            for byte in utf8_bytes:
                binary_char = format(byte, '0{}b'.format(byte_length))
                if len(binary_char) > byte_length:
                    binary_char = binary_char[-byte_length:]

                binary_strings.append(binary_char)

            return separator.join(binary_strings)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
