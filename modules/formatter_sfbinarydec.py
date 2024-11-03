from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf BINARY (decode)',
    'uid': 'sfbinarydec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--byte_length', 8, '--separator', ' '],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfbinarydecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            byte_length = args.get('--byte_length', 8)
            separator = args.get('--separator', ' ') or ''

            binary_strings = text.split(separator)
            decoded_bytes = []

            for binary_string in binary_strings:
                if len(binary_string) == byte_length:
                    byte_value = int(binary_string, 2)
                    decoded_bytes.append(byte_value)
                else:
                    raise ValueError('Binary string has incorrect length: "%s"' % binary_string)

            return bytes(decoded_bytes).decode('utf-8')
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
