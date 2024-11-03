from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf OCTAL (decode)',
    'uid': 'sfoctaldec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--separator', ' '],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfoctaldecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            separator = args.get('--separator', ' ') or ' '

            octal_strings = text.split(separator)
            decoded_bytes = bytearray()

            for octal_string in octal_strings:
                if octal_string:
                    try:
                        byte_value = int(octal_string, 8)
                        decoded_bytes.append(byte_value)
                    except ValueError:
                        raise ValueError('Invalid octal value: "%s"' % octal_string)

            return decoded_bytes.decode('utf-8')
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
