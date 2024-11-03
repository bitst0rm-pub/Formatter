from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf DECIMAL (encode)',
    'uid': 'sfdecimalenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--separator', ' ', '--signed', False],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfdecimalencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            separator = args.get('--separator', ' ') or ' '
            signed = args.get('--signed', False)

            encoded_chars = []
            for char in text:
                byte_sequence = char.encode('utf-8')
                for byte in byte_sequence:
                    if signed and byte > 127:
                        encoded_char = '%d' % (byte - 256)
                    else:
                        encoded_char = '%d' % byte

                    encoded_chars.append(encoded_char)

            return separator.join(encoded_chars)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
