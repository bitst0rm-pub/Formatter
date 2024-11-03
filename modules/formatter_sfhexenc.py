import binascii

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf HEX (encode)',
    'uid': 'sfhexenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--prefix', '\\x', '--separator', ' ', '--bytes_per_line', 0, '--lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfhexencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            prefix = args.get('--prefix', '\\x')
            separator = args.get('--separator', ' ') or ''
            bytes_per_line = args.get('--bytes_per_line', 0)
            lower_case = args.get('--lower', True)

            hex_text = binascii.hexlify(text.encode('utf-8')).decode('utf-8')
            hex_text = hex_text if lower_case else hex_text.upper()

            output_lines = []
            current_line = []

            for i in range(0, len(hex_text), 2):
                byte_hex = prefix + hex_text[i:i + 2]
                current_line.append(byte_hex)

                if len(current_line) == bytes_per_line:
                    output_lines.append(separator.join(current_line) + separator)
                    current_line = []

            if current_line:
                output_lines.append(separator.join(current_line) + separator)

            return '\n'.join(output_lines).rstrip(separator)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
