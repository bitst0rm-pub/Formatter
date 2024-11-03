import binascii

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf HEXDUMP (encode)',
    'uid': 'sfhexdumpenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--width', 16, '--unixformat', True, '--lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfhexdumpencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            width = int(args.get('--width', 16))
            unix_format = args.get('--unixformat', True)
            lower_case = args.get('--lower', True)

            hex_string = binascii.hexlify(text.encode('utf-8')).decode('utf-8')
            hex_string = hex_string if lower_case else hex_string.upper()

            # Ensure hex_string has an even length by padding if needed
            if len(hex_string) % 2 != 0:
                hex_string += '0'

            result = []
            for i in range(0, len(hex_string), width * 2):
                offset = '%08x' % (i // 2)
                hex_bytes = ' '.join(hex_string[j:j + 2] for j in range(i, min(i + width * 2, len(hex_string)), 2))

                ascii_repr = ''
                for j in range(i, min(i + width * 2, len(hex_string)), 2):
                    hex_byte = hex_string[j:j + 2]
                    if len(hex_byte) == 2:
                        char = chr(int(hex_byte, 16))
                        if unix_format:
                            ascii_repr += char if 32 <= ord(char) <= 126 else '.'
                        else:
                            try:
                                ascii_repr += char if char.isprintable() else '.'
                            except Exception:
                                ascii_repr += '.'

                result.append('%s  %-*s  |%s|' % (offset, width * 3, hex_bytes, ascii_repr))

            return '\n'.join(result)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
