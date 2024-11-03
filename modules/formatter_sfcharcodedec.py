from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf CHARCODE (decode)',
    'uid': 'sfcharcodedec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--separator', ' ', '--base', 16],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. "--base" must be between 2 and 36.'
}


class SfcharcodedecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            separator = args.get('--separator', ' ') or ' '
            base = args.get('--base', 16)

            if not (2 <= base <= 36):
                raise ValueError('Invalid base; --base argument must be between 2 and 36')

            encoded_chars = text.split(separator)
            decoded_chars = []

            for code in encoded_chars:
                try:
                    decoded_char = chr(int(code, base))
                    decoded_chars.append(decoded_char)
                except ValueError as e:
                    log.debug('Skipping invalid code "%s": %s', code, e)
                    continue

            return ''.join(decoded_chars)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
