from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf DECIMAL (decode)',
    'uid': 'sfdecimaldec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--separator', ' ', '--signed', False],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfdecimaldecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            separator = args.get('--separator', ' ') or ' '
            signed = args.get('--signed', False)

            encoded_chars = text.split(separator)
            decoded_bytes = []

            for code in encoded_chars:
                try:
                    value = int(code)
                    if signed and value < 0:
                        value += 256

                    # Ensure the value is within byte range (0-255)
                    if value < 0 or value > 255:
                        continue

                    decoded_bytes.append(value)
                except ValueError as e:
                    log.debug('Skipping invalid code "%s": %s', code, e)
                    continue

            return bytes(decoded_bytes).decode('utf-8', errors='ignore')
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
