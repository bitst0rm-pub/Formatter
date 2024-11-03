import base64
import gzip

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf GZIP (decompress)',
    'uid': 'sfgzipdecompress',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args". Input must be base64 encoded.'
}


class SfgzipdecompressFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()

            decompressed_data = gzip.decompress(base64.b64decode(text + '=' * (-len(text) % 4)))  # padding 4 chars
            return decompressed_data.decode('utf-8')
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
