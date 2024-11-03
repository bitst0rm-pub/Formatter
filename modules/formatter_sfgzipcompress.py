import base64
import gzip

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf GZIP (compress)',
    'uid': 'sfgzipcompress',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args". Output is base64 encoded.'
}


class SfgzipcompressFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()

            compressed_data = gzip.compress(text.encode('utf-8'))
            return base64.b64encode(compressed_data).decode('ascii')
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
