import binascii

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf HEXSTR->STR',
    'uid': 'sfhex2str',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args".'
}


class Sfhex2strFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            return binascii.unhexlify(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            log.status('File not formatted due to error: "%s"', e)

        return None
