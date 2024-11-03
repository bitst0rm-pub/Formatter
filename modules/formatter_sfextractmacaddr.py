import re

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf MAC (extract)',
    'uid': 'sfextractmacaddr',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--sort', False, '--unique', False],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfextractmacaddrFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            sort = args.get('--sort', False)
            unique = args.get('--unique', False)

            regex = re.compile(
                r'[A-F\d]{2}(?:[:-][A-F\d]{2}){5}',
                re.IGNORECASE
            )

            macs = regex.findall(text)

            if unique:
                macs = self.get_unique(macs)

            if sort:
                macs.sort()

            return '\n'.join(macs)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
