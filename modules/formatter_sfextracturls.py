import re

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf URLS (extract)',
    'uid': 'sfextracturls',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--url_only', True, '--domain_only', False, '--sort', False, '--unique', False],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfextracturlsFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            url_only = args.get('--url_only', True)
            domain_only = args.get('--domain_only', False)
            sort = args.get('--sort', False)
            unique = args.get('--unique', False)

            if url_only:
                regex_pattern = r'[A-Z]+://[-\w]+(?:\.\w[-\w]*)+(?::\d+)?(?:/[^.!?,"\'<>[\]{}\s\x7F-\xFF]*(?:[.!?,]+[^.!?,"\'<>[\]{}\s\x7F-\xFF]+)*)?'
            elif domain_only:
                regex_pattern = r'\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,})\b'
            else:
                raise ValueError('No extraction option selected. Please set either --url_only or --domain_only.')

            regex = re.compile(regex_pattern, re.IGNORECASE)
            extracted = regex.findall(text)

            if unique:
                extracted = self.get_unique(extracted)

            if sort:
                extracted.sort()

            return '\n'.join(extracted)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
