import re

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf DATES (extract)',
    'uid': 'sfextractdates',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--sort', False, '--unique', False],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfextractdatesFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            sort = args.get('--sort', False)
            unique = args.get('--unique', False)

            date1 = r'(?:19|20)\d\d[- /.](?:0[1-9]|1[012])[- /.](?:0[1-9]|[12][0-9]|3[01])'  # yyyy-mm-dd
            date2 = r'(?:0[1-9]|[12][0-9]|3[01])[- /.](?:0[1-9]|1[012])[- /.](?:19|20)\d\d'  # dd/mm/yyyy
            date3 = r'(?:0[1-9]|1[012])[- /.](?:0[1-9]|[12][0-9]|3[01])[- /.](?:19|20)\d\d'  # mm/dd/yyyy

            regex_pattern = date1 + '|' + date2 + '|' + date3
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
