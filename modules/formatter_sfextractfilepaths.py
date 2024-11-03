import re

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf FILEPATHS (extract)',
    'uid': 'sfextractfilepaths',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--windows', True, '--unix', True, '--sort', False, '--unique', False],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. It is not possible to cover all edge cases.'
}


class SfextractfilepathsFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            windows = args.get('--windows', True)
            unix = args.get('--unix', True)
            sort = args.get('--sort', False)
            unique = args.get('--unique', False)

            win_pattern = r'(?:[a-zA-Z]:\\(?:[^<>:"/\\|?*\x00-\x1F]+\\)*[^<>:\s"/\\|?*\x00-\x1F]*\.?[^<>:\s"/\\|?*\x00-\x1F]*)?'
            unix_pattern = r'(?:~(?:\/(?:[^\/<>:"\\|?*\x00-\x1F]+\/)*[^\/<>:\s"/\\|?*\x00-\x1F]*\.?[^\/<>:\s"/\\|?*\x00-\x1F]*)?|\/(?:[^\/<>:"\\|?*\x00-\x1F]+\/)*[^\/<>:\s"/\\|?*\x00-\x1F]*\.?[^\/<>:\s"/\\|?*\x00-\x1F]*)?'

            if windows and unix:
                regex_pattern = '(' + win_pattern + ')|(' + unix_pattern + ')'
            elif windows:
                regex_pattern = win_pattern
            elif unix:
                regex_pattern = unix_pattern
            else:
                raise ValueError('No valid command argument.')

            regex = re.compile(regex_pattern, re.IGNORECASE)
            extracted = []
            for match in regex.findall(text):
                if windows and unix:
                    if match[0]:
                        extracted.append(match[0])
                    if match[1] and match[1] != '/':
                        extracted.append(match[1])
                elif windows:
                    if match:
                        extracted.append(match)
                elif unix:
                    if match and match != '/':
                        extracted.append(match)

            if unique:
                extracted = self.get_unique(extracted)

            if sort:
                extracted.sort()

            return '\n'.join(extracted)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
