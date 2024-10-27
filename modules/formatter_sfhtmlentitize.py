from html.entities import codepoint2name

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf HTML (entitize)',
    'uid': 'sfhtmlentitize',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--codename', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfhtmlentitizeFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            use_named_entities = args.get('--codename', True) is True

            def to_html_entity(char):
                codepoint = ord(char)

                if codepoint in codepoint2name:
                    if use_named_entities:
                        return '&%s;' % codepoint2name[codepoint]
                    else:
                        return '&#%s;' % codepoint
                else:
                    return char

            return ''.join(to_html_entity(char) for char in text)
        except Exception as e:
            log.status('File not formatted due to error: %s', e)

        return None
