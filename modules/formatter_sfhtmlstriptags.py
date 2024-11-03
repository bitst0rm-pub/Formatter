from html.parser import HTMLParser

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf HTML (strip tags)',
    'uid': 'sfhtmlstriptags',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--remove_indentation', True, '--remove_excess_line_breaks', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfhtmlstriptagsFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def strip_html_tags(self, text):
        result = []

        def handle_data(data):
            result.append(data)

        parser = HTMLParser()
        parser.handle_data = handle_data
        parser.feed(text)
        return ''.join(result)

    def remove_indentation(self, text):
        return '\n'.join(line.lstrip() for line in text.splitlines())

    def remove_excess_line_breaks(self, text):
        return '\n'.join(line for line in text.splitlines() if line.strip() != '')

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            remove_indentation = args.get('--remove_indentation', True)
            remove_excess_line_breaks = args.get('--remove_excess_line_breaks', True)

            text = self.strip_html_tags(text)
            if remove_indentation:
                text = self.remove_indentation(text)
            if remove_excess_line_breaks:
                text = self.remove_excess_line_breaks(text)

            return text
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
