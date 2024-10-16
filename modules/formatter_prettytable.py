import sublime

from ..core import Module, log
from ..libs.prettytable import prettytable

DOTFILES = []
MODULE_CONFIG = {
    'source': 'https://github.com/jazzband/prettytable',
    'name': 'PrettyTable',
    'uid': 'prettytable',
    'type': 'beautifier',
    'syntaxes': ['csv', 'text'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': {
        'default': 'prettytable_rc.json'
    },
    'comment': 'Build-in, no "executable_path".'
}


class PrettytableFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def read_data(self, text, sep):
        lines = text.splitlines()
        for line in lines:
            yield line.split(sep)

    def make_table(self, data):
        table = prettytable.PrettyTable()
        table.field_names = next(data)

        for row in data:
            if len(row) != len(table.field_names):
                continue
            table.add_row(row)

        return table

    def format(self):
        path = self.get_config_path()
        json = {}
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                data = file.read()
            json = sublime.decode_value(data)
            log.debug('Command: %s', json)

        style = json.get('style', None)
        separator = json.get('separator', None)
        align = json.get('align', None)
        output_format = json.get('output_format', 'text')

        stylemap = [
            ('ALL', prettytable.ALL),
            ('DEFAULT', prettytable.DEFAULT),
            ('DOUBLE_BORDER', prettytable.DOUBLE_BORDER),
            ('FRAME', prettytable.FRAME),
            ('HEADER', prettytable.HEADER),
            ('MARKDOWN', prettytable.MARKDOWN),
            ('MSWORD_FRIENDLY', prettytable.MSWORD_FRIENDLY),
            ('NONE', prettytable.NONE),
            ('ORGMODE', prettytable.ORGMODE),
            ('PLAIN_COLUMNS', prettytable.PLAIN_COLUMNS),
            ('RANDOM', prettytable.RANDOM),
            ('SINGLE_BORDER', prettytable.SINGLE_BORDER)
        ]

        sty = prettytable.DEFAULT
        for name, value in stylemap:
            if name.lower() == style.lower():
                sty = value
                break

        text = self.get_text_from_region(self.region)
        data = self.read_data(text, separator)
        table = self.make_table(data)
        table.set_style(sty)
        table.align = align

        out = table.get_formatted_string(output_format)
        if out:
            return out
        else:
            log.status('File not formatted due to an error.')
        return None
