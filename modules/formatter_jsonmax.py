import json
import re

import sublime

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'JSON',
    'uid': 'jsonmax',
    'type': 'beautifier',
    'syntaxes': ['json'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': {
        'default': 'jsonmax_rc.json'
    },
    'comment': 'Build-in, no "executable_path". Standard JSON, not superset JSON5 with comments.'
}


class JsonmaxFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def brace_newline(self, result):
        brace_newline = re.compile(r'^(^([ \t]*)(\"[^\"]*\"):)\s*([{])', re.MULTILINE)  # regex from Pretty JSON
        return brace_newline.sub(r'\1\n\2\4', result)

    def bracket_newline(self, result):
        bracket_newline = re.compile(r'^(^([ \t]*)(\"[^\"]*\"):)\s*([\[])', re.MULTILINE)  # regex from Pretty JSON
        return bracket_newline.sub(r'\1\n\2\4', result)

    def keep_arrays_single_line(self, result, max_length, array_bracket_spacing=False):
        def compact_array_content(array_string):
            # Strip leading and trailing whitespace and match brackets
            array_string = array_string.strip()
            if not (array_string.startswith('[') and array_string.endswith(']')):
                return array_string

            # Remove extra spaces/newlines between items
            compacted = re.sub(r'\s*,\s*', ', ', array_string[1:-1].strip())  # clean spaces around commas
            compacted = re.sub(r'\s+', ' ', compacted)  # collapse any remaining whitespace

            if array_bracket_spacing:
                compacted = '[ ' + compacted + ' ]'
            else:
                compacted = '[' + compacted + ']'

            return compacted

        array_pattern = re.compile(r'\[[^\[\]]*\]', re.DOTALL)
        matches = array_pattern.findall(result)

        for match in matches:
            compacted_content = compact_array_content(match)
            if len(compacted_content) <= max_length:
                result = result.replace(match, compacted_content)

        return result

    def format(self):
        options = {'ensure_ascii': False, 'indent': 4}

        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                data = file.read()

            cmd = sublime.decode_value(data)
            log.debug('Command: %s', cmd)

            item_separator = cmd.get('item_separator', ',')
            key_separator = cmd.get('key_separator', ': ')

            if 'separators' in cmd and len(cmd['separators']) == 2:
                item_separator, key_separator = cmd['separators']

            options = {
                'indent': cmd.get('indent', 4),
                'sort_keys': cmd.get('sort_keys', False),
                'skipkeys': cmd.get('skipkeys', False),
                'ensure_ascii': cmd.get('ensure_ascii', False),
                'check_circular': cmd.get('check_circular', True),
                'allow_nan': cmd.get('allow_nan', True),
                'separators': (item_separator, key_separator),
            }

        try:
            text = self.get_text_from_region(self.region)
            obj = json.loads(text)
            result = json.dumps(obj, **options)

            if cmd.get('brace_newline', False):
                result = self.brace_newline(result)

            if cmd.get('bracket_newline', False):
                result = self.bracket_newline(result)

            if cmd.get('keep_arrays_single_line', False):
                result = self.keep_arrays_single_line(
                    result,
                    cmd.get('max_arrays_line_length', 120),
                    cmd.get('array_bracket_spacing', False)
                )

            return result
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
