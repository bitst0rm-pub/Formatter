import json
import sublime
from .. import log
from ..core import common

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'JSON',
    'uid': 'jsonmin',
    'type': 'minifier',
    'syntaxes': ['json'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'build-in, no executable, no config. json not json5 with comments.'
}


class JsonminFormatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            obj = json.loads(text)
            result = json.dumps(obj, ensure_ascii=False, separators=(',', ':'), indent=None)
            return result
        except ValueError as err:
            log.status('File not formatted due to ValueError: "%s"', err)

        return None
