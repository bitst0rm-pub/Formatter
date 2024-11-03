import sublime

from ..core import Module, log
from ..libs import yaml

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'YAML',
    'uid': 'yamlmax',
    'type': 'beautifier',
    'syntaxes': ['yaml'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': {
        'default': 'yamlmax_rc.json'
    },
    'comment': 'Build-in, no "executable_path".'
}


class YamlmaxFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        cmd = {}

        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                data = file.read()

            cmd = sublime.decode_value(data)
            log.debug('Command: %s', cmd)

        try:
            text = self.get_text_from_region(self.region)
            obj = yaml.safe_load(text)
            result = yaml.dump(obj, **cmd)

            return result
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
