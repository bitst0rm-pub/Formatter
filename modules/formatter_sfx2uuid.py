from uuid import NAMESPACE_DNS, uuid1, uuid3, uuid4, uuid5

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf X->UUID',
    'uid': 'sfx2uuid',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--mode', 'uuid4', '--lower', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. Set "--mode" to "uuid1", "uuid3", "uuid4", "uuid5". Current text used as input for uuid3 and uuid5.'
}


class Sfx2uuidFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            mode = args.get('--mode', 'uuid4')
            lower = args.get('--lower', True)

            if mode == 'uuid1':
                result = str(uuid1())
            elif mode == 'uuid3':
                result = str(uuid3(NAMESPACE_DNS, text))
            elif mode == 'uuid4':
                result = str(uuid4())
            elif mode == 'uuid5':
                result = str(uuid5(NAMESPACE_DNS, text))
            else:
                raise ValueError('Invalid UUID mode: %s' % mode)

            return result if lower else result.upper()
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
