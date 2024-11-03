from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf BRAILLE (encode)',
    'uid': 'sfbrailleenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': None,
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", no "args". For blind people with love.'
}


class SfbrailleencFormatter(Module):
    BRAILLE_LOOKUP = {
        'ascii': ' A1B\'K2L@CIF/MSP"E3H9O6R^DJG>NTQ,*5<-U8V.%[$+X!&;:4\\0Z7(_?W]#Y)=',
        'dot6': '⠀⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓⠔⠕⠖⠗⠘⠙⠚⠛⠜⠝⠞⠟⠠⠡⠢⠣⠤⠥⠦⠧⠨⠩⠪⠫⠬⠭⠮⠯⠰⠱⠲⠳⠴⠵⠶⠷⠸⠹⠺⠻⠼⠽⠾⠿'
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def char_to_braille(self, char):
        idx = self.BRAILLE_LOOKUP['ascii'].find(char.upper())
        if idx >= 0:
            return self.BRAILLE_LOOKUP['dot6'][idx]
        return char

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            return ''.join(self.char_to_braille(c) for c in text)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
