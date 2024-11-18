import time
from datetime import datetime, timezone

from ..core import Module, log
from ..libs.dateutil.parser import parse

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf TIMESTAMP (encode)',
    'uid': 'sfunixtimestampenc',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--units', 'sec', '--utc', True, '--show_datetime', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. Set "--units" to "sec", "millisec", "microsec", "nanosec".'
}


class SfunixtimestampencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            units = args.get('--units', 'sec')
            utc = args.get('--utc', True)
            show_datetime = args.get('--show_datetime', True)

            dt = parse(text)

            if utc:
                dt = dt.replace(tzinfo=timezone.utc)
                timestamp = dt.timestamp()
            else:
                timestamp = time.mktime(dt.timetuple())

            x = {
                'sec': 1,
                'millisec': 1_000,
                'microsec': 1_000_000,
                'nanosec': 1_000_000_000
            }
            timestamp *= x.get(units, 1)

            timestamp_int = int(timestamp)

            if show_datetime:
                out_dt = datetime.fromtimestamp(timestamp_int, tz=timezone.utc)
                out_str = out_dt.strftime('%a %d %B %Y %H:%M:%S %Z')
                return '%d (%s)' % (timestamp_int, out_str)
            else:
                return str(timestamp_int)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
