from datetime import datetime, timezone

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf TIMESTAMP (decode)',
    'uid': 'sfunixtimestampdec',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--unit', 'sec', '--show_as_utc', True, '--format', '%a %d %B %Y %H:%M:%S %z'],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. Set "--unit" to "sec", "millisec", "microsec", "nanosec".'
}


class SfunixtimestampdecFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            unit = args.get('--unit', 'sec')
            show_as_utc = args.get('--show_as_utc', True)
            fmt = args.get('--format', '%a %d %B %Y %H:%M:%S %z')

            try:
                timestamp = int(text)
            except ValueError:
                raise ValueError('Invalid timestamp format: %s' % text)

            scale = {
                'sec': 1,
                'millisec': 1_000,
                'microsec': 1_000_000,
                'nanosec': 1_000_000_000
            }
            timestamp /= scale.get(unit, 1)

            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)

            if not show_as_utc:
                local_time = datetime.now().astimezone().utcoffset()
                local_timezone = timezone(local_time)
                dt = dt.astimezone(local_timezone)

            tz_info = dt.strftime('%z')
            tz_info = 'UTC%s:%s' % (tz_info[:3], tz_info[3:])

            if '%Z' in fmt or '%z' in fmt:
                return dt.strftime(fmt.replace('%Z', '').replace('%z', '')) + tz_info
            else:
                return dt.strftime(fmt)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
