import re
from datetime import datetime, timedelta, timezone

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
    'args': ['--unit', 'sec', '--current_time', False, '--show_datetime', True, '--show_as_utc', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead. Set "--unit" to "sec", "millisec", "microsec", "nanosec".'
}


class SfunixtimestampencFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format(self):
        try:
            text = self.get_text_from_region(self.region).strip()
            args = self.parse_args(convert=True)
            unit = args.get('--units', 'sec')
            current_time = args.get('--current_time', False)
            show_datetime = args.get('--show_datetime', True)
            show_as_utc = args.get('--show_as_utc', True)

            if current_time:
                dt = datetime.now(timezone.utc)
            else:
                dt = parse(text)
                iso_format = dt.isoformat()

                match = re.search(r'([+-])(\d{2}):(\d{2})', iso_format)
                if match:  # extract timezone
                    sign = match.group(1)
                    hours_offset = int(match.group(2))
                    minutes_offset = int(match.group(3))

                    if sign == '+':
                        hours_offset = -hours_offset
                        minutes_offset = -minutes_offset
                    elif sign == '-':
                        hours_offset = +hours_offset
                        minutes_offset = +minutes_offset

                    tz_offset = timezone(timedelta(hours=hours_offset, minutes=minutes_offset))
                    dt = dt.replace(tzinfo=tz_offset)

            dt_utc = dt.astimezone(timezone.utc)
            timestamp = dt_utc.timestamp()

            dt_local = dt_utc.astimezone(datetime.now().astimezone().tzinfo)

            scale = {
                'sec': 1,
                'millisec': 1_000,
                'microsec': 1_000_000,
                'nanosec': 1_000_000_000
            }
            timestamp *= scale.get(unit, 1)

            if show_datetime:
                datetime_to_show = dt_utc if show_as_utc else dt_local

                tz_info = datetime_to_show.strftime('%z')
                tz_info = 'UTC%s:%s' % (tz_info[:3], tz_info[3:])

                return '%d (%s)' % (timestamp, datetime_to_show.strftime('%a %d %B %Y %H:%M:%S ') + tz_info)
            else:
                return str(timestamp)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
