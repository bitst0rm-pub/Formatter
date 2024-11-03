import re

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf IP (extract)',
    'uid': 'sfextractipaddr',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--ipv4', True, '--ipv6', False, '--remove_local_ipv4', False, '--sort', False, '--unique', False],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path", use "args" instead.'
}


class SfextractipaddrFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def is_local_ipv4(self, ip):
        try:
            octets = list(map(int, ip.split('.')))
            if len(octets) != 4:
                return False

            return (
                octets[0] == 127 or                              # 127.0.0.1
                (octets[0] == 10) or                             # 10.0.0.0/8
                (octets[0] == 172 and 16 <= octets[1] <= 31) or  # 172.16.0.0/12
                (octets[0] == 192 and octets[1] == 168)          # 192.168.0.0/16
            )
        except ValueError:
            return False

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            ipv4 = args.get('--ipv4', True)
            ipv6 = args.get('--ipv6', False)
            remove_local_ipv4 = args.get('--remove_local_ipv4', False)
            sort = args.get('--sort', False)
            unique = args.get('--unique', False)

            ipv4_regex = re.compile(r'(?<!\d|\.)\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b(?!\.\d)')

            # https://nbviewer.org/github/rasbt/python_reference/blob/master/tutorials/useful_regex.ipynb
            # Regex from: https://snipplr.com/view/43003/regex--match-ipv6-address
            ipv6_regex = re.compile(r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?')

            extracted_ips = []

            if ipv4:
                extracted_ips.extend(ipv4_regex.findall(text))

            if ipv6:
                extracted_ips.extend([match[0] for match in ipv6_regex.findall(text) if match[0]])

            if remove_local_ipv4:
                extracted_ips = [ip for ip in extracted_ips if not self.is_local_ipv4(ip)]

            if unique:
                extracted_ips = self.get_unique(extracted_ips)

            if sort:
                extracted_ips.sort()

            return '\n'.join(extracted_ips)
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)

        return None
