from ..core import Module, log

EXECUTABLES = ['shellcheck']
DOTFILES = ['.shellcheckrc', 'shellcheckrc']
MODULE_CONFIG = {
    'source': 'https://github.com/koalaman/shellcheck',
    'name': 'ShellCheck',
    'uid': 'shellcheck',
    'type': 'beautifier',
    'syntaxes': ['bash'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/shellcheck',
    'args': None,
    'config_path': {
        'default': 'shellcheck_rc.cfg'
    },
    'comment': 'Limited autofix, no formatting capability.'
}


class ShellcheckFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        executable = self.get_executable(runtime_type=None)
        if not executable:
            return None

        cmd = [executable]

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            cmd.extend(self.build_config(path))

        cmd.extend(['--color=never', '--format', 'diff', '-'])

        return cmd

    def build_config(self, path):
        cmd = []
        enable_values, disable_values = self.parse_config_file(path)

        if enable_values:
            cmd.extend(['--enable', ','.join(enable_values)])
        if disable_values:
            cmd.extend(['--exclude', ','.join(disable_values)])

        return cmd

    def parse_config_file(self, path):
        enable_values = []
        disable_values = []

        with open(path, 'r', encoding='utf-8') as file:
            for line in file:
                stripped_line = line.strip()

                if not stripped_line or stripped_line.startswith('#'):
                    continue

                key, value = stripped_line.split('=', 1)

                if key == 'enable':
                    enable_values.extend(value.split(','))
                elif key == 'disable':
                    disable_values.extend(value.split(','))

        return enable_values, disable_values

    def remove_last_blank_lines(self, text):
        lines = text.split('\n')

        # Remove consecutive blank lines at the end
        while lines and not lines[-1].strip():
            lines.pop()

        return '\n'.join(lines)

    def make_patch(self, a, b):
        '''
        License: Public domain (CC0)
        Isaac Turner 2016/12/05
        File: unifieddiff.py
        Source: https://gist.github.com/noporpoise/16e731849eb1231e86d78f9dfeca3abc

        Get unified string diff between two strings. Trims top two lines.
        Returns empty string if strings are identical.
        '''
        import difflib

        _no_eol = r'\ No newline at end of file'

        diffs = difflib.unified_diff(a.splitlines(True), b.splitlines(True), n=0)
        try:
            _, _ = next(diffs), next(diffs)
        except StopIteration:
            pass
        # diffs = list(diffs); print(diffs)
        return ''.join([d if d[-1] == '\n' else d + '\n' + _no_eol + '\n' for d in diffs])

    def apply_patch(self, s, patch, revert=False):
        '''
        License: Public domain (CC0)
        Isaac Turner 2016/12/05
        File: unifieddiff.py
        Source: https://gist.github.com/noporpoise/16e731849eb1231e86d78f9dfeca3abc

        Apply patch to string s to recover newer string.
        If revert is True, treat s as the newer string, recover older string.
        '''
        import re

        _hdr_pat = re.compile(r'^@@ -(\d+),?(\d+)? \+(\d+),?(\d+)? @@$')

        s = s.splitlines(True)
        p = patch.splitlines(True)
        t = ''
        i = sl = 0
        (midx, sign) = (1, '+') if not revert else (3, '-')
        while i < len(p) and p[i].startswith(('---', '+++')):
            i += 1  # skip header lines
        while i < len(p):
            m = _hdr_pat.match(p[i])
            if not m:
                raise Exception('Bad patch -- regex mismatch [line ' + str(i) + ']')
            length = int(m.group(midx)) - 1 + (m.group(midx + 1) == '0')
            if sl > length or length > len(s):
                raise Exception('Bad patch -- bad line num [line ' + str(i) + ']')
            t += ''.join(s[sl:length])
            sl = length
            i += 1
            while i < len(p) and p[i][0] != '@':
                if i + 1 < len(p) and p[i + 1][0] == '\\':
                    line = p[i][:-1]
                    i += 2
                else:
                    line = p[i]
                    i += 1
                if len(line) > 0:
                    if line[0] == sign or line[0] == ' ':
                        t += line[1:]
                    sl += line[0] != sign
        t += ''.join(s[sl:])
        return t

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            stdout = self.remove_last_blank_lines(stdout)
            text = self.get_text_from_region(self.region)
            out = self.apply_patch(text, stdout)

            if exitcode > 0:
                if stdout:
                    return out
                else:
                    self.print_exiterr(exitcode, stderr)
                    _, stdout, _ = self.exec_cmd([s.replace('diff', 'tty') for s in cmd])
                    log.debug(stdout)
            else:
                return out
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
