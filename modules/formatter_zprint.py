import re
from os.path import basename

from ..core import Module

INTERPRETERS = ['bb', 'java']
EXECUTABLES = ['zprint-filter', 'zprintma', 'zprintm', 'zprintl', 'zprint']
DOTFILES = ['.zprintrc', '.zprint.edn']
MODULE_CONFIG = {
    'source': 'https://github.com/kkinnear/zprint',
    'name': 'Zprint',
    'uid': 'zprint',
    'type': 'beautifier',
    'syntaxes': ['clojure'],
    'exclude_syntaxes': None,
    'interpreter_path': '/path/to/bin/java.exe if use zprint-filter OR /path/to/bin/bb if use babashka OR just omit',
    'executable_path': '/path/to/bin/zprint[l|m|ma|] or /path/to/bin/zprint-filter if use java',
    'args': None,
    'config_path': {
        'default': 'zprint_rc.edn'
    },
    'comment': 'Requires java on PATH to use zprint-filter. MacOS: another zprint already exists, avoid to use this same name.'
}


class ZprintFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def remove_comments(self, text):
        # Pattern to match comments
        pattern = r';;.*?(?=\n|$)|(\'.*?\'|".*?")'
        # Remove single comments ;;
        text_without_comments = re.sub(pattern, lambda x: x.group(1) if x.group(1) else '', text)
        return text_without_comments

    def remove_extra_whitespaces(self, text):
        return re.sub(r'\s+', ' ', text)

    def get_cmd(self):
        interpreter = self.get_interpreter()
        executable = self.get_executable(runtime_type=None)
        if executable and interpreter:
            if 'zprint-filter' in basename(executable).lower():
                cmd = [interpreter, '-jar', executable]
            elif 'bb' in basename(interpreter).lower():
                cmd = [interpreter, executable]
            else:
                cmd = [executable]
        elif executable:
            cmd = [executable]
        else:
            return None

        cmd.extend(self.get_args())

        path = self.get_config_path()
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                text = self.remove_comments(file.read())
                text = ''.join(text.splitlines())
                cmd.extend([self.remove_extra_whitespaces(text)])

        return cmd

    def format(self):
        cmd = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)

            if exitcode > 0:
                self.print_exiterr(exitcode, stderr)
            else:
                return stdout
        except Exception as e:
            self.print_oserr(cmd, e)

        return None
