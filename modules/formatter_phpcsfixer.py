from ..core import Module

INTERPRETERS = ['php']
EXECUTABLES = ['php-cs-fixer-v3.phar', 'php-cs-fixer-v3', 'phpcsfixer.phar', 'phpcsfixer', 'php-cs-fixer.phar', 'php-cs-fixer', 'php-cs-fixer-v2.phar', 'php-cs-fixer-v2']
DOTFILES = ['.php-cs-fixer.php', '.php-cs-fixer.dist.php']
MODULE_CONFIG = {
    'source': 'https://github.com/FriendsOfPHP/PHP-CS-Fixer',
    'name': 'PHPCSFixer',
    'uid': 'phpcsfixer',
    'type': 'beautifier',
    'syntaxes': ['php'],
    'exclude_syntaxes': None,
    'executable_path': '/path/to/bin/php-cs-fixer.phar',
    'args': None,
    'config_path': {
        'default': 'php_cs_fixer_rc.php'
    },
    'comment': 'Omit "interpreter_path" if php already on PATH.'
}


class PhpcsfixerFormatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_cmd(self):
        cmd = self.get_combo_cmd(runtime_type=None)
        if not cmd:
            return None

        path = self.get_config_path()
        if path:
            cmd.extend(['--config=' + path, '--allow-risky=yes'])

        tmp_file = self.create_tmp_file(autodel=True)
        cmd.extend(['fix', tmp_file])

        return cmd, tmp_file

    def format(self):
        cmd, tmp_file = self.get_cmd()

        try:
            exitcode, stdout, stderr = self.exec_com(cmd)

            result = None

            if exitcode > 0 or not stdout:
                self.print_exiterr(exitcode, stderr)
            else:
                with open(tmp_file, 'r', encoding='utf-8') as file:
                    result = file.read()
                    file.close()
        except Exception as e:
            self.print_oserr(cmd, e)

        return result
