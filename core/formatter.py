from ..modules import formatter_map
from . import NOOP, Module, log


class Formatter(Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kwargs = kwargs

    def _log_debug_info(self, method, syntax):
        file = self.view.file_name() or 'view'
        log.debug('Syntax: %s | Scope: %s', syntax, self.view.scope_name(self.region.begin()).strip())
        log.debug('UID: %s (method: %s) | Target: %s', self.uid, method, file)

    def is_success(self, result):
        if self.kwargs.get('type', None) == 'graphic' and result is not None:
            return True

        if result:
            self.view.run_command('replace_view_content', {'result': result, 'region': [self.region.a, self.region.b]})
            return True

        return False

    def run(self):
        if not self.is_view_formattable():
            log.error('View is not formattable.')
            return False

        syntax = self.get_assigned_syntax()

        if self.uid == NOOP:
            log.info('No operation')
            return None

        if not syntax:
            self.popup_message('Syntax out of the scope', 'UID:' + self.uid)
            return False

        self.kwargs.update(uid=self.uid)
        formatter_plugin = formatter_map.get(self.uid)
        if formatter_plugin:
            self.kwargs.update(formatter_plugin['specs'])
            self._log_debug_info('module', syntax)
        else:
            formatter_plugin = formatter_map.get('generic')
            self._log_debug_info('generic', syntax)

        result = formatter_plugin['class'](**self.kwargs).format()
        return self.is_success(result)

    def format(self):
        raise Exception('Oh! Sticking in the wrong hole!')
