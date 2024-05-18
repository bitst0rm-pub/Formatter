import logging
from . import common
from ..modules import formatter_generic
from ..modules import formatter_map

log = logging.getLogger(__name__)


class Formatter(common.Module):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kwargs = kwargs

    def _log_debug_info(self, method, syntax):
        file = self.view.file_name() or '(view)'
        log.debug('Target: %s', file)
        log.debug('Scope: %s', self.view.scope_name(self.region.begin()))
        log.debug('Syntax: %s', syntax)
        log.debug('UID: %s (method: %s)', self.uid, method)

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
        if not syntax:
            self.popup_message('Syntax out of the scope.', 'UID:' + self.uid)
            return False

        self.kwargs.update(uid=self.uid)
        formatter_plugin = formatter_map.get(self.uid)
        if formatter_plugin:
            self.kwargs.update(formatter_plugin['const'])
            self._log_debug_info('module', syntax)
            result = formatter_plugin['class'](**self.kwargs).format()
        else:
            self._log_debug_info('generic', syntax)
            result = formatter_generic.GenericFormatter(**self.kwargs).format()

        return self.is_success(result)
