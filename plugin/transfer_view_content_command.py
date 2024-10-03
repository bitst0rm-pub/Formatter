import sublime
import sublime_plugin

from ..core import CONFIG, STATUS_KEY, InterfaceHandler, OptionHandler, log


class TransferViewContentCommand(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        path = kwargs.get('path', None)
        src_view = self.view

        dst_view = self.create_or_reuse_view(path, src_view)
        self.copy_content_and_selections(src_view, dst_view)

        if path:
            self.save_dst_content(dst_view, path)
        else:
            log.debug('Unsaved buffer, manual save required.')

        self.update_status(dst_view)
        self.focus_source_view(src_view)

    @staticmethod
    def create_or_reuse_view(path, src_view):
        src_window = src_view.window()
        txt_vref = src_view.id()

        dst_view = next((v for window in sublime.windows() for v in window.views() if v.settings().get('txt_vref', None) == txt_vref), None)

        if dst_view:
            dst_view.window().focus_view(dst_view)
            dst_view.run_command('select_all')
            dst_view.run_command('right_delete')
        else:
            src_window.focus_group(1)
            dst_view = src_window.new_file(flags=sublime.TRANSIENT, syntax=src_view.settings().get('syntax', None))
            dst_view.run_command('append', {'characters': ''})  # magic to assign a tab
            dst_view.settings().set('txt_vref', txt_vref)
            if path:
                dst_view.retarget(path)
                dst_view.set_scratch(True)
            else:
                dst_view.set_scratch(False)

        return dst_view

    @staticmethod
    def copy_content_and_selections(src_view, dst_view):
        dst_view.run_command('append', {'characters': src_view.substr(sublime.Region(0, src_view.size()))})

        selections = list(src_view.sel())
        dst_view.sel().clear()
        dst_view.sel().add_all(selections)

        dst_view.set_viewport_position(src_view.viewport_position(), False)
        dst_view.window().focus_view(dst_view)

    @staticmethod
    def save_dst_content(view, path):
        try:
            with open(path, 'w', encoding='utf-8') as file:
                file.write(view.substr(sublime.Region(0, view.size())))
        except OSError as e:
            log.error('Error saving file: %s\n%s', path, e)
            InterfaceHandler.popup_message('Error saving file:\n' + path + '\nPermissions issue likely.', 'ERROR')

    def update_status(self, view):
        if view.is_loading():
            sublime.set_timeout(lambda: self.update_status(view), 250)
        else:
            if OptionHandler.query(CONFIG, True, 'show_statusbar'):
                view.window().set_status_bar_visible(True)
                view.set_status(STATUS_KEY, self.view.get_status(STATUS_KEY))

    @staticmethod
    def focus_source_view(src_view):
        window = src_view.window()
        window.focus_group(0)
        window.focus_view(src_view)
