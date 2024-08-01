import base64
import os
import tempfile
import traceback

import sublime

from ..core import (CONFIG, ConfigHandler, InterfaceHandler, LayoutHandler,
                    OptionHandler, PathHandler, PhantomHandler, PrintHandler,
                    log)
from ..core.constants import GFX_OUT_NAME, PACKAGE_NAME, STATUS_KEY
from ..core.formatter import Formatter


class FileFormat:
    def __init__(self, view, **kwargs):
        self.view = view
        self.kwargs = kwargs
        self.kwargs.update(view=self.view)
        self.temp_dir = None
        self.success, self.failure = 0, 0
        self.cycles = []

    def run(self):
        self.create_graphic_temp_dir()
        PrintHandler.print_sysinfo(pretty=True)

        try:
            for region in (self.view.sel() if self.has_selection() else [sublime.Region(0, self.view.size())]):
                self.kwargs.update(region=region)
                is_success = Formatter(**self.kwargs).run()
                self.cycles.append(is_success)
                self.print_status(is_success)

            if any(self.cycles):
                self.close_console_on_success()
                self.handle_successful_formatting()
            else:
                self.open_console_on_failure()
        except Exception as e:
            log.error('Error occurred: %s\n%s', e, ''.join(traceback.format_tb(e.__traceback__)))

    def create_graphic_temp_dir(self):
        if self.kwargs.get('type', None) == 'graphic':
            self.temp_dir = tempfile.TemporaryDirectory()
            self.kwargs.update(temp_dir=self.temp_dir.name)

    def has_selection(self):
        return any(not sel.empty() for sel in self.view.sel())

    def print_status(self, is_success):
        if is_success:
            self.success += 1
            log.status('🎉 Formatting successful. 🥳✨\n')
        else:
            self.failure += 1
            log.status('❌ Formatting failed. 😢💔\n')

        if OptionHandler.query(CONFIG, True, 'show_statusbar'):
            self.set_status_bar_text()

    def set_status_bar_text(self):
        status_text = '{}({}) [ok:{}|ko:{}]'.format(PACKAGE_NAME[0], ConfigHandler.get_mode_description(short=True), self.success, self.failure)
        self.view.set_status(STATUS_KEY, status_text)

    def open_console_on_failure(self):
        if OptionHandler.query(CONFIG, False, 'open_console_on_failure'):
            self.view.window().run_command('show_panel', {'panel': 'console'})

    def close_console_on_success(self):
        if OptionHandler.query(CONFIG, False, 'close_console_on_success'):
            self.view.window().run_command('hide_panel', {'panel': 'console'})

    def handle_successful_formatting(self):
        if self.kwargs.get('type', None) == 'graphic':
            self.handle_graphic_formatting()
        else:
            self.handle_text_formatting()

    def handle_graphic_formatting(self):
        window = self.view.window()
        window.focus_group(0)
        layout = OptionHandler.query(CONFIG, '2cols', 'layout', 'enable')
        layout = layout if layout in ['2cols', '2rows'] else '2cols'
        window.set_layout(LayoutHandler.assign_layout(layout))
        self.create_or_reuse_view()

    def handle_text_formatting(self):
        uid = self.kwargs.get('uid', None)
        mode = 'qo' if ConfigHandler.is_quick_options_mode() else 'user'
        layout, suffix = self.get_layout_and_suffix(uid, mode)

        if suffix and isinstance(suffix, str):
            window = self.view.window()
            window.focus_group(0)

            if mode == 'qo':
                window.set_layout(LayoutHandler.assign_layout(layout))
            elif LayoutHandler.want_layout():
                LayoutHandler.setup_layout(self.view)

            file_path = self.view.file_name()
            new_path = '{0}.{2}{1}'.format(*os.path.splitext(file_path) + (suffix,)) if file_path and os.path.isfile(file_path) else None
            self.view.run_command('transfer_view_content', {'path': new_path})
            sublime.set_timeout(self.undo_history, 250)

    def create_or_reuse_view(self):
        path = self.view.file_name()
        src_window = self.view.window()
        gfx_vref = self.view.id()

        dst_view = next((v for window in sublime.windows() for v in window.views() if v.settings().get('gfx_vref', None) == gfx_vref), None)

        if dst_view:
            dst_view.window().focus_view(dst_view)
            dst_view.set_read_only(False)
            self.set_graphic_phantom(dst_view)
        else:
            src_window.focus_group(1)
            dst_view = src_window.new_file(flags=sublime.TRANSIENT, syntax=self.view.settings().get('syntax', None))
            dst_view.run_command('append', {'characters': ''})  # magic to assign a tab
            dst_view.settings().set('gfx_vref', gfx_vref)
            self.set_graphic_phantom(dst_view)
            dst_view.set_scratch(True)
            if path:
                dst_view.retarget(path)

        dst_view.set_read_only(True)

    def get_extended_data(self):
        uid = self.kwargs.get('uid', None)

        if ConfigHandler.is_quick_options_mode():
            if uid not in OptionHandler.query(CONFIG, [], 'quick_options', 'render_extended'):
                return {}

        try:
            extended_data = {}
            image_extensions = ['svg'] if not ConfigHandler.is_generic_method(uid) else list(OptionHandler.query(CONFIG, {}, 'formatters', uid, 'args_extended').keys())

            for ext in image_extensions:
                ext = ext.strip().lower()
                image_path = os.path.join(self.temp_dir.name, GFX_OUT_NAME + '.' + ext)
                if os.path.exists(image_path):
                    with open(image_path, 'rb') as image_file:
                        extended_data[ext] = base64.b64encode(image_file.read()).decode('utf-8')

            return extended_data
        except Exception:
            return {}

    def set_graphic_phantom(self, dst_view):
        try:
            image_path = os.path.join(self.temp_dir.name, GFX_OUT_NAME + '.png')
            with open(image_path, 'rb') as image_file:
                data = image_file.read()
                image_width, image_height = PhantomHandler.get_image_size(data)
                image_data = base64.b64encode(data).decode('utf-8')

            fit_image_width, fit_image_height = PhantomHandler.image_scale_fit(dst_view, image_width, image_height)
            extended_data = self.get_extended_data()

            html = PhantomHandler.set_html_phantom(dst_view, image_data, image_width, image_height, fit_image_width, fit_image_height, extended_data)
            data = {'dst_view_id': dst_view.id(), 'image_data': image_data, 'image_width': image_width, 'image_height': image_height, 'extended_data': extended_data}

            dst_view.erase_phantoms('graphic')
            dst_view.add_phantom('graphic', sublime.Region(0), html, sublime.LAYOUT_INLINE, on_navigate=lambda href: self.on_navigate(href, data, dst_view))
        except Exception as e:
            log.error('Error creating phantom: %s', e)
        finally:
            self.temp_dir.cleanup()

    def on_navigate(self, href, data, dst_view):
        if href == 'zoom_image':
            dst_view.window().run_command('zoom', data)
        else:
            stem = PathHandler(view=dst_view).get_pathinfo()['stem'] or GFX_OUT_NAME
            save_path = os.path.join(PhantomHandler.get_downloads_folder(), stem + '.' + href.split('/')[1].split(';')[0])

            try:
                mime_type, base64_data = href.split(',', 1)
                decoded_data = base64.b64decode(base64_data)
                with open(save_path, 'wb') as f:
                    f.write(decoded_data)

                InterfaceHandler.popup_message('Image successfully saved to:\n%s' % save_path, 'INFO', dialog=True)
            except Exception as e:
                InterfaceHandler.popup_message('Could not save file:\n%s\nError: %s' % (save_path, e), 'ERROR')

    def get_layout_and_suffix(self, uid, mode):
        if mode == 'qo':
            return (
                OptionHandler.query(CONFIG, False, 'quick_options', 'layout'),
                OptionHandler.query(CONFIG, False, 'quick_options', 'new_file_on_format')
            )
        else:
            return (
                OptionHandler.query(CONFIG, False, 'layout', 'enable'),
                OptionHandler.query(CONFIG, False, 'formatters', uid, 'new_file_on_format')
            )

    def undo_history(self):
        for _ in range(min(500, self.cycles.count(True))):
            self.view.run_command('undo')
