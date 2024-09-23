import base64
import os

import sublime
import sublime_plugin

from ..core import GFX_OUT_NAME, InterfaceHandler, PhantomHandler, log


class ZoomCommand(sublime_plugin.WindowCommand):
    ZOOM_LEVELS = ['Fit', '10%', '25%', '50%', '75%', '100%', '125%', '150%', '175%', '200%', '225%', '250%', '275%', '300%', '325%', '350%', '375%', '400%']

    def run(self, **kwargs):
        self.window.show_quick_panel(self.ZOOM_LEVELS, lambda index: self.on_done(index, **kwargs))

    def on_done(self, index, **kwargs):
        if index != -1:
            zoom_level = self.ZOOM_LEVELS[index]
            if zoom_level == 'Fit' or zoom_level == '100%' or zoom_level == '-100%':
                zoom_factor = 1.0
            else:
                zoom_factor = float(zoom_level[:-1]) / 100

            dst_view_id = kwargs.get('dst_view_id')
            image_data = kwargs.get('image_data')
            image_width = kwargs.get('image_width')
            image_height = kwargs.get('image_height')
            extended_data = kwargs.get('extended_data')

            dst_view = self.find_view_by_id(dst_view_id) or self.window.active_view()
            if zoom_level == 'Fit':
                fit_image_width, fit_image_height = PhantomHandler.image_scale_fit(dst_view, image_width, image_height)
            else:
                fit_image_width = image_width * zoom_factor
                fit_image_height = image_height * zoom_factor

            try:
                html = PhantomHandler.set_html_phantom(dst_view, image_data, image_width, image_height, fit_image_width, fit_image_height, extended_data)
                data = {'dst_view_id': dst_view.id(), 'image_data': image_data, 'image_width': image_width, 'image_height': image_height, 'extended_data': extended_data}

                dst_view.erase_phantoms('graphic')
                dst_view.add_phantom('graphic', sublime.Region(0), html, sublime.LAYOUT_INLINE, on_navigate=lambda href: self.on_navigate(href, data, dst_view))
            except Exception as e:
                log.error('Error creating phantom: %s', e)

    @staticmethod
    def on_navigate(href, data, dst_view):
        if href == 'zoom_image':
            dst_view.window().run_command('zoom', data)
        else:
            stem = os.path.splitext(os.path.basename(dst_view.file_name() or GFX_OUT_NAME))[0]
            save_path = os.path.join(PhantomHandler.get_downloads_folder(), stem + '.' + href.split('/')[1].split(';')[0])

            try:
                mime_type, base64_data = href.split(',', 1)
                decoded_data = base64.b64decode(base64_data)
                with open(save_path, 'wb') as f:
                    f.write(decoded_data)

                InterfaceHandler.popup_message('Image saved to:\n%s' % save_path, 'INFO', dialog=True)
            except Exception as e:
                InterfaceHandler.popup_message('Could not save file:\n%s\nError: %s' % (save_path, e), 'ERROR')

    @staticmethod
    def find_view_by_id(dst_view_id):
        for window in sublime.windows():
            for view in window.views():
                if view.id() == dst_view_id:
                    return view
        return None
