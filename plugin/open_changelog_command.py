import os

import sublime
import sublime_plugin

from ..core import PACKAGE_NAME, MarkdownHandler, PhantomHandler, log


class OpenChangelogCommand(sublime_plugin.WindowCommand):
    @staticmethod
    def get_file_path():
        return os.path.join(sublime.packages_path(), PACKAGE_NAME, 'CHANGELOG.md')

    @staticmethod
    def convert_markdown_file_to_html(filepath):
        try:
            with open(filepath, 'r') as f:
                markdown = f.read()

            return MarkdownHandler.markdown_to_html(markdown)
        except Exception as e:
            log.error('Error reading file: %s\n%s', filepath, e)
        return None

    def is_enabled(self):
        return os.path.exists(self.get_file_path())

    def is_visible(self):
        return self.is_enabled()

    def run(self):
        file_path = self.get_file_path()
        if os.path.exists(file_path):
            html = self.convert_markdown_file_to_html(file_path)
            if html:
                view = sublime.active_window().new_file()
                PhantomHandler.style_view(view)
                view.erase_phantoms('changelog')
                view.add_phantom('changelog', sublime.Region(0), html, sublime.LAYOUT_INLINE)
                view.set_name('Changelog')
                view.set_read_only(True)
                view.set_scratch(True)
        else:
            log.error('File does not exist: %s', file_path)
