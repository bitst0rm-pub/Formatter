import os

import sublime
import sublime_plugin

from ..core import (log, MarkdownHandler, PhantomHandler)
from ..core.constants import PACKAGE_NAME


class OpenChangelogCommand(sublime_plugin.WindowCommand):
    def __init__(self, *args, **kwargs):
        self.FILE_PATH = self.get_file_path()

    def get_file_path(self):
        return os.path.join(sublime.packages_path(), PACKAGE_NAME, 'CHANGELOG.md')

    def convert_markdown_file_to_html(self, filepath):
        try:
            with open(filepath, 'r') as f:
                markdown = f.read()

            return MarkdownHandler.markdown_to_html(markdown)
        except Exception as e:
            log.error('Error reading file: %s\n%s', filepath, e)
        return None

    def is_enabled(self):
        return os.path.exists(self.FILE_PATH)

    def is_visible(self):
        return self.is_enabled()

    def run(self):
        if os.path.exists(self.FILE_PATH):
            html = self.convert_markdown_file_to_html(self.FILE_PATH)
            if html:
                view = sublime.active_window().new_file()
                PhantomHandler.style_view(view)
                view.erase_phantoms('changelog')
                view.add_phantom('changelog', sublime.Region(0), html, sublime.LAYOUT_INLINE)
                view.set_name('Changelog')
                view.set_read_only(True)
                view.set_scratch(True)
        else:
            log.error('File does not exist: %s', self.FILE_PATH)
