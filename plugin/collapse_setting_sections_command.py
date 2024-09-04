import sublime
import sublime_plugin

from ..core import log

EXCLUDE_COLLAPSE_KEYS = []  # example: ['stylelint', 'examplegeneric']


class CollapseSettingSectionsCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        view = self.view
        content = view.substr(sublime.Region(0, view.size()))

        try:
            data = sublime.decode_value(content)
            if isinstance(data, dict) and 'formatters' in data:
                formatters_region = self.find_formatters_region(content)
                if formatters_region:
                    self.collapse_all_formatters(view, content, formatters_region)

        except Exception as e:
            log.error('Failed to decode JSON: %s', e)

    @staticmethod
    def find_formatters_region(content):
        start = content.find('"formatters"')
        if start == -1:
            return None

        start = content.find('{', start)
        if start == -1:
            return None

        # Find the end of the "formatters" object
        depth = 1
        for i in range(start + 1, len(content)):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
                if depth == 0:
                    return sublime.Region(start, i + 1)
        return None

    def collapse_all_formatters(self, view, content, formatters_region):
        start = formatters_region.begin()
        end = formatters_region.end()

        pos = start + 1
        while pos < end:
            # Find the next key
            key_start = content.find('"', pos)
            if key_start == -1 or key_start >= end:
                break
            key_end = content.find('"', key_start + 1)
            if key_end == -1 or key_end >= end:
                break

            key = content[key_start + 1:key_end]

            if key in EXCLUDE_COLLAPSE_KEYS:
                pos = self.skip_object(content, key_end, end)
                continue

            # Find the start of the object for this key
            colon_pos = content.find(':', key_end)
            if colon_pos == -1 or colon_pos >= end:
                break

            object_start = content.find('{', colon_pos)
            if object_start == -1 or object_start >= end:
                break

            # Find the end of the object
            object_end = self.find_object_end(content, object_start, end)
            view.fold(sublime.Region(object_start + 1, object_end - 1))  # +1,-1 to add the missing brackets { ... }
            pos = object_end + 1

    def skip_object(self, content, start_pos, end):
        object_start = content.find('{', start_pos)
        if object_start == -1 or object_start >= end:
            return end

        return self.find_object_end(content, object_start, end)

    @staticmethod
    def find_object_end(content, start_pos, end):
        depth = 1
        for i in range(start_pos + 1, end):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
                if depth == 0:
                    return i + 1
        return end
