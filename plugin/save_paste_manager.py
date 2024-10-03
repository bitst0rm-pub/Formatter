from os.path import basename, dirname, splitext

import sublime

from ..core import (CONFIG, MAX_CHAIN_PLUGINS, NOOP, CleanupHandler,
                    ConfigHandler, DataHandler, DotFileHandler,
                    InterfaceHandler, OptionHandler, SyntaxHandler,
                    TransformHandler, log)
from . import FileFormat


class SavePasteManager:
    @classmethod
    def apply_formatting(cls, view=None, action=None):
        DataHandler.set('__save_paste_action__', 'action', action)
        file_path = view.file_name()

        if file_path and splitext(file_path)[1] in ['.sublime-settings', '.sublime-keymap']:
            return  # exclude by default

        if cls._on_auto_format(view=view, file_path=file_path, actkey=action):
            return  # fallthrough if False

        cls._on_paste_or_save(view=view, actkey=action)

    @classmethod
    def _on_auto_format(cls, view=None, file_path=None, actkey=None):
        auto_format_args = DotFileHandler.get_auto_format_args(view=view, active_file_path=file_path)
        config = auto_format_args['auto_format_config'].get('config', {})
        if config and not cls._should_skip(view=view, value=config.get(actkey, False)):
            CleanupHandler.clear_console()

            log.debug('"%s" (autoformat)', actkey)
            FileFormat.reset_status()
            try:
                afc = auto_format_args['auto_format_config']

                for i in range(MAX_CHAIN_PLUGINS):
                    is_non_empty = cls._process_plugin_chain(afc)

                    if not is_non_empty:
                        # For handle_text_formatting() in new_file_on_format mode
                        FileFormat.set_auto_format_finished()

                    if i > 0 and not is_non_empty:  # > 0 for "plugin" or ["plugin"]
                        break  # finished

                    with FileFormat(view=view, **auto_format_args) as file_format:
                        file_format.run()

                DataHandler.reset('__auto_format_chain_item__')

                is_noop = DataHandler.get('__auto_format_noop__')[1] == NOOP
                DataHandler.reset('__auto_format_noop__')

                if not is_noop:
                    return True
            except Exception as e:
                log.error('Error during auto formatting: %s', e)

        return False

    @staticmethod
    def _process_plugin_chain(afc):
        syntax, uid = DataHandler.get('__auto_format_chain_item__')
        if not (syntax and uid):  # De Morgan's laws
            return False  # no match found

        if not isinstance(afc.get(syntax), list):
            return False  # not type chain

        # Remove the consumed uid until the chain list is empty
        afc[syntax] = [item for item in afc[syntax] if item != uid]

        return bool(afc[syntax])  # the chain list is now empty

    @classmethod
    def _on_paste_or_save(cls, view=None, actkey=None):
        if not actkey:
            return None

        unique = OptionHandler.query(CONFIG, {}, 'format_on_priority') or OptionHandler.query(CONFIG, {}, 'format_on_unique')
        if unique and isinstance(unique, dict) and unique.get('enable', False):
            cls._handle_unique_format(view=view, unique=unique, actkey=actkey)
        else:
            cls._handle_regular_format(view=view, actkey=actkey)

    @classmethod
    def _handle_unique_format(cls, view=None, unique=None, actkey=None):
        def are_unique_values(unique=None):
            flat_values = [value for key, values_list in unique.items() if key != 'enable' for value in values_list]
            return (len(flat_values) == len(set(flat_values)))

        formatters = OptionHandler.query(CONFIG, {}, 'formatters')

        if are_unique_values(unique=unique):
            for uid, value in unique.items():
                if uid == 'enable':
                    continue

                val = OptionHandler.query(formatters, None, uid)
                if not cls._should_skip_formatter(view=view, uid=uid, value=val, actkey=actkey):
                    syntax = cls._get_syntax(view=view, uid=uid)
                    if cls._should_skip_syntaxes(value=val, syntax=syntax, actkey=actkey):
                        continue
                    if syntax in value:
                        CleanupHandler.clear_console()

                        log.debug('"%s" (priority)', actkey)
                        try:
                            with FileFormat(view=view, uid=uid, type=value.get('type', None)) as file_format:
                                file_format.run()
                        except Exception as e:
                            log.error('Error during priority formatting: %s', e)
                        finally:
                            break
        else:
            InterfaceHandler.popup_message('There are duplicate syntaxes in your "format_on_priority" option. Please sort them out.', 'ERROR')

    @classmethod
    def _handle_regular_format(cls, view=None, actkey=None):
        seen = set()
        formatters = OptionHandler.query(CONFIG, {}, 'formatters')

        for uid, value in formatters.items():
            if not cls._should_skip_formatter(view=view, uid=uid, value=value, actkey=actkey):
                syntax = cls._get_syntax(view=view, uid=uid)
                if cls._should_skip_syntaxes(value=value, syntax=syntax, actkey=actkey):
                    continue
                if syntax in value.get('syntaxes', []) and syntax not in seen:
                    CleanupHandler.clear_console()

                    log.debug('"%s" (regular)', actkey)
                    try:
                        with FileFormat(view=view, uid=uid, type=value.get('type', None)) as file_format:
                            file_format.run()
                    except Exception as e:
                        log.error('Error during regular formatting: %s', e)
                    finally:
                        seen.add(syntax)

    @staticmethod
    def _should_skip_syntaxes(value=None, syntax=None, actkey=None):
        actkey_value = value.get(actkey, None)
        if isinstance(actkey_value, dict):
            return syntax in actkey_value.get('exclude_syntaxes', [])
        return False

    @classmethod
    def _should_skip_formatter(cls, view=None, uid=None, value=None, actkey=None):
        if not isinstance(value, dict):
            return True

        if ('disable' in value and value.get('disable', True)) or ('enable' in value and not value.get('enable', False)):
            return True

        is_qo_mode = ConfigHandler.is_quick_options_mode()
        is_rff_on = OptionHandler.query(CONFIG, False, 'quick_options', 'dir_format')

        if is_qo_mode:
            if uid not in OptionHandler.query(CONFIG, [], 'quick_options', actkey):
                return True

            if is_rff_on:
                log.info('Quick Options mode: %s has the "%s" option enabled, which is incompatible with "dir_format" mode.', uid, actkey)
                return True
        else:
            if cls._should_skip(view=view, value=value.get(actkey, False)):
                return True

            if OptionHandler.query(value, False, 'dir_format', 'enable'):
                log.info('User Settings mode: %s has the "%s" option enabled, which is incompatible with "dir_format" mode.', uid, actkey)
                return True

        return False

    @classmethod
    def _should_skip(cls, view=None, value=None):
        if isinstance(value, bool):
            return not value

        if isinstance(value, dict):
            return cls._should_exclude(view=view, value=value)

        return False

    @staticmethod
    def _should_exclude(view=None, value=None):
        file_path = view.file_name()

        if file_path:
            dir_path = dirname(file_path)
            extension = splitext(basename(file_path))[1].lstrip('.').lower()

            exclude_dirs_regex_compiled = TransformHandler.compile_regex_patterns(value.get('exclude_dirs_regex', []))
            exclude_files_regex_compiled = TransformHandler.compile_regex_patterns(value.get('exclude_files_regex', []))
            exclude_extensions_regex_compiled = TransformHandler.compile_regex_patterns(value.get('exclude_extensions_regex', []))

            if any(pattern.match(dir_path) for pattern in exclude_dirs_regex_compiled):
                return True

            if any(pattern.match(file_path) for pattern in exclude_files_regex_compiled):
                return True

            if any(pattern.match(extension) for pattern in exclude_extensions_regex_compiled):
                return True

        return False

    @staticmethod
    def _get_syntax(view=None, uid=None):
        is_selected = any(not sel.empty() for sel in view.sel())

        if is_selected:
            # Selections: find the first non-empty region or use the first region if all are empty
            region = next((region for region in view.sel() if not region.empty()), view.sel()[0])
        else:
            # Entire view
            region = sublime.Region(0, view.size())

        uid, syntax = SyntaxHandler.get_assigned_syntax(view=view, uid=uid, region=region, auto_format_config=None)
        return syntax
