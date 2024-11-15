import hashlib
import json
import re
import uuid
from collections import OrderedDict
from errno import EEXIST
from os import makedirs
from os.path import isfile, join

import sublime

from . import (ASSETS_DIRECTORY, CONFIG, MAX_CHAIN_PLUGINS, PACKAGE_NAME,
               QUICK_OPTIONS_SETTING_FILE, ConfigHandler, HashHandler, log)


class NoIndent:
    def __init__(self, value):
        self.value = value


class NoIndentEncoder(json.JSONEncoder):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kwargs = dict(kwargs)
        self.kwargs.pop('indent', None)
        self._replacement_map = {}

    def default(self, o):
        if isinstance(o, NoIndent):
            key = uuid.uuid4().hex
            self._replacement_map[key] = json.dumps(o.value, **self.kwargs)
            return '@@%s@@' % key
        else:
            return super().default(o)

    def encode(self, o):
        result = super().encode(o)
        for k, v in self._replacement_map.items():
            result = result.replace('"@@%s@@"' % k, v)
        return result

    @classmethod
    def decode(cls, s):
        def object_hook(obj):
            for key, value in obj.items():
                if isinstance(value, str) and value.startswith('@@') and value.endswith('@@'):
                    obj[key] = NoIndent(json.loads(value[2:-2]))
            return obj

        return json.loads(s, object_hook=object_hook)


def strip_trailing(text):
    return ('\n'.join([line.rstrip() for line in text.split('\n')]))


def build_sublime_menu_children(formatter_map):
    beautifiers = []
    minifiers = []
    converters = []
    graphics = []
    custom = []
    type_to_list = {'beautifier': beautifiers, 'minifier': minifiers, 'converter': converters, 'graphic': graphics}

    for uid, module_info in formatter_map.items():
        config = getattr(module_info['module'], 'MODULE_CONFIG', None)
        if config:
            child = OrderedDict([
                ('caption', (config['name'][0].upper() + config['name'][1:]) + (' (min)' if config['type'] == 'minifier' else '')),
                ('command', 'run_format'),
                ('args', OrderedDict([
                    ('uid', config['uid']),
                    ('type', config['type'])
                ]))
            ])

            target_list = type_to_list.get(config['type'], custom)
            target_list.append(child)

    formatters = CONFIG.get('formatters', {})
    for uid, v in formatters.items():
        name = v.get('name', None)
        typ = v.get('type', None)
        if name and typ:
            child = OrderedDict([
                ('caption', name + (' (min)' if typ == 'minifier' else '')),
                ('command', 'run_format'),
                ('args', OrderedDict([
                    ('uid', uid),
                    ('type', typ)
                ]))
            ])

            target_list = type_to_list.get(typ, custom)
            target_list.append(child)

    return beautifiers, minifiers, converters, graphics, custom


def build_context_sublime_menu(formatter_map):
    context_menu = [
        OrderedDict([
            ('caption', 'Formatter'),
            ('id', 'formatter'),
            ('children', [
                OrderedDict([
                    ('caption', '☰ Quick Options'),
                    ('command', 'quick_options')
                ]),
                OrderedDict([
                    ('caption', 'Auto Format File'),
                    ('command', 'auto_format_file')
                ])
            ])
        ])
    ]

    beautifiers, minifiers, converters, graphics, custom = build_sublime_menu_children(formatter_map)
    sort_and_extend = lambda lst, caption=None: context_menu[0]['children'].extend(  # noqa: E731
        ([{'caption': caption}] if (caption and lst) else []) + sorted(lst, key=lambda x: x['args']['uid'])
    )
    sort_and_extend(beautifiers, '-')
    sort_and_extend(minifiers, '-')
    sort_and_extend(converters, '-')
    sort_and_extend(graphics, '-')
    sort_and_extend(custom, '-')

    json_text = json.dumps(context_menu, cls=NoIndentEncoder, ensure_ascii=False, indent=4)
    return strip_trailing(json_text)


def build_main_sublime_menu(formatter_map):
    main_menu = [
        OrderedDict([
            ('caption', 'Tools'),
            ('id', 'tools'),
            ('mnemonic', 'T'),
            ('children', [
                OrderedDict([
                    ('caption', 'Formatter'),
                    ('id', 'formatter'),
                    ('children', [
                        OrderedDict([
                            ('caption', '☰ Quick Options'),
                            ('command', 'quick_options')
                        ]),
                        OrderedDict([
                            ('caption', 'Auto Format File'),
                            ('command', 'auto_format_file')
                        ])
                    ])
                ])
            ])
        ]),
        OrderedDict([
            ('caption', 'Preferences'),
            ('id', 'preferences'),
            ('mnemonic', 'n'),
            ('children', [
                OrderedDict([
                    ('caption', 'Package Settings'),
                    ('id', 'package-settings'),
                    ('mnemonic', 'P'),
                    ('children', [
                        OrderedDict([
                            ('caption', 'Formatter'),
                            ('children', [
                                OrderedDict([
                                    ('caption', 'Settings'),
                                    ('command', 'edit_settings'),
                                    ('args', OrderedDict([
                                        ('base_file', '${packages}/Formatter/Formatter.sublime-settings'),
                                        ('default', '{\n\t$0\n}\n')
                                    ]))
                                ]),
                                OrderedDict([
                                    ('caption', 'Modules Info'),
                                    ('command', 'modules_info')
                                ]),
                                OrderedDict([
                                    ('caption', 'Browser Configs'),
                                    ('command', 'browser_configs')
                                ]),
                                OrderedDict([
                                    ('caption', '-')
                                ]),
                                OrderedDict([
                                    ('caption', 'Key Bindings'),
                                    ('command', 'key_bindings')
                                ]),
                                OrderedDict([
                                    ('caption', '-')
                                ]),
                                OrderedDict([
                                    ('caption', 'Backup Settings'),
                                    ('command', 'backup_manager'),
                                    ('args', OrderedDict([
                                        ('type', 'backup')
                                    ]))
                                ]),
                                OrderedDict([
                                    ('caption', 'Restore Settings'),
                                    ('command', 'backup_manager'),
                                    ('args', OrderedDict([
                                        ('type', 'restore')
                                    ]))
                                ]),
                                OrderedDict([
                                    ('caption', '-')
                                ]),
                                OrderedDict([
                                    ('caption', 'Changelog'),
                                    ('command', 'open_changelog')
                                ]),
                                OrderedDict([
                                    ('caption', 'About'),
                                    ('command', 'about')
                                ])
                            ])
                        ])
                    ])
                ])
            ])
        ])
    ]

    def add_mnemonic_recursive(data, mnemonic_prefix=''):
        for item in data:
            caption = item.get('caption')
            mnemonic = item.get('mnemonic')
            if caption and caption != '-' and mnemonic is None:
                mnemonic_key = 'mnemonic'
                caption_mnemonic = mnemonic_prefix
                for char in caption:
                    if char.isalnum():
                        caption_mnemonic += char
                        break
                item[mnemonic_key] = caption_mnemonic.upper()
                ordered_item = OrderedDict([(key, item[key]) if key in item else (key, None) for key in ['caption', mnemonic_key]])
                ordered_item.update(item)
                item.clear()
                item.update(ordered_item)

            children = item.get('children', [])
            if children:
                add_mnemonic_recursive(children, mnemonic_prefix)

    beautifiers, minifiers, converters, graphics, custom = build_sublime_menu_children(formatter_map)
    sort_and_extend = lambda lst, caption=None: main_menu[0]['children'][0]['children'].extend(  # noqa: E731
        ([{'caption': caption}] if (caption and lst) else []) + sorted(lst, key=lambda x: x['args']['uid'])
    )
    sort_and_extend(beautifiers, '-')
    sort_and_extend(minifiers, '-')
    sort_and_extend(converters, '-')
    sort_and_extend(graphics, '-')
    sort_and_extend(custom, '-')
    add_mnemonic_recursive(main_menu, mnemonic_prefix='')

    json_text = json.dumps(main_menu, cls=NoIndentEncoder, ensure_ascii=False, indent=4)
    return strip_trailing(json_text)


def build_formatter_sublime_commands_children(formatter_map):
    beautifiers = []
    minifiers = []
    converters = []
    graphics = []
    custom = []
    type_to_list = {'beautifier': beautifiers, 'minifier': minifiers, 'converter': converters, 'graphic': graphics}
    type_to_action = {'beautifier': 'Beautify', 'minifier': 'Minify', 'converter': 'Convert', 'graphic': 'Visualize'}

    for uid, module_info in formatter_map.items():
        config = getattr(module_info['module'], 'MODULE_CONFIG', None)
        if config:
            child = OrderedDict([
                ('caption', 'Formatter: ' + type_to_action.get(config['type'], 'Customize') + ' with ' + (config['name'][0].upper() + config['name'][1:])),
                ('command', 'run_format'),
                ('args', OrderedDict([
                    ('uid', config['uid']),
                    ('type', config['type'])
                ]))
            ])

            target_list = type_to_list.get(config['type'], custom)
            target_list.append(child)

    formatters = CONFIG.get('formatters', {})
    for uid, v in formatters.items():
        name = v.get('name', None)
        typ = v.get('type', None)
        if name and typ:
            child = OrderedDict([
                ('caption', 'Formatter: ' + type_to_action.get(typ, 'Customize') + ' with ' + name),
                ('command', 'run_format'),
                ('args', OrderedDict([
                    ('uid', uid),
                    ('type', typ)
                ]))
            ])

            target_list = type_to_list.get(typ, custom)
            target_list.append(child)

    return beautifiers, minifiers, converters, graphics, custom


def build_formatter_sublime_commands(formatter_map):
    sublime_commands = [
        OrderedDict([
            ('caption', 'Preferences: Formatter Settings'),
            ('command', 'edit_settings'),
            ('args', OrderedDict([
                ('base_file', '${packages}/Formatter/Formatter.sublime-settings'),
                ('default', '{\n\t$0\n}\n'),
            ])),
        ]),
        OrderedDict([
            ('caption', 'Preferences: Formatter About'),
            ('command', 'about')
        ]),
        OrderedDict([
            ('caption', 'Preferences: Formatter Changelog'),
            ('command', 'open_changelog')
        ]),
        OrderedDict([
            ('caption', 'Preferences: Formatter Modules Info'),
            ('command', 'modules_info')
        ]),
        OrderedDict([
            ('caption', 'Preferences: Formatter Browser Configs'),
            ('command', 'browser_configs')
        ]),
        OrderedDict([
            ('caption', 'Preferences: Formatter Key Bindings'),
            ('command', 'key_bindings')
        ]),
        OrderedDict([
            ('caption', 'Preferences: Formatter Backup Settings'),
            ('command', 'backup_manager'),
            ('args', OrderedDict([
                ('type', 'backup')
            ]))
        ]),
        OrderedDict([
            ('caption', 'Preferences: Formatter Restore Settings'),
            ('command', 'backup_manager'),
            ('args', OrderedDict([
                ('type', 'restore')
            ]))
        ]),
        OrderedDict([
            ('caption', 'Preferences: Formatter Quick Options'),
            ('command', 'quick_options')
        ]),
        OrderedDict([
            ('caption', 'Formatter: Auto Format File'),
            ('command', 'auto_format_file')
        ])
    ]

    beautifiers, minifiers, converters, graphics, custom = build_formatter_sublime_commands_children(formatter_map)
    sort_and_extend = lambda lst, caption=None: sublime_commands.extend(  # noqa: E731
        ([{'caption': caption}] if (caption and lst) else []) + sorted(lst, key=lambda x: x['args']['uid'])
    )
    sort_and_extend(beautifiers, None)
    sort_and_extend(minifiers, None)
    sort_and_extend(converters, None)
    sort_and_extend(graphics, None)
    sort_and_extend(custom, None)

    json_text = json.dumps(sublime_commands, cls=NoIndentEncoder, ensure_ascii=False, indent=4)
    return strip_trailing(json_text)


def build_example_sublime_keymap(formatter_map):
    beautifiers = []
    minifiers = []
    converters = []
    graphics = []
    custom = []
    type_to_list = {'beautifier': beautifiers, 'minifier': minifiers, 'converter': converters, 'graphic': graphics}

    for uid, module_info in formatter_map.items():
        config = getattr(module_info['module'], 'MODULE_CONFIG', None)
        if config:
            child = OrderedDict([
                ('keys', ['ctrl+super+?']),
                ('command', 'run_format'),
                ('args', OrderedDict([
                    ('uid', uid),
                    ('type', config['type'])
                ]))
            ])

            target_list = type_to_list.get(config['type'], custom)
            target_list.append(child)

    formatters = CONFIG.get('formatters', {})
    for uid, v in formatters.items():
        name = v.get('name', None)
        typ = v.get('type', None)
        if name and typ:
            child = OrderedDict([
                ('keys', ['ctrl+super+?']),
                ('command', 'run_format'),
                ('args', OrderedDict([
                    ('uid', uid),
                    ('type', typ)
                ]))
            ])

            target_list = type_to_list.get(typ, custom)
            target_list.append(child)

    sort_key = lambda x: x['args']['uid']  # noqa: E731
    sorted_beautifiers, sorted_minifiers, sorted_converters, sorted_graphics, sorted_custom = [sorted(lst, key=sort_key) for lst in [beautifiers, minifiers, converters, graphics, custom]]

    quick_options = '{"keys": ["ctrl+super+?"], "command": "quick_options"},\n    '
    auto_format_file = '{"keys": ["ctrl+super+?"], "command": "auto_format_file"},\n    '
    formatted_keymap = '[\n    ' + quick_options + auto_format_file + ',\n    '.join([json.dumps(item, cls=NoIndentEncoder, ensure_ascii=False) for item in sorted_beautifiers + sorted_minifiers + sorted_converters + sorted_graphics + sorted_custom]) + '\n]'

    comment = '''// This example is not ready to use.
// End-users are free to remap any key combination.
//
// Modifiers:
// shift
// ctrl or control
// alt
// super (Windows: Windows key, MacOS: Command Key)
// primary (Windows: Control key, MacOS: Command Key)
// command (MacOS only)
// option (MacOS only: same as alt)

'''

    return strip_trailing(comment + formatted_keymap)


def build_formatter_sublime_settings_children(formatter_map):
    beautifiers = []
    minifiers = []
    converters = []
    graphics = []
    custom = []
    type_to_list = {'beautifier': beautifiers, 'minifier': minifiers, 'converter': converters, 'graphic': graphics}

    for uid, module_info in formatter_map.items():
        config = getattr(module_info['module'], 'MODULE_CONFIG', None)
        if config:
            child = OrderedDict([
                ('info', config['source']),
                ('enable', False),
                ('format_on_save', False),
                ('format_on_paste', False),
                # ('new_file_on_format', False),
                ('dir_format', False),
                ('syntaxes', NoIndent(config['syntaxes']))
            ])

            typ = config.get('type', None)
            if typ == 'graphic':
                child.pop('new_file_on_format', None)
                child.pop('dir_format', None)
                child['type'] = 'graphic'
                child['render_extended'] = False

            exclude_syntaxes = config.get('exclude_syntaxes', None)
            if exclude_syntaxes is not None and isinstance(exclude_syntaxes, dict):
                child['exclude_syntaxes'] = {key: NoIndent(value) for key, value in exclude_syntaxes.items()}

            interpreter_path = config.get('interpreter_path', None)
            if interpreter_path is not None:
                if isinstance(interpreter_path, str):
                    child['interpreter_path'] = NoIndent([interpreter_path])
                elif isinstance(interpreter_path, list):
                    child['interpreter_path'] = NoIndent(interpreter_path)

            executable_path = config.get('executable_path', None)
            if executable_path is not None:
                if isinstance(executable_path, str):
                    child['executable_path'] = NoIndent([executable_path])
                elif isinstance(executable_path, list):
                    child['executable_path'] = NoIndent(executable_path)

            args = config.get('args', None)
            if args is not None and isinstance(args, list) and len(args) > 0:
                child['args'] = NoIndent(args)

            config_path = config.get('config_path', None)
            if config_path is not None and isinstance(config_path, dict) and len(config_path) > 0:
                child['config_path'] = {key: join('${packages}', 'User', ASSETS_DIRECTORY, 'config', value) for key, value in config['config_path'].items()}
                default_value = child['config_path'].pop('default', None)
                sorted_config_path = OrderedDict(sorted(child['config_path'].items()))
                child['config_path'] = OrderedDict([('ignore_dotfiles', False)] + list(sorted_config_path.items()))
                if default_value:
                    child['config_path']['default'] = default_value

            comment = config.get('comment', None)
            if comment is not None and isinstance(comment, str) and len(comment) > 0:
                truncated_comment = comment[:200] + '...' if len(comment) > 200 else comment
                child['__COMMENT__child'] = '/* ' + truncated_comment.replace('/*', '').replace('*/', '') + ' */'  # '/* ' is marker for pattern_comma_before_comment

            target_list = type_to_list.get(config['type'], custom)
            target_list.append({uid: child})

    return beautifiers, minifiers, converters, graphics, custom


def build_formatter_sublime_settings(formatter_map):
    sublime_settings = OrderedDict([
        ('__COMMENT__debug', '''// Enable debug mode to view errors in the console.
    // Accepted values: true (verbose), false, OR "status" (recommended)'''),
        ('debug', False),
        ('__COMMENT__clear_console', '''
    // By default, all previous console messages will be cleared. (ST4088+ only)
    // If you want to retain the console message history, set this to false.'''),
        ('clear_console', True),
        ('__COMMENT__open_console_on_failure', '''
    // Auto open the console panel whenever formatting fails.
    // This is useful if "debug" is "status" or true'''),
        ('open_console_on_failure', False),
        ('__COMMENT__close_console_on_success', '''
    // The counterpart for success.'''),
        ('close_console_on_success', False),
        ('__COMMENT__timeout', '''
    // Timeout to abort subprocess in seconds.
    // Default to 10 seconds. Set to false to disable the timeout.'''),
        ('timeout', 10),
        ('__COMMENT__file_chars_limit', '''
    // Limit the total number of characters in the file.
    // A max of 1 MB = 1024 * 1024 ≈ 1.048.576 chars seems reasonable.
    // Accepted values: int OR false'''),
        ('file_chars_limit', False),
        ('__COMMENT__custom_modules_manifest', '''
    // Integrate your custom modules into the Formatter ecosystem.
    // Modules can be located either locally or remotely (with or without signing).
    // This option must be of type string pointing to the JSON metata file path.
    // More about the format of this file, see README.md > Integrating modules'''),
        ('custom_modules_manifest', ''),
        ('__COMMENT__show_statusbar', '''
    // Display results in the status bar with the current settings mode info:
    // PUS: Persistent User Settings
    // PQO: Persistent Quick Options
    // TQO: Temporary Quick Options'''),
        ('show_statusbar', True),
        ('__COMMENT__show_words_count', '''
    // Display a real-time word and character count in the status bar.
    // By default, whitespace is not included in the character count.'''),
        ('show_words_count', OrderedDict([
            ('enable', True),
            ('use_short_label', False),
            ('ignore_whitespace_char', True)
        ])),
        ('__COMMENT__remember_session', '''
    // Remember and restore cursor position, selections, bookmarks,
    // and foldings each time a file is closed and re-opened.
    // This is helpful to resume your work from where you left off.
    // It does not remember any sublime sessions as name might suggest.'''),
        ('remember_session', True),
        ('__COMMENT__layout', '''
    // Configure the layout when opening new files.
    // This only takes effect if the "new_file_on_format" option is true.
    // Accepted values: "2cols", "2rows", "single" OR false'''),
        ('layout', OrderedDict([
            ('enable', '2cols'),
            ('sync_scroll', True)
        ])),
        ('__COMMENT__environ', '''
    // A set of directories where executable programs are located.
    // These can be absolute paths to module directories or Python zipfiles.
    // Any environment variables like PATH, PYTHONPATH, GEM_PATH, GOPATH,
    // GOROOT, GOBIN, TMPDIR, WHATEVER, etc. can be added here.
    // This is similar to running 'export PYTHONPATH="/path/to/my/site-packages"'
    // from the terminal. It is temporary, your system environment remains untouched.
    // On Windows, you can use either escaped backslashes (e.g., "C:\\a\\b\\c") or
    // forward slashes (e.g., "C:/a/b/c") as path separators for all other options.
    // Tip: Activating "print_on_console" will help to set the correct environment.'''),
        ('environ', OrderedDict([
            ('print_on_console', False),
            ('PATH', []),
            ('GEM_PATH', []),
            ('PYTHONPATH', []),
            ('OLALA', [])
        ])),
        ('__COMMENT__format_on_priority', '''
    // This option resolves the syntax conflicts described in "format_on_save".
    // It acts as an override and only applies to the following options:
    // 1. "format_on_save"
    // 2. "format_on_paste"
    // Syntaxes in this option always take precedence over the syntaxes specified there.
    // All syntaxes must be unique without any duplicates.'''),
        ('format_on_priority', OrderedDict([
            ('enable', False),
            ('csscomb', NoIndent(['css'])),
            ('jsbeautifier', NoIndent(['js']))
        ])),
        ('__COMMENT__auto_format', '''
    // This option enables auto-detect formatting for file.
    // Configure it here and/or by using the dot files in your working folder.
    // If both methods are used, the config from the dot files will override this embedded one.
    // Advantage: The embedded one can handle both saved and unsaved files,
    // while the dot files variant only applies to saved files, as unsaved files
    // (puffer in view) never have a working dir to contain dot files.
    //
    // This option supports chaining multiple formatters in a single run.
    // Chaining requires a list type with a maximum of ''' + str(MAX_CHAIN_PLUGINS) + ''' items in a list.
    //
    // By default, "format_on_save" and "format_on_paste" use a boolean value: false OR true
    // But you can use the dictionary format to exclude dirs, files, extensions and syntaxes:
    // "format_on_save": {
    //     "exclude_dirs_regex": [".*(\\.git|node_modules|__pycache__|env).*", ".*/project/test"],
    //     "exclude_files_regex": [".*test_file\\.py\\$", ".*/project/test/config\\.json"],
    //     "exclude_extensions_regex": ["ya?ml", "mjs", "json"],
    //     "exclude_syntaxes": []
    // }
    // Terminology: Hidden dot files, like .bashrc, do not have an extension to exclude.
    // More about this feature, see README.md > Auto-detect Formatting'''),
        ('auto_format', OrderedDict([
            ('__COMMENT__auto_format_a', '/*'),
            ('config', OrderedDict([
                ('format_on_save', False),
                ('format_on_paste', False)
            ])),
            ('python', NoIndent(['isort', 'black'])),
            ('json', 'jsbeautifier'),
            ('php', OrderedDict([
                ('uid', 'phpcsfixer')
            ])),
            ('html', OrderedDict([
                ('uid', 'jsbeautifier'),
                ('exclude_syntaxes', OrderedDict([
                    ('html', NoIndent(['markdown']))
                ]))
            ])),
            ('__COMMENT__auto_format_b', '*/')
        ])),
        ('__COMMENT__formatters', '''
    // THIRD-PARTY PLUGINS LEVEL
    // Info: Preferences > Package Settings > Formatter > Modules Info'''),
        ('formatters', OrderedDict([
            ('examplemodule', OrderedDict([
                ('__COMMENT__enable', '''// Plugin activation.
            // By default, all plugins are disabled.'''),
                ('enable', False),
                ('__COMMENT__format_on_save', '''
            // Auto formatting whenever the current file is being saved.
            // This option should be used for plugins with unique syntaxes.
            // For multi plugins with the same syntaxes, the first plugin takes precedence.
            // Remove the identical syntaxes from one of the plugins to avoid conflicts.
            // For example:
            // Plugin A (enabled): syntaxes ["css", "js"]
            // Plugin B (enabled): syntaxes ["html", "css"]
            // In the case you want to use Plugin B with "css", then you should remove
            // the "css" from plugin A or just disable it, as there is no guarantee of the
            // execution order between the two, and determining your favorist is not possible.
            // Solution: Use the "format_on_priority" option to workaround this.
            //
            // By default, this option uses a boolean value: false OR true
            // To exclude dirs, files, extensions and syntaxes, use a dictionary format:
            // "format_on_save": {
            //     "exclude_dirs_regex": [".*(\\.git|node_modules|__pycache__|env).*", ".*/project/test"],
            //     "exclude_files_regex": [".*test_file\\.py\\$", ".*/project/test/config\\.json"],
            //     "exclude_extensions_regex": ["ya?ml", "mjs", "json"],
            //     "exclude_syntaxes": []
            // }
            // Terminology: Hidden dot files, like .bashrc, do not have an extension to exclude.'''),
                ('format_on_save', False),
                ('__COMMENT__format_on_paste', '''
            // Auto formatting whenever code is pasted into the current file.
            // This option works the same way as "format_on_save".
            // So the mentioned syntax conflicts and solution are the same.
            //
            // Also you can use the same dictionary format to exclude:
            // dirs, files, extensions, and syntaxes'''),
                ('format_on_paste', False),
                ('__COMMENT__new_file_on_format', '''
            // Create a new file containing formatted code.
            // The value of this option is the suffix of the new file being renamed.
            // Suffix must be of type string. =true, =false means =false
            // Note: It will overwrite any existing file that has the same new name in
            // the same location.
            // For example:
            // "new_file_on_format": "min", will create a new file:
            // myfile.raw.js -> myfile.raw.min.js'''),
                ('new_file_on_format', False),
                ('__COMMENT__dir_format', '''
            // Recursive directory formatting, regardless of depth.
            // This option requires an existing and currently opened file
            // to serve as the starting point.
            // - For the sake of convenience, two new folders will be created at
            //   the same level as the file, which will contain all failed and
            //   successfully formatted files. Your original files remain unchanged.
            // - The "new_file_on_format" option can be used to rename files
            //   at the same time if needed.
            // - The "format_on_save" option above, which only works in the
            //   single-file mode, does not take effect here.
            // - All none-text files (binary) will be automatically ignored.
            // - To STOP the current formatting process, press any of the
            //   arrow keys (up, down, left, right) on your keyboard.
            // Any literal "$" must be escaped to "\\$" to distinguish it from
            // the variable expansion "${...}". This important rule applies
            // to the entire content of this settings file!
            //
            // By default, this option uses a boolean value: false OR true
            // To exclude dirs, files, extensions and syntaxes, use a dictionary format:
            // "dir_format": {
            //     "exclude_dirs_regex": [".*(\\.git|node_modules|__pycache__|env).*", ".*/project/test"],
            //     "exclude_files_regex": [".*test_file\\.py\\$", ".*/project/test/config\\.json"],
            //     "exclude_extensions_regex": ["ya?ml", "mjs", "json"],
            //     "exclude_syntaxes': []
            // }'''),
                ('dir_format', False),
                ('__COMMENT__syntaxes', '''
            // Syntax support based on the scope name, not file extension.
            // Syntax name is part of the scope name and can be retrieved from:
            // Tools > Developer > Show Scope Name
            // End-users are advised to consult plugin manpages to add more syntaxes.
            // The wildcard syntax "*" will accept any syntax, regardless of syntax type.'''),
                ('syntaxes', NoIndent(['css', 'html', 'js', 'php'])),
                ('__COMMENT__exclude_syntaxes', '''
            // Exclude a list of syntaxes associated with an individual syntax key.
            // The wildcard syntax "*" will accept any key, regardless of syntax type.
            // This option is useful to exclude part of the scope selector.
            // For example: text.html.markdown, want html but wish to filter out html.markdown.'''),
                ('exclude_syntaxes', OrderedDict([
                    ('html', NoIndent(['markdown'])),
                    ('*', NoIndent(['markdown']))
                ])),
                ('__COMMENT__interpreter_path', '''
            // Path to the interpreter.
            // Omit this option will force Formatter to detect interpreter on PATH and
            // automatically set them for you.
            // Or you can set the basename as the interpreter name to search on PATH or
            // locally, similar to how it is done with the "executable_path" option.'''),
                ('interpreter_path', NoIndent(['${HOME}/example/path/to\\$my/php.exe'])),
                ('__COMMENT__executable_path', '''
            // Path to the plugin executable.
            // This option can be either a string or a list of executable paths.
            // - If this option is omitted or set to null, then the global executable
            //   on PATH will be used, OR the local executable if automatically found.
            // - If this option is exactly the basename, then it will be used as the
            //   executable name and searched for on the PATH.
            //   Basename can be with or without dot.extension as both variants are the same.
            //   For example: "fiLe.exe" (Windows only), "fiLe" (Windows + Unix + Linux)
            // System variable expansions like ${HOME}, ${USER} etc. and the Sublime Text
            // specific ${packages} can be used to assign paths.
            // Note: Again, any literal "$" must be escaped to "\\$" to distinguish
            // it from the variable expansion "${...}".'''),
                ('executable_path', NoIndent(['${HOME}/example/path/to\\$my/php-cs-fixer.phar'])),
                ('__COMMENT__config_path', '''
            // Path to the config file for each individual syntaxes.
            // Syntax keys must match those in the "syntaxes" option above.
            // A single config file can be used for all syntaxes.
            // In that case, the key must be named: "default"
            // - You can choose another config file format as the default one
            //   provided by Formatter if supported by the third-party plugin.
            // - Formatter provides a set of default config files under
            //   "formatter.assets/config" folder for getting start.
            //   Avoid using the reference files with the suffix '.master.'
            //   directly, as they may be overwritten by future updates.
            // - Any auto-detected local config dotfile within the file
            //   tree always takes precedence over this option.
            // To ignore the local config dotfile in favor of this option:
            // 1. Set "ignore_dotfiles" to true, OR
            // 2. Remove or rename the detected local config dotfile, OR
            // 3. Use the Quick Options: Ignore Config Dotfiles, OR
            // 4. Place an '.sublimeformatter.ignore.json' file inside
            //    the working root folder. The structure of this file is
            //    explained in README.md > Auto-detect Formatting'''),
                ('config_path', OrderedDict([
                    ('ignore_dotfiles', False),
                    ('css', '${packages}/User/formatter.assets/config/only_css_rc.json'),
                    ('php', '${packages}/User/formatter.assets/config/only_php_rc.json'),
                    ('default', '${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json')
                ])),
                ('__COMMENT__args', '''
            // Array of additional arguments for the command line.'''),
                ('args', NoIndent(['--basedir', './example/my/foo', '--show-bar', 'yes'])),
                ('__COMMENT__render_extended', '''
            // This option is specifically designed for type graphic.
            // It enables SVG image generation for saving.
            // Enable it if you need SVG image at the cost of processing time.
            // Unlike the generic method, this method only supports SVG generation.'''),
                ('render_extended', False),
                ('__COMMENT__fix_commands', '''
            // Manipulate hardcoded command-line arguments.
            // This option allow you to modify hardcoded parameters, values and
            // their positions without digging into the source code.
            // This feature is primarily intended to temporarily fix bugs until
            // an official solution is implemented.
            // Note: Hardcoded args can be changed (rarely) by any release updates.
            // Enable debug mode will help to find all current hardcoded args.
            // Use "args" option above to add, this option to remove or manipulate.
            // Using regex: Again, any literal "$" must be escaped to "\\$" to
            // distinguish it from the variable expansion "${...}". Accepted args:
            // [search, [replace, [index, count, new position]]], where:
            // - search:   @type:str (regex)
            // - replace:  @type:str
            // - index:    @type:int (the number is known as a list index); required!
            // - count:    @type:int (the matching occurrences per index, 0 = all); required!
            // - position: @type:int (move old index pos. to new/old one, -1 = delete index); required!'''),
                ('fix_commands', [
                    NoIndent(['--autocorrect', '--autocorrect-all', 4, 0, 4]),
                    NoIndent(['^.*?auto.*\\$', '--with', 4, 1, 5]),
                    NoIndent(['${packages}/to/old', '${packages}/to/new', 3, 0, 3]),
                    NoIndent(['css', 5, 0, 7]),
                    NoIndent([3, 0, 4]),
                    NoIndent([2, 0, -1]),
                    NoIndent(['--show-bar', 'xxx', 2, 0, -1])
                ])
            ])),
            ('examplegeneric', OrderedDict([
                ('__COMMENT__generic', '''// Formatter provides 2 methods to add custom plugins:
            // - Generic: this one, you design the bridge yourself. Suitable for simple tasks.
            // - Modules: requires writing Python modules for complex tasks.
            // Note: The Generic method requires a Sublime Text restart after adding or changing
            // the "name" and "type" keys. Also, avoid reusing existing UID keys in JSON.'''),
                ('__COMMENT__name', '''
            // The Capitalized plugin name, preferred in PascalCase style (REQUIRED!)
            // This will appear in the Sublime menu and other commands.'''),
                ('name', 'ExampleGeneric'),
                ('__COMMENT__type', '''
            // The plugin type (REQUIRED!)
            // This will categorize the plugin. Accepted values:
            // "beautifier", "minifier", "converter", "graphic", or any string of your choice.'''),
                ('type', 'beautifier'),
                ('__COMMENT__render_extended', '''
            // This will activate the "args_extended" option for the graphic type
            // to generate extended files like SVG for saving.'''),
                ('render_extended', False),
                ('__COMMENT__success_code', '''
            // The exit code for the third-party plugin (optional, default to 0).'''),
                ('success_code', 0),
                ('__COMMENT__dotfiles', '''
            // Local config dotfiles supported by your plugin (optional).
            // These files will be auto detected and used as config file within your project.'''),
                ('dotfiles', NoIndent(['.pluginrc', 'pyproject.toml', '.pycodestyle', 'setup.cfg', 'tox.ini', '.pep8', '.editorconfig'])),
                ('__COMMENT__df_ident', '''
            // Keywords to identify special local config dotfiles (optional).
            // Special dotfiles: "pyproject.toml", ".pycodestyle", "setup.cfg", "tox.ini", ".pep8", ".editorconfig"
            // contain specific sections, such as "[tool.autopep8]" for identification.
            // This is only necessary if the uid, here "examplegeneric", differs from "autopep8".'''),
                ('df_ident', NoIndent(['juliet', 'romeo', 'autopep8'])),
                ('__COMMENT__enable', '''
            // Same as the one in the examplemodule.'''),
                ('enable', False),
                ('__COMMENT__format_on_save', '''// Same as the one in the examplemodule.'''),
                ('format_on_save', False),
                ('__COMMENT__format_on_paste', '''// Same as the one in the examplemodule.'''),
                ('format_on_paste', False),
                ('__COMMENT__new_file_on_format', '''// Same as the one in the examplemodule, but disabled/unused for type graphic.'''),
                ('new_file_on_format', False),
                ('__COMMENT__dir_format', '''// Same as the one in the examplemodule, but disabled/unused for type graphic.'''),
                ('dir_format', False),
                ('__COMMENT__syntaxes', '''// Same as the one in the examplemodule.'''),
                ('syntaxes', NoIndent(['css', 'html', 'js', 'php'])),
                ('__COMMENT__exclude_syntaxes', '''// Same as the one in the examplemodule.'''),
                ('exclude_syntaxes', {}),
                ('__COMMENT__interpreter_path', '''// Same as the one in the examplemodule.'''),
                ('interpreter_path', NoIndent(['${HOME}/example/path/to\\$my/php.exe'])),
                ('__COMMENT__executable_path', '''// Same as the one in the examplemodule.'''),
                ('executable_path', NoIndent(['${HOME}/example/path/to\\$my/php-cs-fixer.phar'])),
                ('__COMMENT__config_path', '''// Same as the one in the examplemodule.'''),
                ('config_path', OrderedDict([
                    ('ignore_dotfiles', False),
                    ('css', '${packages}/User/formatter.assets/config/only_css_rc.json'),
                    ('php', '${packages}/User/formatter.assets/config/only_php_rc.json'),
                    ('default', '${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json')
                ])),
                ('__COMMENT__args', '''
            // Main commands to trigger the formatting process.
            // You can either set the qualified paths directly or use variable substitution for:
            // - "interpreter_path"   : "{{i}}"
            // - "executable_path"    : "{{e}}", "{{e=node}}" (for local executable auto-resolving with runtime type node)
            // - "config_path"        : "{{c}}"
            // - SPECIAL CASE GRAPHIC : "{{o}}" (output PNG image, e.g: "args": [... "--output", "{{o}}"])
            // Variable substitution provides advanced mechanisms such as auto-search path, auto-config, etc.
            // SPECIAL CASE GRAPHIC requirements:
            // 1. The plugin must support exporting PNG format.
            // 2. The hardcoded "{{o}}" MUST ALWAYS be included in "args".
            //    You might regret using your own path instead of "{{o}}" or daring to omit "{{o}}" in this case.
            // In all other cases, output may not be as a file; use "-" or "--" instead.'''),
                ('args', NoIndent(['{{i}}', '{{e=node}}', '--config', '{{c}}', '--basedir', './example/my/foo', '--'])),
                ('__COMMENT__args_extended', '''
            // This is for the SPECIAL CASE GRAPHIC to saving extended graphic files.
            // To use this, the trigger option "render_extended" above must be activated.
            // Sublime Text only supports PNG, JPG, and GIF images. Formatter uses PNG to display
            // image in view and generates the same image in various formats for you.
            // WARNING: Formatter will loop subprocess to render extended files. This means, process
            // will takes more time. This option might be useful for the final step to production.
            // "key":["value",..], where key is the output file extension, value is the command arguments.'''),
                ('args_extended', OrderedDict([
                    ('svg', NoIndent(['{{e}}', '--config', '{{c}}', '--blabla-format', 'svgv5', '--output', '{{o}}'])),
                    ('pdf', NoIndent(['{{e}}', '--config', '{{c}}', '--blabla-format', 'pdf2001', '--output', '{{o}}']))
                ]))
            ])),
            ('__COMMENT__end_explanation', '// -- END of explanation --')
        ]))
    ])

    beautifiers, minifiers, converters, graphics, custom = build_formatter_sublime_settings_children(formatter_map)
    categories = [
        ('beautifiers', beautifiers),
        ('minifiers', minifiers),
        ('converters', converters),
        ('graphics', graphics),
        ('custom', custom)
    ]
    for category_name, category in categories:
        sorted_category = sorted(category, key=lambda x: list(x.keys())[0])
        if category:
            sublime_settings['formatters'].update({'__COMMENT__cat_' + category_name: '\n        // -- ' + category_name.upper() + ' --'})
        for x in sorted_category:
            sublime_settings['formatters'].update(x)

    json_text = json.dumps(sublime_settings, cls=NoIndentEncoder, ensure_ascii=False, indent=4)

    pattern_comment_and_commas = re.compile(r'"__COMMENT__.+"[\s\t]*:[\s\t]*"(.+)",?|[^:]//[^\n]+')
    pattern_comment_linebreaks = re.compile(r'^(.*?//.*)$', re.MULTILINE)
    pattern_comma_before_comment = re.compile(r',([\s\n]+)(/\*)')
    json_text = pattern_comment_and_commas.sub(r'\1', json_text)
    json_text = re.sub(r'(?<!")\\\"(?!")', '"', json_text)  # replace all \" but not "\""
    json_text = pattern_comma_before_comment.sub(r'\1\2', json_text)
    matched_lines = pattern_comment_linebreaks.findall(json_text)
    for line in matched_lines:
        modified_line = re.sub(r'(?<!")\\\"(?!")', '"', line).replace('\\n', '\n')
        json_text = json_text.replace(line, modified_line)

    s = [
        r'["--autocorrect", "--autocorrect-all", 4, 0, 4],',
        r'["^.*?auto.*\\$", "--with", 4, 1, 5],',
        r'["${packages}/to/old", "${packages}/to/new", 3, 0, 3],',
        r'["css", 5, 0, 7],',
        r'[3, 0, 4],',
        r'[2, 0, -1],',
        r'["--show-bar", "xxx", 2, 0, -1]'
    ]
    r = [
        r'["--autocorrect", "--autocorrect-all", 4, 0, 4], // no index pos change',
        r'["^.*?auto.*\\$", "--with", 4, 1, 5], // using escaped "\\$" regex, move index 4 to pos 5',
        r'["${packages}/to/old", "${packages}/to/new", 3, 0, 3], // variable expansion, no escaped "$"',
        r'["css", 5, 0, 7], // replace the value in index 5 with "css", move it to pos 7',
        r'[3, 0, 4], // just move index 3 to the new pos 4. (count 0 irrelevant)',
        r'[2, 0, -1], // just delete the index 2. (count 0 irrelevant)',
        r'["--show-bar", "xxx", 2, 0, -1] // enough bar, pop it out. ("xxx", 2, 0 irrelevant)'
    ]
    for s, r in zip(s, r):
        json_text = json_text.replace(s, r)

    return strip_trailing(json_text)


def create_package_config_files():
    directory = join(sublime.packages_path(), PACKAGE_NAME)

    try:
        makedirs(directory, exist_ok=True)
    except OSError as e:
        if e.errno != EEXIST:
            log.error('Could not create directory: %s', directory)
        return False

    file_functions = {
        'Context.sublime-menu': build_context_sublime_menu,
        'Main.sublime-menu': build_main_sublime_menu,
        'Formatter.sublime-commands': build_formatter_sublime_commands,
        'Example.sublime-keymap': build_example_sublime_keymap,
        'Formatter.sublime-settings': build_formatter_sublime_settings
    }

    # Import must be included here, not in the header
    from ..modules import formatter_map

    for file_name, build_function in file_functions.items():
        try:
            text = build_function(formatter_map)
            file = join(directory, file_name)
            if isfile(file):
                hash_src = hashlib.md5(text.encode('utf-8')).hexdigest()
                hash_dst = HashHandler.md5f(file)
                if hash_src == hash_dst:
                    continue

            with open(file, 'w', encoding='utf-8') as f:
                f.write(text)
        except Exception as e:
            log.error('Error while saving %s: %s', file, e)
            return False

    try:
        for file in [join(directory, QUICK_OPTIONS_SETTING_FILE), ConfigHandler.quick_options_config_file()]:
            if not isfile(file):
                with open(file, 'w', encoding='utf-8') as f:
                    json.dump({}, f, ensure_ascii=False, indent=4)
    except Exception as e:
        log.error('Error while saving %s: %s', file, e)
        return False

    return True
