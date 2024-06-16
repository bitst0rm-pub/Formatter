import re
import uuid
import json
import logging
from collections import OrderedDict

import sublime

from . import common
from ..modules import formatter_map

log = logging.getLogger(__name__)


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

    formatters = common.config.get('formatters', {})
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
    sort_and_extend = lambda lst, caption=None: context_menu[0]['children'].extend(
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
                                        ('default', '// Do not edit the left-hand pane.\n'
                                                    '// Pick up needed items while keeping the JSON structure intact.\n'
                                                    '{\n\t$0\n}\n')
                                    ]))
                                ]),
                                OrderedDict([
                                    ('caption', 'Modules Info'),
                                    ('command', 'modules_info')
                                ]),
                                OrderedDict([
                                    ('caption', 'Open Config Folders'),
                                    ('command', 'open_config_folders')
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
                                    ('caption', 'Version Info'),
                                    ('command', 'version_info')
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
    sort_and_extend = lambda lst, caption=None: main_menu[0]['children'][0]['children'].extend(
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

    formatters = common.config.get('formatters', {})
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
            ('caption', 'Formatter: Version Info'),
            ('command', 'version_info')
        ]),
        OrderedDict([
            ('caption', 'Formatter: Changelog'),
            ('command', 'open_changelog')
        ]),
        OrderedDict([
            ('caption', 'Formatter: Modules Info'),
            ('command', 'modules_info')
        ]),
        OrderedDict([
            ('caption', 'Formatter: Open Config Folders'),
            ('command', 'open_config_folders')
        ]),
        OrderedDict([
            ('caption', 'Formatter: Key Bindings'),
            ('command', 'key_bindings')
        ]),
        OrderedDict([
            ('caption', 'Formatter: Backup Settings'),
            ('command', 'backup_manager'),
            ('args', OrderedDict([
                ('type', 'backup')
            ]))
        ]),
        OrderedDict([
            ('caption', 'Formatter: Restore Settings'),
            ('command', 'backup_manager'),
            ('args', OrderedDict([
                ('type', 'restore')
            ]))
        ]),
        OrderedDict([
            ('caption', 'Formatter: Quick Options'),
            ('command', 'quick_options')
        ]),
        OrderedDict([
            ('caption', 'Formatter: Auto Format File'),
            ('command', 'auto_format_file')
        ])
    ]

    beautifiers, minifiers, converters, graphics, custom = build_formatter_sublime_commands_children(formatter_map)
    sort_and_extend = lambda lst, caption=None: sublime_commands.extend(
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

    formatters = common.config.get('formatters', {})
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

    sort_key = lambda x: x['args']['uid']
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
                ('new_file_on_format', False),
                ('recursive_folder_format', OrderedDict([
                    ('enable', False),
                    ('exclude_folders_regex', []),
                    ('exclude_files_regex', []),
                    ('exclude_extensions', []),
                    ('exclude_syntaxes', [])
                ])),
                ('syntaxes', NoIndent(config['syntaxes']))
            ])

            typ = config.get('type', None)
            if typ == 'graphic':
                child.pop('new_file_on_format')
                child.pop('recursive_folder_format')
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
                child['config_path'] = {key: common.join('${packages}', 'User', common.ASSETS_DIRECTORY, 'config', value) for key, value in config['config_path'].items()}
                default_value = child['config_path'].pop('default', None)
                sorted_config_path = OrderedDict(sorted(child['config_path'].items()))
                if default_value:
                    sorted_config_path['default'] = default_value
                child['config_path'] = sorted_config_path

            comment = config.get('comment', None)
            if comment is not None and isinstance(comment, str) and len(comment) > 0:
                truncated_comment = comment[:200] + '...' if len(comment) > 200 else comment
                child['__COMMENT__child'] = '/* ' + truncated_comment.replace('/*', '').replace('*/', '') + ' */'  # '/* ' is marker for pattern_comma_before_comment

            target_list = type_to_list.get(config['type'], custom)
            target_list.append({uid:child})

    return beautifiers, minifiers, converters, graphics, custom

def build_formatter_sublime_settings(formatter_map):
    sublime_settings = OrderedDict([
            ('__COMMENT__debug', '''// Enable debug mode to view errors in the console.
    // Accepted values: true (verbose), false, OR "status" (recommended)'''),
            ('debug', False),
            ('__COMMENT__open_console_on_failure', '''
    // Auto open the console panel whenever formatting fails.
    // This is useful when combined with "debug": "status" or true'''),
            ('open_console_on_failure', False),
            ('__COMMENT__timeout', '''
    // Timeout to abort subprocess in seconds.
    // Default to 10 seconds. Set to false to disable the timeout.'''),
            ('timeout', 10),
            ('__COMMENT__custom_modules', '''
    // Integrate your custom modules into the Formatter ecosystem.
    // All paths to files and folders must be local.'''),
            ('custom_modules', OrderedDict([
                ('config', []),
                ('modules', []),
                ('libs', [])
            ])),
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
                ('ignore_whitespace_char', True)
            ])),
            ('__COMMENT__remember_session', '''
    // Remember and restore cursor position, selections and bookmarks
    // each time a file is closed and re-opened.
    // This is helpful to resume your work from where you left off.
    // It does not remember the whole session as name might suggest.'''),
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
    // forward slashes (e.g., "C:/a/b/c") as path separators for all other options.'''),
            ('environ', OrderedDict([
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
    // This option enables auto-detect formatting for file using a single command.
    // Configure it here and/or by using the dot files in your working folder.
    // If both methods are used, the config from the dot files will override this embedded one.
    // More about this feature, see README.md > Auto-detect Formatting'''),
            ('auto_format', OrderedDict([
                ('__COMMENT__auto_format_a', '/*'),
                ('config', OrderedDict([
                    ('format_on_save', False),
                    ('format_on_paste', False)
                ])),
                ('json', OrderedDict([
                    ('uid', 'jsbeautifier')
                ])),
                ('html', OrderedDict([
                    ('uid', 'jsbeautifier'),
                    ('exclude_syntaxes', OrderedDict([
                        ('html', NoIndent(['markdown']))
                    ]))
                ])),
                ('python', OrderedDict([
                    ('uid', 'autopep8')
                ])),
                ('__COMMENT__auto_format_b', '*/')
            ])),
            ('__COMMENT__formatters', '''
    // THIRD-PARTY PLUGINS LEVEL
    // Help: Preferences > Package Settings > Formatter > Modules Info'''),
            ('formatters', OrderedDict([
                ('examplegeneric', OrderedDict([
                    ('__COMMENT__generic', '''// Formatter provides 2 methods to add custom plugins:
            // - Generic: this one, you design the bridge yourself. Suitable for simple tasks.
            // - Modules: requires writing Python modules for complex tasks.
            // Note: The Generic method requires a Sublime Text restart after adding or changing
            // the "name" and "type" keys. Also, avoid reusing existing UID keys in JSON.'''),
                    ('__COMMENT__name', '''
            // The capitalized Plugin name (REQUIRED!)
            // This will appear in the Sublime menu and other commands.'''),
                    ('name', 'Example Generic'),
                    ('__COMMENT__type', '''
            // The plugin type (REQUIRED!)
            // This will categorize the plugin. Accepted values:
            // "beautifier", "minifier", "converter", "graphic", or any string of your choice.'''),
                    ('type', 'beautifier'),
                    ('__COMMENT__render_extended', '''
            // This will activate the "args_extended" option for the graphic type
            // to generate extended files like SVG for download.'''),
                    ('render_extended', False),
                    ('__COMMENT__success_code', '''
            // The exit code for the third-party plugin (optional, default is 0).'''),
                    ('success_code', 0),
                    ('__COMMENT__enable', '''
            // Same as the one in the examplemodule.'''),
                    ('enable', False),
                    ('__COMMENT__format_on_save', '''// Same as the one in the examplemodule.'''),
                    ('format_on_save', False),
                    ('__COMMENT__format_on_paste', '''// Same as the one in the examplemodule.'''),
                    ('format_on_paste', False),
                    ('__COMMENT__new_file_on_format', '''// Same as the one in the examplemodule, but disabled/unused for type graphic.'''),
                    ('new_file_on_format', False),
                    ('__COMMENT__recursive_folder_format', '''// Same as the one in the examplemodule, but disabled/unused for type graphic.'''),
                    ('recursive_folder_format', {}),
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
                        ('css', '${packages}/User/formatter.assets/config/only_css_rc.json'),
                        ('php', '${packages}/User/formatter.assets/config/only_php_rc.json'),
                        ('default', '${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json')
                    ])),
                    ('__COMMENT__args', '''
            // Main commands to trigger the formatting process.
            // You can either set the paths directly or use variable substitution for:
            // - "interpreter_path"   : "{{i}}"
            // - "executable_path"    : "{{e}}", "{{e=node}}" (for local executable auto-resolving with runtime type node)
            // - "config_path"        : "{{c}}"
            // - SPECIAL CASE GRAPHIC : "{{o}}" (output PNG image, e.g: "args": [... "--output", "{{o}}"])
            // Variable substitution allows advanced mechanisms such as auto-search path, auto-config, etc.
            // SPECIAL CASE GRAPHIC requirements:
            // 1. The plugin must support exporting PNG format.
            // 2. The hardcoded "{{o}}" MUST ALWAYS be included in "args".
            //    You might regret using your own path instead of "{{o}}" or daring to omit "{{o}}" in this case.
            // In all other cases, output may not be as a file; use "-" or "--" instead.'''),
                    ('args', NoIndent(['{{i}}', '{{e=node}}', '--config', '{{c}}', '--basedir', './example/my/foo', '--'])),
                    ('__COMMENT__args_extended', '''
            // This is for the SPECIAL CASE GRAPHIC to downloading extended graphic files.
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
                ('examplemodule', OrderedDict([
                    ('__COMMENT__enable', '''// Plugin activation.
            // By default, all plugins are disabled and disappear from the menu.'''),
                    ('enable', False),
                    ('__COMMENT__format_on_save', '''
            // Auto formatting whenever the current file/view is being saved.
            // This option should be used for plugins with unique syntaxes.
            // For multi plugins with the same syntaxes, the first plugin takes precedence.
            // Remove the identical syntaxes from one of the plugins to avoid conflicts.
            // For example:
            // Plugin A (enabled): syntaxes ["css", "js"]
            // Plugin B (enabled): syntaxes ["html", "css"]
            // In the case you want to use Plugin B with "css", then you should remove
            // the "css" from plugin A or just disable it, as there is no guarantee of the
            // execution order between the two, and determining your favorist is not possible.
            // Solution: Use the "format_on_priority" option to workaround this.'''),
                    ('format_on_save', False),
                    ('__COMMENT__format_on_paste', '''
            // Auto formatting whenever code is pasted into the current file/view.
            // This option is affected by the same syntax conflict, so its solutions
            // are identical to those mentioned above for the "format_on_save" option.'''),
                    ('format_on_paste', False),
                    ('__COMMENT__new_file_on_format', '''
            // Create a new file containing formatted codes.
            // The value of this option is the suffix of the new file being renamed.
            // Suffix must be of type string. =true, =false and all other types imply =false
            // Note: It will overwrite any existing file that has the same new name in
            // the same location.
            // For example:
            // "new_file_on_format": "min", will create a new file:
            // myfile.raw.js -> myfile.raw.min.js'''),
                    ('new_file_on_format', False),
                    ('__COMMENT__recursive_folder_format', '''
            // Recursively format the entire folder with unlimited depth.
            // This option requires an existing and currently opened file
            // to serve as the starting point. Files will be opened and closed.
            // For the sake of convenience, two new folders will be created at
            // the same level as the file, which will contain all failed and
            // successfully formatted files. The "new_file_on_format" option
            // can be used to rename files if needed.
            // The "format_on_save" option above, which applies only to
            // single files, does not take effect here.
            // All none-text files (binary) will be automatically ignored.
            // Note: Placing files directly on the Desktop or elsewhere without
            // enclosing them within a folder can lead to accidental formatting.
            // Any literal "$" must be escaped to "\\$" to distinguish it from
            // the variable expansion "${...}". This important rule applies
            // to the entire content of this settings file!'''),
                    ('recursive_folder_format', OrderedDict([
                        ('enable', False),
                        ('exclude_folders_regex', NoIndent(['Spotlight-V100', 'temp', 'cache', 'logs', '^_.*foo\\$'])),
                        ('exclude_files_regex', NoIndent(['^._.*$', '.*bar.exe'])),
                        ('exclude_extensions', NoIndent(['DS_Store', 'localized', 'TemporaryItems', 'Trashes', 'db', 'ini', 'git', 'svn', 'tmp', 'bak'])),
                        ('exclude_syntaxes', [])
                    ])),
                    ('__COMMENT__syntaxes', '''
            // Syntax support based on the scope name, not file extension.
            // Syntax name is part of the scope name and can be retrieved from:
            // Tools > Developer > Show Scope Name
            // End-users are advised to consult plugin manpages to add more syntaxes.'''),
                    ('syntaxes', NoIndent(['css', 'html', 'js', 'php'])),
                    ('__COMMENT__exclude_syntaxes', '''
            // Exclude a list of syntaxes for an individual syntax key.
            // A list of excluded syntaxes can be applied to all syntax definitions.
            // In this case, the key must be named: "all".
            // This option is useful to exclude part of the scope selector.
            // For example: text.html.markdown, want html but wish to filter out html.markdown.'''),
                    ('exclude_syntaxes', OrderedDict([
                        ('html', NoIndent(['markdown'])),
                        ('all', NoIndent(['markdown']))
                    ])),
                    ('__COMMENT__interpreter_path', '''
            // Path to the interpreter to run the third-party plugin.
            // Just for the sake of completeness, but it is unlikely that you will ever need
            // to use this option. Most of the programs you have installed are usually set
            // to run in the global environment, such as Python, Node.js, Ruby, PHP, etc.
            // Formatter is able to detect and automatically set them for you.
            // However, if you do need to use a specific interpreter, you can provide the path.
            // Alternatively, you can set the basename as the interpreter name to search on
            // PATH, similar to how it is done with the "executable_path" option.'''),
                    ('interpreter_path', NoIndent(['${HOME}/example/path/to\\$my/php.exe'])),
                    ('__COMMENT__executable_path', '''
            // Path to the third-party plugin executable to process formatting.
            // This option can be either a string or a list of executable paths.
            // - If this option is omitted or set to null, then the global executable
            //   on PATH will be used, if automatically found.
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
            // A single config file can be used to assign to all syntaxes.
            // In this case, the key must be named: "default"
            // Note:
            // - You can choose another config file format as the default one
            //   provided by Formatter if the third-party plugin supports it.
            // - Formatter provides a set of default config files under
            //   "formatter.assets/config" folder for your personal use.
            //   Do not use the reference files with suffix '.master.' directly.
            //   These files could be overwritten by any release updates.
            // - Options from this config file always have precedence over
            //   the options from any local project (per-project config dotfile).
            // - Disabling this option will force Formatter to auto resolve
            //   the per-project config dotfile in the file tree to use.
            // To disable this option:
            // 1. Set the config path of this option to null, OR
            // 2. Use the Quick Options: Ignore Config Path, OR
            // 3. Place an '.sublimeformatter.cfgignore.json' file inside
            //    the working root folder. The structure of this file is
            //    descripted in README.md > Auto-detect Formatting
            // Formatter will start to search up the file tree until a
            // '.sublimeformatter.cfgignore' file is found to bypass this option.'''),
                    ('config_path', OrderedDict([
                        ('css', '${packages}/User/formatter.assets/config/only_css_rc.json'),
                        ('php', '${packages}/User/formatter.assets/config/only_php_rc.json'),
                        ('default', '${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json')
                    ])),
                    ('__COMMENT__args', '''
            // Array of additional arguments for the command line.'''),
                    ('args', NoIndent(['--basedir', './example/my/foo', '--show-bar', 'yes'])),
                    ('__COMMENT__render_extended', '''
            // This option is specifically designed for type graphic.
            // It enables SVG image generation for download.
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
                ('__COMMENT__end_explanation', '''// -- END of explanation --
                ''')
            ]))
        ])

    beautifiers, minifiers, converters, graphics, custom = build_formatter_sublime_settings_children(formatter_map)
    categories = [beautifiers, minifiers, converters, graphics, custom]
    for category in categories:
        sorted_category = sorted(category, key=lambda x: list(x.keys())[0])
        for x in sorted_category:
            sublime_settings['formatters'].update(x)

    json_text = json.dumps(sublime_settings, cls=NoIndentEncoder, ensure_ascii=False, indent=4)

    pattern_comment_and_commas = re.compile(r'"__COMMENT__.+"[\s\t]*:[\s\t]*"(.+)",?|[^:]//[^\n]+')
    pattern_comment_linebreaks = re.compile(r'^(.*?//.*)$', re.MULTILINE)
    pattern_comma_before_comment = re.compile(r',([\s\n]+)(/\*)')
    json_text = pattern_comment_and_commas.sub(r'\1', json_text)
    json_text = json_text.replace('\\"', '"')
    json_text = pattern_comma_before_comment.sub(r'\1\2', json_text)
    matched_lines = pattern_comment_linebreaks.findall(json_text)
    for line in matched_lines:
        modified_line = line.replace(r'\"', '"').replace('\\n', '\n')
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
    directory = common.join(sublime.packages_path(), common.PACKAGE_NAME)

    try:
        common.os.makedirs(directory, exist_ok=True)
    except OSError as e:
        if e.errno != os.errno.EEXIST:
            log.error('Could not create directory: %s', directory)
        return False

    file_functions = {
        'Context.sublime-menu': build_context_sublime_menu,
        'Main.sublime-menu': build_main_sublime_menu,
        'Formatter.sublime-commands': build_formatter_sublime_commands,
        'Example.sublime-keymap': build_example_sublime_keymap,
        'Formatter.sublime-settings': build_formatter_sublime_settings
    }

    api = common.Base()

    for file_name, build_function in file_functions.items():
        try:
            text = build_function(formatter_map)
            file = common.join(directory, file_name)
            if common.isfile(file):
                hash_src = common.hashlib.md5(text.encode('utf-8')).hexdigest()
                hash_dst = api.md5f(file)
                if hash_src == hash_dst:
                    continue

            with open(file, 'w', encoding='utf-8') as f:
                f.write(text)
        except Exception as e:
            log.error('An error occurred while saving %s: %s', file, e)
            return False

    try:
        for file in [common.join(directory, common.QUICK_OPTIONS_SETTING_FILE), api.quick_options_config_file()]:
            if not common.isfile(file):
                with open(file, 'w', encoding='utf-8') as f:
                    json.dump({}, f, ensure_ascii=False, indent=4)
    except Exception as e:
        log.error('An error occurred while saving %s: %s', file, e)
        return False

    return True
