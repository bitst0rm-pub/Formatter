# Formatter

Formatter is a plugin for Sublime Text 3 & 4 to beautify and minify source code.

Features:

- Support for more than 20 major programming languages
- Ability to format entire file, single or multi selections
- Ability to format entire folder recursively
- Config files available for each 3rd-party plugin
- Offline functionality

Formatter has been thoroughly tested on MacOSX with Sublime Text `3` and `4` and it _should_ work fine on other platforms (not tested).


## Guides

- Table of Contents
  - [Plugins](#Plugins)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Usage](#usage)
  - [Troubleshooting](#troubleshooting)
  - [Todo](#todo)
  - [License](#license)


## Plugins

Formatter is useless without third-party plugins. It relies on external plugins in order to format code. These plugins need to be installed separately and can be easily disabled in the settings. To install third-party plugins, follow the instructions provided in the linked list below. To set up the plugins correctly, please consider the following:

- Check plugin requirements, eg. PHP-CS-Fixer needs PHP >=7.4.0 or Black requires Python >=3.7.0
- Ensure to pass the correct path to the plugin executable and
- Adjust their environment variables (PATH, PYTHONPATH etc.) in the `Formatter.sublime-settings`.

**Plugins that work with Formatter:**

1. [Beautysh](https://github.com/lovesegfault/beautysh): A Unix shell script beautifier that formats shell scripts for better readability.
2. [Black](https://github.com/ambv/black): A code formatter for Python that enforces a consistent style by automatically reformatting Python code.
3. [ClangFormat](https://clang.llvm.org/docs/ClangFormat.html): A tool that formats C, C++, Objective-C, and other related languages based on specified coding style rules.
4. [CleanCSS](https://github.com/jakubpawlowicz/clean-css-cli): A command-line tool that minifies and optimizes CSS files, removing unnecessary spaces, comments, etc.
5. [CSScomb](https://github.com/csscomb/csscomb.js): A coding style formatter for CSS files that rearranges properties in a predefined order.
6. [ESLint](https://github.com/eslint/eslint): A popular linting tool for JavaScript that identifies and fixes common coding errors and enforces consistent code style.
7. [HTMLMinifier](https://github.com/kangax/html-minifier): A tool to minify HTML code by removing unnecessary white spaces, comments, and other optimizations.
8. [HTML Tidy](https://github.com/htacg/tidy-html5): A library and command-line tool for cleaning up and formatting HTML code.
9. [JS Beautifier](https://github.com/beautify-web/js-beautify): A tool to beautify and format JavaScript, JSON, and CSS code.
10. JSONMax (built-in): A JSON beautifier
11. JSONMin (built-in): A JSON minifier
12. [Perltidy](https://github.com/perltidy/perltidy): A code formatter for Perl, which indents and aligns Perl code according to specified rules.
13. [PHP-CS-Fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer): A tool that fixes PHP coding standards issues and enforces a consistent coding style.
14. [Prettier](https://github.com/prettier/prettier): An opinionated code formatter that supports various programming languages and focuses on code consistency.
15. [Pretty Diff](https://github.com/prettydiff/prettydiff): A language-aware code comparison tool that can also format and minify code.
16. [PrettyTable](https://github.com/jazzband/prettytable): A Python library for displaying tabular data in a visually appealing ASCII table format.
17. [Python Minifier](https://github.com/dflook/python-minifier): A tool to minify Python code, making it smaller and harder to read, though it remains executable.
18. [RuboCop](https://github.com/rubocop-hq/rubocop): A code analyzer and formatter for Ruby, enforcing various style guidelines and best practices.
19. [SQL Formatter](https://github.com/sql-formatter-org/sql-formatter): A library and command-line tool for formatting SQL queries to improve readability.
20. SQLMin (built-in): A SQL minifier to reduce size and improve performance.
21. [Stylelint](https://github.com/stylelint/stylelint): A linter for CSS and SCSS code that helps maintain a consistent style and avoid errors.
22. [Terser](https://github.com/terser-js/terser): A JavaScript minifier that removes unnecessary characters and renames variables to make the code smaller.
23. [Uncrustify](https://github.com/uncrustify/uncrustify): A configurable source code beautifier for C, C++, Objective-C, and other related languages.
24. [YAPF](https://github.com/google/yapf): Yet Another Python Formatter, a tool to format Python code according to specified style guidelines.


Note: This list does not contain the complete languages that each plugin does support.
For example, Pretty Diff supports 45 languages, that would blow up the frame of this list here.<br/>
`build-in` plugins are integrated plugins that do not need to install by end-users.

| Languages | Beautify | Minify | Requirements | Config-Online |
| ------ | :------: | :------: | :------: | :------: |
| CSS, SCSS, Sass, Less, SugarSS | [Stylelint](https://github.com/stylelint/stylelint), [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), [CSScomb](https://github.com/csscomb/csscomb.js) | [CleanCSS CLI](https://github.com/jakubpawlowicz/clean-css-cli), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| HTML, XML | [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), [HTML Tidy](https://github.com/htacg/tidy-html5) | [HTMLMinifier](https://github.com/kangax/html-minifier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| JavaScript | [ESLint](https://github.com/eslint/eslint), [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [Pretty Diff](https://github.com/prettydiff/prettydiff), [`ClangFormat`](https://clang.llvm.org/docs/ClangFormat.html) | [Terser](https://github.com/terser-js/terser), [Pretty Diff](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://zed0.co.uk/clang-format-configurator) |
| JSON | [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), JSONMax (build-in) | [`Pretty Diff`](https://github.com/prettydiff/prettydiff), JSONMin (build-in) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| GraphQL | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| Markdown | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| TypeScript | [Prettier](https://github.com/prettier/prettier), [JS Beautifier](https://github.com/beautify-web/js-beautify), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| Vue | [Prettier](https://github.com/prettier/prettier), [JS Beautifier](https://github.com/beautify-web/js-beautify) | -- | Node.js | -- |
| YAML | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| Perl | [Perltidy](https://github.com/perltidy/perltidy) | -- | Perl | -- |
| PHP | [PHP-CS-Fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer) | -- | PHP >=`7.4.0` | [Yes](https://mlocati.github.io/php-cs-fixer-configurator) |
| Python | [YAPF](https://github.com/google/yapf), [`Black`](https://github.com/ambv/black) | [Python Minifier](https://github.com/dflook/python-minifier) | Python `>=3.7.0` | [Yes](https://python-minifier.com) |
| Ruby | [RuboCop](https://github.com/rubocop-hq/rubocop) | -- | Ruby | -- |
| Bash, Shell | [Beautysh](https://github.com/lovesegfault/beautysh) | -- | Python | -- |
| SQL, SQL dialects | [SQL Formatter](https://github.com/sql-formatter-org/sql-formatter) | SQLMin (build-in) | Node.js | [Yes](https://sql-formatter-org.github.io/sql-formatter) |
| CSV, TSV, DSV, Text | [PrettyTable](https://github.com/jazzband/prettytable) (build-in) | -- | Python | -- |
| C, C++, C#, Objective-C, D, Java, Pawn, VALA | [Uncrustify](https://github.com/uncrustify/uncrustify) | -- | None | [Yes](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| C, C++, C#, Objective-C, Java, Json, JavaScript, Proto, TableGen, TextProto, Verilog | [ClangFormat](https://clang.llvm.org/docs/ClangFormat.html) | -- | None | [Yes](https://zed0.co.uk/clang-format-configurator) |

💡 **Hint**:

- [Prettier](https://github.com/prettier/prettier) and [Stylelint](https://github.com/stylelint/stylelint) and can cooperate together to format CSS. Config example:

        stylelint_rc.json:
        {"extends":["stylelint-config-recommended","stylelint-config-standard"],"plugins":["stylelint-group-selectors","stylelint-no-indistinguishable-colors","@double-great/stylelint-a11y","stylelint-prettier"],"rules":{"plugin/stylelint-group-selectors":true,"plugin/stylelint-no-indistinguishable-colors":true,"a11y/content-property-no-static-value":false,"a11y/font-size-is-readable":false,"a11y/line-height-is-vertical-rhythmed":[true,{"severity":"warning"}],"a11y/media-prefers-color-scheme":false,"a11y/media-prefers-reduced-motion":false,"a11y/no-display-none":false,"a11y/no-obsolete-attribute":[true,{"severity":"warning"}],"a11y/no-obsolete-element":[true,{"severity":"warning"}],"a11y/no-outline-none":false,"a11y/no-spread-text":false,"a11y/no-text-align-justify":false,"a11y/selector-pseudo-class-focus":false,"prettier/prettier":[true,{"parser":"css","printWidth":120,"semi":true,"singleQuote":false,"tabWidth":4,"useTabs":false}]}}

        Then in Formatter settings > "stylelint": { ... "args": ["--config-basedir", "/absolute/path/to/javascript/node_modules"] ... }

- [Prettier](https://github.com/prettier/prettier) and [ESLint](https://github.com/eslint/eslint) can cooperate together to format JS. Config example:

        eslint_rc.json:
        {"env":{"es2022":true,"node":true,"browser":true},"parserOptions":{"ecmaVersion":13,"sourceType":"module","ecmaFeatures":{"jsx":true}},"extends":["../javascript/node_modules/eslint-config-prettier","../javascript/node_modules/eslint-config-airbnb-base"],"plugins":["eslint-plugin-prettier"],"rules":{"prettier/prettier":["error",{"bracketSpacing":true,"jsxSingleQuote":true,"parser":"babel","printWidth":120,"semi":true,"singleQuote":true,"tabWidth":4,"useTabs":false},{"usePrettierrc":false}],"indent":["error",4]}}


## Installation

There are 3 ways to install Formatter:

- **With the Package Control plugin:** The easiest way to install `Formatter` is through [Package Control](https://packagecontrol.io/packages/Formatter).

> Once you install Package Control, restart Sublime Text and bring up the Command Palette (<kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> on MacOSX, <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> on Linux/Windows). Select "Package Control: Install Package", wait while Package Control fetches the latest package list, then select `Formatter` when the list appears. The advantage of using this method is that Package Control will automatically keep Formatter up to date with the latest version.

- **With Git:** Clone the repository in your Sublime Text `Packages` directory:

        git clone https://github.com/bitst0rm-pub/Formatter.git Formatter

- **Without Git:** Download the latest source from [GitHub](https://github.com/bitst0rm-pub/Formatter), copy the whole directory into the Sublime Text `Packages` directory and make sure to rename it to `Formatter`.

The `Packages` directory is located differently in:

- MacOSX: `~/Library/Application Support/Sublime Text 3/Packages/`
- Linux: `~/.config/sublime-text-3/Packages/`
- Windows: `%APPDATA%/Sublime Text 3/Packages/`


## Configuration

Formatter stores config files in 2 different locations:

- Plugin [config files](https://github.com/bitst0rm-pub/Formatter/tree/master/config) that control the behaviours of 3rd party plugins. The full list of supported options and parameters can be found on plugins dev websites. Formatter provides only a set of default config files to illustrate how it works. You might want to tweak and refine them to fit your needs.<br/>
Note: Do **not** use config files with suffix `.master.` This is the latest reference files and will be updated by any package updates.

        Sublime Text > Packages > User > formatter.assets > config

- Default and User config files that control Formatter:

        Sublime Text > Packages > User > Formatter.sublime-settings

Formatter settings can be accessed from: Preferences > Package Settings > Formatter > Settings.

The left-hand pane contains all the default settings, while right-hand pane is where personal customizations can be made.<br/>
Ensure to maintain the config structure in the right-hand pane.<br/>
Do **not** edit the default settings in the left-hand pane. Any modifications there will be lost when the package is updated.

The following settings example should give you direction on how to setup Formatter:

```js
{
    // Enable debug mode to view errors in the console; [type: bool]
    "debug": false,

    // Auto open the console panel whenever formatting failed; [type: bool]
    // This is especially useful when combined with "debug": true,
    "open_console_on_failure": false,

    // Display results on the status bar; [type: bool]
    "show_statusbar": true,

    // A set of directories where executable programs are located; [type: dict{str:list[str]}]
    // It can be absolute paths to module directories, python zipfiles.
    // Any environment variables like PATH, PYTHONPATH, GEM_PATH, TMPDIR etc.
    // can be added here.
    // This option is similar to running 'export PYTHONPATH="/path/to/my/site-packages"'
    // from terminal. But it is only temporary in the memory and will only apply
    // for the current formatting session.
    // Non-existent environment directories and files will be silently ignored.
    // This option can be ommitted, but for python and ruby you probably need
    // to add it, either permanently via ~/.bashrc, ~/.zshrc, ~/.profile or here.
    "environ": {
        "PATH": [],
        "GEM_PATH": ["${HOME}/to/my/ruby"],
        "PYTHONPATH": ["${packages}/User/MyFolder/python/lib/python3.7/site-packages"]
    },

    // Plugins settings
    "formatters": {
        "example": {
            // Disable and remove plugin from being shown in the menu; [type: bool]
            "disable": false,

            // Auto formatting whenever the current file/view is being saved; [type: bool]
            // For safety reasons, newly formatted codes will be finally saved
            // after the next save demand.
            // This option should be used for plugins with unique syntaxes.
            // For plugins with the same syntaxes, the first plugin takes precedence.
            // Remove the identical syntaxes from one of the plugins to avoid conflicts.
            // For example:
            // Plugin A (enabled): syntaxes ["css", "js"]
            // Plugin B (enabled): syntaxes ["html", "css"]
            // In the case you want to use Plugin B with "css", then you should remove the "css"
            // from plugin A, because plugin A will run first in range of this/yours setting file.
            "format_on_save": false,

            // Create a new file containing formatted codes [type: str]
            // The value of this option is the suffix of the new file being renamed.
            // Suffix must be of type string. =true, =false and all other types imply =false
            // Note: It will overwrite any existing file that has the same new name in
            // the same location.
            // For example:
            // "new_file_on_format": "min", will create a new file:
            // myfile.raw.js -> myfile.raw.min.js
            "new_file_on_format": false,

            // Recursively format the entire folder with unlimited depth. [type: dict{str:(bool|list[str])}]
            // This option requires an existing and currently opened file
            // to serve as the starting point.
            // For the sake of convenience, two new folders will be created at
            // the same level as the file, which will contain all failed and
            // successfully formatted files. The "new_file_on_format" option
            // might be useful for renaming if needed.
            // The "format_on_save" option above, which applies only to
            // single files, does not take effect here.
            // All none-text files (binary) will be automatically ignored.
            // Note: Placing files directly on the Desktop or elsewhere without
            // enclosing them within a folder can lead to accidental formatting.
            // Any literal "$" must be escaped to "\\$" to distinguish it from
            // the variable expansion "${...}". This important rule applies
            // to the entire content of this settings file!
            "recursive_folder_format": {
                "enable": false,
                "exclude_folders_regex": ["Spotlight-V100", "temp", "cache", "logs", "^_.*?tits\\$"],
                "exclude_files_regex": ["show_tits.sx", ".*?ball.js", "^._.*?"],
                "exclude_extensions": ["DS_Store", "localized", "TemporaryItems", "Trashes", "db", "ini", "git", "svn", "tmp", "bak"],
                "exclude_syntaxes": []
            },

            // Syntax support based on the scope name, not file extension; [type: list[str]]
            // Syntax name is part of the scope name and can be retrieved from:
            // Tools > Developer > Show Scope Name
            // End-users are advised to consult plugin documentation to add more syntaxes.
            "syntaxes": ["css", "js", "php"],

            // Path to the interpreter to be used; [type: str]
            // Just for the sake of completeness, but it is unlikely that you will
            // ever need to use this option. Most programs you install are usually set
            // to run in the global environment, such as Python, Node.js, Ruby, PHP, etc.
            // However, this option might be useful when you have several versions
            // of the same program installed on your system. Even in such cases,
            // it is still recommended to use the "environ" option mentioned above,
            // along with the PATH variable, to handle this situation.
            "interpreter_path": "${HOME}/example/path/to\\$my/java.exe",

            // Path to the plugin executable to be used; [type: str]
            // System variable expansions like ${HOME} and Sublime Text specific
            // ${packages}, ${file_path} etc. can be used to assign paths. More:
            // https://www.sublimetext.com/docs/build_systems.html#variables
            // Note: Again, any literal "$" must be escaped to "\\$" to distinguish
            // it from the variable expansion "${...}". This important rule applies
            // to the entire content of this settings file!
            "executable_path": "${HOME}/example/path/to\\$my/php-cs-fixer.phar",

            // Path to the config file for each individual syntaxes; [type: dict{str:str}]
            // Syntax keys must match those in the "syntaxes" option above.
            // A single config file can be used to assign to all syntaxes.
            // In this case the key must be named: "default"
            // Formatter provides a set of default config files under
            // "formatter.assets/config" folder for your personal use.
            // Do not use the reference files with suffix '.master.' directly.
            // These files could be overwritten by any release updates.
            "config_path": {
                "css": "${packages}/User/formatter.assets/config/only_css_rc.json",
                "php": "${packages}/User/formatter.assets/config/only_php_rc.json",
                "default": "${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json"
            },

            // Array of additional arguments for the command line; [type: list[str]]
            "args": ["--basedir", "./example/my/baseball", "--show-tits", "yes"],

            // Manipulate hardcoded command-line arguments; [type: list[list[str]]]
            // This option allow you to modify hardcoded parameters, values and
            // their positions without digging into the source code.
            // Note: Hardcoded args can be changed (rarely) by any release updates.
            // Enable debug mode will help to find all current hardcoded args.
            // Use "args" option above to add, this option to remove or manipulate.
            // Using regex: Again, any literal "$" must be escaped to "\\$" to
            // distinguish it from the variable expansion "${...}". Accepted args:
            // [search, [replace, [index, count, new position]]], where:
            // - search: type:str (regex)
            // - replace: type:str
            // - index: type:int (the number is known as a list index); required!
            // - count: type:int (the matching occurrences per index, 0 = all); required!
            // - position: type:int (move old index pos. to new/old one, -1 = delete index); required!
            "fix_commands": [
                ["--autocorrect", "--autocorrect-all", 4, 0, 4], // no index pos change
                ["^.*?auto.*\\$", "--with", 4, 1, 5], // using escaped "\\$" regex, move index 4 to pos 5
                ["${packages}/to/old", "${packages}/to/new", 3, 0, 3], // variable expansion, no escaped "$"
                ["css", 5, 0, 7], // replace the value in index 5 with "css", move it to pos 7
                [3, 0 , 4], // just move index 3 to the new pos 4. (count 0 irrelevant)
                [2, 0, -1], // just delete the index 2. (count 0 irrelevant)
                ["--show-tits", "xxx", 2, 0, -1] // enough tits, pop it out. ("xxx", 2, 0 irrelevant)
            ]
        },
        "beautysh": {
            "disable": false,
            "format_on_save": false,
            "new_file_on_format": false,
            "recursive_folder_format": {
                "enable": false,
                "exclude_folders_regex": ["Spotlight-V100", "temp", "cache", "logs", "^_.*?tits\\$"],
                "exclude_files_regex": ["show_tits.sx", ".*?ball.js", "^._.*?"],
                "exclude_extensions": ["DS_Store", "localized", "TemporaryItems", "Trashes", "db", "ini", "git", "svn", "tmp", "bak"],
                "exclude_syntaxes": []
            },
            "syntaxes": ["bash"],
            "executable_path": "${packages}/User/MyFolder/python/bin/beautysh",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/beautysh_rc.json"
            }
        },
        "htmltidy": {
            "disable": false,
            "format_on_save": false,
            "new_file_on_format": false,
            "recursive_folder_format": {
                "enable": false,
                "exclude_folders_regex": ["Spotlight-V100", "temp", "cache", "logs", "^_.*?tits\\$"],
                "exclude_files_regex": ["show_tits.sx", ".*?ball.js", "^._.*?"],
                "exclude_extensions": ["DS_Store", "localized", "TemporaryItems", "Trashes", "db", "ini", "git", "svn", "tmp", "bak"],
                "exclude_syntaxes": []
            },
            "syntaxes": ["html", "xml"],
            "executable_path": "${packages}/User/formatter.assets/bin/tidy",
            "config_path": {
                "html": "${packages}/User/formatter.assets/config/htmltidy_html_rc.cfg",
                "xml": "${packages}/User/formatter.assets/config/htmltidy_xml_rc.cfg"
            }
        },
        "stylelint": {
            "disable": false,
            "format_on_save": false,
            "new_file_on_format": false,
            "recursive_folder_format": {
                "enable": false,
                "exclude_folders_regex": ["Spotlight-V100", "temp", "cache", "logs", "^_.*?tits\\$"],
                "exclude_files_regex": ["show_tits.sx", ".*?ball.js", "^._.*?"],
                "exclude_extensions": ["DS_Store", "localized", "TemporaryItems", "Trashes", "db", "ini", "git", "svn", "tmp", "bak"],
                "exclude_syntaxes": []
            },
            "syntaxes": ["css", "scss", "sass", "less", "sss", "sugarss"],
            "executable_path": "${packages}/User/MyFolder/javascript/node_modules/.bin/stylelint",
            "args": ["--config-basedir", "/path/to/javascript/node_modules"],
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/stylelint_rc.json"
            }
        },
        "uncrustify": {
            "disable": false,
            "format_on_save": false,
            "new_file_on_format": false,
            "recursive_folder_format": {
                "enable": false,
                "exclude_folders_regex": ["Spotlight-V100", "temp", "cache", "logs", "^_.*?tits\\$"],
                "exclude_files_regex": ["show_tits.sx", ".*?ball.js", "^._.*?"],
                "exclude_extensions": ["DS_Store", "localized", "TemporaryItems", "Trashes", "db", "ini", "git", "svn", "tmp", "bak"],
                "exclude_syntaxes": []
            },
            "syntaxes": ["c", "c++", "cs", "objc", "objc++", "d", "java", "pawn", "vala"],
            "executable_path": "${HOME}/path/to/bin/uncrustify",
            "config_path": {
                "objc": "${packages}/User/formatter.assets/config/uncrustify_objc_rc.cfg",
                "objc++": "${packages}/User/formatter.assets/config/uncrustify_objc_rc.cfg",
                "java": "${packages}/User/formatter.assets/config/uncrustify_sun_java_rc.cfg",
                "default": "${packages}/User/formatter.assets/config/uncrustify_rc.cfg"
            }
        }
    }
}
```


## Usage

Formatter has been designed to detect the syntax of files according to file scopes, not file extension. In the most cases, Sublime Text already does this job for you when you open a file. For the rest, you must explicit assign the syntax via the syntax menu in the righ-hand bottom corner or via:

        Sublime Text > View > Syntax

Setting wrong syntax when formatting code will cause error: _`Syntax out of the scope.`_

Formatting actions can be triggered in different ways:

- Tools > Command Palette (<kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>) and type `Formatter`.
- Tools > Formatter
- Right-click > Context-Menu > Formatter
- Settings > Key Bindings


## Troubleshooting

If you encounter issues, please activate the key `"debug": true` in `Formatter.sublime-settings` to see what is going on. Errors can arise from upstream plugins, from your transcoding codebase, also setting wrong parameters to path or bugs inside Formatter itself can be the root of issues.


## Todo:

- Maybe add support for more languages.


## License

Formatter is licensed under the [MIT license](https://github.com/bitst0rm-pub/Formatter/blob/master/LICENSE).
