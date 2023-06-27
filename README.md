# Formatter

Formatter is a Sublime Text 3/4 plugin to beautify and minify source code.

Features:

- Support more than 20 major languages
- Format whole file, single or multi selections
- Config files available for each 3rd party plugins
- Work offline

Formatter has been tested under Sublime Text `3 and 4` on MacOSX and it _should_ work fine on other platforms (not tested).<br/>
A backport to Sublime Text `2` was never intended.


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

Formatter is useless without third-party plugins. It relies on external plugins in order to format code. Such plugins need to be installed separately and can be easily disabled in settings. Instructions on how to install them are linked below. To setup plugins please keep in mind to:
- check plugin requirements, eg. PHP-CS-Fixer needs PHP >=7.4.0 or Black Python >=3.7.0 !!!
- pass the correct path to the plugin executable and
- adjust their environment variables (PATH, PYTHONPATH etc.) in the `Formatter.sublime-settings`.

**Plugins that work with Formatter:**

Note: This list does not contain the complete languages that each plugin does support.
For example, Pretty Diff support 45 languages, that would blow up the frame of the list here.

| Languages | Beautify | Minify | Requirements | cfg-Online |
| ------ | :------: | :------: | :------: | :------: |
| CSS, SCSS, Sass, Less, SugarSS | [Stylelint](https://github.com/stylelint/stylelint), [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), [CSScomb](https://github.com/csscomb/csscomb.js) | [CleanCSS CLI](https://github.com/jakubpawlowicz/clean-css-cli), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| HTML, XML | [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), [HTML Tidy](https://github.com/htacg/tidy-html5) | [HTMLMinifier](https://github.com/kangax/html-minifier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| JavaScript | [ESLint](https://github.com/eslint/eslint), [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [Pretty Diff](https://github.com/prettydiff/prettydiff), [`ClangFormat`](https://clang.llvm.org/docs/ClangFormat.html) | [Terser](https://github.com/terser-js/terser), [Pretty Diff](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://zed0.co.uk/clang-format-configurator) |
| JSON | [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), JSONMax (build-in) | [`Pretty Diff`](https://github.com/prettydiff/prettydiff), JSONMin (build-in) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| GraphQL | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| Markdown | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| TypeScript | [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| Vue | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| YAML | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| Perl | [Perltidy](https://github.com/perltidy/perltidy) | -- | Perl | -- |
| PHP | [PHP-CS-Fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer) | -- | PHP >=`7.4.0` | [Yes](https://mlocati.github.io/php-cs-fixer-configurator) |
| Python | [YAPF](https://github.com/google/yapf), [`Black`](https://github.com/ambv/black) | -- | Python `>=3.7.0` | -- |
| Ruby | [RuboCop](https://github.com/rubocop-hq/rubocop) | -- | Ruby | -- |
| Bash, Shell | [Beautysh](https://github.com/lovesegfault/beautysh) | -- | Python | -- |
| C, C++, C#, ObjectiveC, D, Java, Pawn, VALA | [Uncrustify](https://github.com/uncrustify/uncrustify) | -- | None | [Yes](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| C, C++, Objective-C, Java, Protobuf | [ClangFormat](https://clang.llvm.org/docs/ClangFormat.html) | -- | None | [Yes](https://zed0.co.uk/clang-format-configurator) |

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

- **With the Package Control plugin:** The easiest way to install `Formatter` is through [Package Control](https://packagecontrol.io/).

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

- Plugin [config files](https://github.com/bitst0rm-pub/Formatter/tree/master/config) that control the behaviours of 3rd party plugins. The full list of supported options and parameters can be found on plugins dev websites. Formatter provides only a set of default config files to illustrate how it works. You might want to tweak and refine them to fit your needs:

        Sublime Text > Packages > User > formatter.assets > config

- Default and User config files that control Formatter:

        Sublime Text > Packages > User > Formatter.sublime-settings

Formatter settings can be accessed from: Preferences > Package Settings > Formatter > Settings.

The left-hand pane contains all of the default settings. The right-hand pane is where personal customization can be made.<br/>
Make sure that you wrap all the configurations into a single root object and copy them from the left-hand to the right-hand pane.<br/>
Do **not** edit the Default settings in the left-hand pane. Any modifications there will be lost when the package is updated.

The following settings example should give you direction, how to setup Formatter:

```
{
    // Enable debug mode to view errors in the console; [type: bool]
    // Any changes will need a restart to get applied.
    "debug": false,

    // Display results on status bar; [type: bool]
    "show_statusbar": true,

    // A set of directories where executable programs are located; [type: list]
    // It can be absolute paths to module directories, python zipfiles.
    // Any environment variables like PATH, PYTHONPATH, GEM_PATH, TMPDIR
    // can be added here.
    // This option is similar to 'export PYTHONPATH="/path/to/my/site-packages"'
    // from terminal. But it is only temporary and will take effect
    // for the current formatting session only.
    // Non-existent environment directories and files are silently ignored.
    // This option can be ommitted, but for python and ruby you probably need
    // to add it, either permanently via ~/.bashrc, ~/.zshrc, ~/.profile or here.
    "environ": {
        "PATH": [],
        "GEM_PATH": ["${HOME}/to/my/ruby"],
        "PYTHONPATH": ["${packages}/User/MyFolder/python/lib/python3.7/site-packages"]
    },

    // Plugins settings
    "formatters": {
        "example_name": {
            // Disable and remove plugin from being shown in the menu; [type: bool]
            // Any changes will need a restart to get applied.
            "disable": false,

            // Auto formatting whenever the current raw file is being saved; [type: bool]
            // This option should be used for plugins with unique syntaxes.
            // For plugins with the same syntaxes then the first plugin will be processed.
            // Disable the others in favor of desired plugins to avoid conflicts.
            "format_on_save": false,

            // Create a new file containing formatted codes [type: string]
            // The value of this option is the suffix of the new file being renamed.
            // Suffix must be of type string. =false, =true and all other types imply =false
            // Note: It will overwrite any existing file that has the same new name in
            // the same location.
            // For example:
            // "new_file_on_format": "min", will create a new file:
            // myfile.raw.js -> myfile.raw.min.js
            "new_file_on_format": false,

            // Syntax support based on the scope name, not file extension; [type: list]
            // Syntax name is part of scope name and can be retrieved from:
            // Tools > Developer > Show Scope Name
            "syntaxes": ["css", "js", "php"],

            // Path to the plugin executable to be used; [type: string]
            // System variable expansion like ${HOME} also Sublime Text
            // ${packages}, ${file_path} etc. can be used to assign paths. More:
            // https://www.sublimetext.com/docs/build_systems.html#variables
            "executable_path": "${HOME}/example/path/to/php-cs-fixer.phar",

            // Path to the config file for each individual syntaxes; [type: dict]
            // Syntax keys must match those in "syntaxes" option above.
            // A single config file can be used to assign to all syntaxes.
            // In this case the key must be named: "default"
            // Formatter provides a set of default config files under
            // "formatter.assets/config" folder for personal use.
            "config_path": {
                "css": "${packages}/User/formatter.assets/config/only_css_rc.json",
                "php": "${packages}/User/formatter.assets/config/only_php_rc.json",
                "default": "${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json"
            },

            // Array of additional arguments for the command line; [type: list]
            "args": ["--basedir", "./example/my/baseball", "--show-tits", "yes"]
        },
        "beautysh": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["bash"],
            "executable_path": "${packages}/User/MyFolder/python/bin/beautysh",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/beautysh_rc.json"
            }
        },
        "htmltidy": {
            "disable": false,
            "format_on_save": false,
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

Formatter has been designed to detect the syntax of files according to file scopes, not file extension. In the most cases Sublime Text already does this job for you when you open a file. For the rest you must explicit assign syntax via the syntax menu on the righ-hand bottom corner or via:

        Sublime Text > View > Syntax

Setting wrong syntax when format code will cause error: _`Syntax out of the scope.`_

Formatting actions can be triggered in different ways:

- Tools > Command Palette (<kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>) and type `Formatter`.
- Tools > Formatter
- Right-click > Context-Menu > Formatter


## Troubleshooting
Please activate the key `"debug": true` in `Formatter.sublime-settings` to see what is going on. Errors can come from upstream plugin dev, from your transcoding code text also setting wrong parameters to path or bugs inside Formatter itself can be the root of issues.


## Todo:

- Maybe add support for more languages, but which one? More is not always better.


## License

Formatter is licensed under the [MIT license](https://github.com/bitst0rm-pub/Formatter/blob/master/LICENSE).
