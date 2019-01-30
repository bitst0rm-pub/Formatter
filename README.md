# Formatter

Formatter is a Sublime Text 3 plugin to beautify and minify source code.

Features:

- Support more than 20 major languages
- Format whole file, single or multi selections
- Config files available for each 3rd party plugins
- Work offline

Todo:

- Add support for more languages

Formatter has been tested under Sublime Text `3` and it _should_ work fine on all platforms.<br/>
A backport to Sublime Text `2` was never intended.


## Donation
If this project help you reduce time to develop, you can give me a cup of coffee :)

[![paypal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=WMZN4QESLS6GW&source=url)


## Plugins

Formatter requires special plugins in order to format code. It is currently extended to work with the following plugins. These plugins need to be installed separately and can be easily disabled in settings. Instructions on how to install them are linked below. After you've finished, keep in mind to pass the correct path to the plugin executable and adjust their environment variables in the Formatter settings.

| Languages | Beautify | Minify | Requirements | cfg-Online |
| ------ | :------: | :------: | :------: | :------: |
| CSS, SCSS, Sass,<br/>Less, SugarSS | [Stylelint](https://github.com/stylelint/stylelint), [JS Beautifier](https://github.com/beautify-web/js-beautify),<br/>[Prettier](https://github.com/prettier/prettier), [CSScomb](https://github.com/csscomb/csscomb.js) | [CleanCSS CLI](https://github.com/jakubpawlowicz/clean-css-cli) | [Node.js](https://www.nodejs.org) | -- |
| HTML, XML | [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier),<br/>[`HTML Tidy`](https://github.com/htacg/tidy-html5) | [HTMLMinifier](https://github.com/kangax/html-minifier) | [Node.js](https://www.nodejs.org)<br/>`Binary:` [W](http://binaries.html-tidy.org), [M](https://bintray.com/homebrew/bottles/tidy-html5#files), [L](http://binaries.html-tidy.org) | -- |
| JavaScript | [ESLint](https://github.com/eslint/eslint), [JS Beautifier](https://github.com/beautify-web/js-beautify),<br/>[Prettier](https://github.com/prettier/prettier), [`ClangFormat`](https://clang.llvm.org/docs/ClangFormat.html) | [Terser](https://github.com/terser-js/terser) | [Node.js](https://www.nodejs.org)<br/>`Binary:` [W](https://llvm.org/builds), [M](https://bintray.com/homebrew/bottles/clang-format#files), [L](https://pkgs.org/download/clang-format) | [`[1]`](https://github.com/adamyanalunas/clangformat.com) [`[2]`](https://github.com/zed0/clang-format-configurator) |
| JSON | [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier),<br/>JSONMax (build-in) | JSONMin (build-in) | [Node.js](https://www.nodejs.org) | -- |
| GraphQL | [Prettier](https://github.com/prettier/prettier) | -- | [Node.js](https://www.nodejs.org) | -- |
| Markdown | [Prettier](https://github.com/prettier/prettier) | -- | [Node.js](https://www.nodejs.org) | -- |
| TypeScript | [Prettier](https://github.com/prettier/prettier) | -- | [Node.js](https://www.nodejs.org) | -- |
| Vue | [Prettier](https://github.com/prettier/prettier) | -- | [Node.js](https://www.nodejs.org) | -- |
| YAML | [Prettier](https://github.com/prettier/prettier) | -- | [Node.js](https://www.nodejs.org) | -- |
| Perl | [Perltidy](https://github.com/perltidy/perltidy) | -- | [Perl](https://www.perl.org), Binary: [W](https://perltidy.github.io/perltidy/INSTALL.html), [M](https://perltidy.github.io/perltidy/INSTALL.html), [L](https://perltidy.github.io/perltidy/INSTALL.html) | -- |
| PHP | [PHP-CS-Fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer) | -- | [PHP 5.6.0+](https://www.php.net) | [\[1\]](https://github.com/mlocati/php-cs-fixer-configurator) |
| Python | [YAPF](https://github.com/google/yapf), [`Black`](https://github.com/ambv/black) | -- | [Python `3.6.0+`](https://www.python.org) | -- |
| Ruby | [RuboCop](https://github.com/rubocop-hq/rubocop) | -- | [Ruby](https://www.ruby-lang.org) | -- |
| Bash, Shell | [Beautysh](https://github.com/bemeurer/beautysh) | -- | [Python](https://www.python.org) | -- |
| C, C++, C#, ObjectiveC,<br/>D, Java, Pawn, VALA | [Uncrustify](https://github.com/uncrustify/uncrustify) | -- | Binary: [W](https://sourceforge.net/projects/uncrustify/files/uncrustify/), [M](https://bintray.com/homebrew/bottles/uncrustify#files), [L](https://pkgs.org/download/uncrustify) | [\[1\]](https://github.com/CDanU/uncrustify_config) |
| C, C++, Objective-C,<br/>Java, Protobuf | [ClangFormat](https://clang.llvm.org/docs/ClangFormat.html) | -- | Binary: [W](https://llvm.org/builds), [M](https://bintray.com/homebrew/bottles/clang-format#files), [L](https://pkgs.org/download/clang-format) | [\[1\]](https://github.com/adamyanalunas/clangformat.com) [\[2\]](https://github.com/zed0/clang-format-configurator) |

💕**Hint**:

- [Stylelint](https://github.com/stylelint/stylelint) and [Prettier](https://github.com/prettier/prettier) can cooperate together using [stylelint-plugin-prettier](https://github.com/prettier/stylelint-prettier). Configuration can be done with:

        Sublime Text: Packages > User > formatter.assets > config > stylelintrc.json

        Example (stylelintrc.json): { "extends": [ "stylelint-config-standard", "stylelint-config-prettier" ], "plugins": [ "stylelint-prettier" ], "rules": { "prettier/prettier": [ true, { "parser": "css", "singleQuote": false, "tabWidth": 4 } ] } }

        Then in Formatter settings > "stylelint": { ... "args": ["--config-basedir", "/absolute/path/to/node_modules"] ... }

- [ESLint](https://github.com/eslint/eslint) and [Prettier](https://github.com/prettier/prettier) can cooperate together using [eslint-plugin-prettier](https://github.com/prettier/eslint-plugin-prettier). Configuration can be done with:

        Sublime Text: Packages > User > formatter.assets > config > eslintrc.json

        Example (eslintrc.json): { "extends": [ "eslint-config-standard", "eslint-config-prettier" ], "plugins": [ "eslint-plugin-standard", "eslint-plugin-prettier" ], "rules": { "prettier/prettier": [ "error", { "bracketSpacing": true, "jsxSingleQuote": true, "parser": "babel", "printWidth": 120, "singleQuote": true, "tabWidth": 4 } ] } }


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

Formatter stores configuration data in 2 different locations:

- Specific [config files](https://github.com/bitst0rm-pub/Formatter/tree/master/config) that control the behaviours of 3rd party plugins. The full list of supported options and acceptable values can be found on plugins dev websites. Formatter provides only the basic foundation to demonstrate how it works. You might want to tweak and refine them to fit your needs:

        Sublime Text: Preferences > Package Settings > Formatter > Open Config Files

        Location:
        Sublime Text: Packages > User > formatter.assets > config

- Default and User config files that control Formatter:

        Sublime Text: Packages > User > Formatter.sublime-settings

Formatter settings are accessed via the Preferences > Package Settings > Formatter > Settings.

The left-hand pane contains all of the default settings. The right-hand pane is where customization can be saved.<br/>
Make sure that you wrap all the configurations into a single root object and copy them from the left-hand to the right-hand pane.<br/>
Do **not** edit the Default settings in the left-hand pane. Any modifications there will be lost when the package is updated.

The following settings example should give you direction, how to setup Formatter:

```
{
    // Output debugging information in the console; [type:bool]
    // Any changes will need a restart to get applied.
    "debug": false,

    // Display result report in status bar; [type:bool]
    "show_statusbar": true,

    // Augment the default search path for executables,
    // module directories, python zipfiles etc...; [type:dict:list]
    // Environment variables can be almost any dynamic-named values:
    // PATH, PYTHONPATH, GEM_PATH, TMPDIR etc... can be added here.
    // Standard variables usually contain a list of absolute paths
    // to _directories_ in which to search for files. An exception
    // makes PYTHONPATH, it may refer to zipfiles containing pure
    // Python modules (in either source or compiled form).
    // Non-existent directories and files are silently ignored.
    // This customization is temporary and will only take effect
    // for the current formatting process.
    // This option can be ommitted.
    "environ": {
        "PATH": [],
        "GEM_PATH": ["${packages}/User/formatter.assets/ruby"],
        "PYTHONPATH": ["${packages}/User/formatter.assets/python/lib/python3.7/site-packages"]
    },

    // Formatter specific settings
    "formatters": {
        "name_id": {
            // Disable and remove plugin from being shown in the menu; [type:bool]
            // Any changes will need a restart to get applied.
            "disable": false,

            // Auto formatting whenever file is being saved; [type:bool]
            // This option should be used for plugins with unique syntaxes.
            // For plugins with the same syntaxes the first plugin will be taken.
            // Disable the others in favor of desired plugins to avoid conflicts.
            "format_on_save": false,

            // Syntax support based on the scope name, not file extension; [type:list]
            // Syntax name is part of scope name and can be retrieved from:
            // Tools > Developer > Show Scope Name
            "syntaxes": ["css", "js", "php"],

            // Path to the plugin executable to be used; [type:string]
            "executable_path": "",

            // Path to the config file for each individual syntaxes; [type:dict]
            // Syntax keys must match those in "syntaxes" option above.
            // A single config file can be used to assign to all syntaxes.
            // In this case the key must be named: "default"
            "config_path": {
                "css": "/path/to/config/___only_css_rc.json",
                "default": "/path/to/config/___combo_js_plus_php_rc.json"
            },

            // Array of additional arguments for the command line; [type:list]
            "args": []
        },
        "beautysh": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["bash"],
            "executable_path": "${packages}/User/formatter.assets/python/bin/beautysh",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/beautyshrc.json"
            }
        },
        "black": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["python"],
            "executable_path": "${packages}/User/formatter.assets/python/bin/black",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/blackrc.toml"
            }
        },
        "clangformat": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["c", "c++", "objc", "objc++", "js", "java", "proto"],
            "executable_path": "${packages}/User/formatter.assets/bin/clang-format",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/clangformatrc.yaml"
            }
        },
        "csscomb": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["css", "scss", "sass", "less"],
            "executable_path": "${packages}/User/formatter.assets/javascript/node_modules/.bin/csscomb",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/csscombrc.json"
            }
        },
        "eslint": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["js"],
            "executable_path": "${packages}/User/formatter.assets/javascript/node_modules/.bin/eslint",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/eslintrc.json"
            }
        },
        "htmltidy": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["html", "xml"],
            "executable_path": "${packages}/User/formatter.assets/bin/tidy",
            "config_path": {
                "html": "${packages}/User/formatter.assets/config/htmltidyrc_html.cfg",
                "xml": "${packages}/User/formatter.assets/config/htmltidyrc_xml.cfg"
            }
        },
        "jsbeautifier": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["js", "css", "html", "json"],
            "executable_path": "${packages}/User/formatter.assets/javascript/node_modules/.bin/js-beautify",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/jsbeautifyrc.json"
            }
        },
        "jsonmax": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["json"],
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/jsonmaxrc.json"
            }
        },
        "perltidy": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["perl"],
            "executable_path": "${packages}/User/formatter.assets/bin/perltidy",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/perltidyrc.cfg"
            }
        },
        "phpcsfixer": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["php"],
            "executable_path": "${packages}/User/formatter.assets/bin/php-cs-fixer-v2.phar",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/phpcsfixerrc.php"
            }
        },
        "prettier": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["css", "scss", "less", "js", "jsx", "json", "html", "graphql", "markdown", "tsx", "vue", "yaml"],
            "executable_path": "${packages}/User/formatter.assets/javascript/node_modules/.bin/prettier",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/prettierrc.json"
            }
        },
        "rubocop": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["ruby"],
            "executable_path": "${packages}/User/formatter.assets/ruby/bin/rubocop",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/rubocoprc.yml"
            }
        },
        "stylelint": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["css", "scss", "sass", "less", "sss", "sugarss"],
            "executable_path": "${packages}/User/formatter.assets/javascript/node_modules/.bin/stylelint",
            "args": ["--config-basedir", "${packages}/User/formatter.assets/javascript/node_modules"],
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/stylelintrc.json"
            }
        },
        "uncrustify": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["c", "c++", "cs", "objc", "objc++", "d", "java", "pawn", "vala"],
            "executable_path": "${packages}/User/formatter.assets/bin/uncrustify",
            "config_path": {
                "objc": "${packages}/User/formatter.assets/config/uncrustifyrc_objc.cfg",
                "default": "${packages}/User/formatter.assets/config/uncrustifyrc.cfg"
            }
        },
        "yapf": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["python"],
            "executable_path": "${packages}/User/formatter.assets/python/bin/yapf",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/yapfrc.yapf"
            }
        },
        "cleancss": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["css", "scss", "sass", "less"],
            "executable_path": "${packages}/User/formatter.assets/javascript/node_modules/.bin/cleancss",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/cleancssrc.json"
            }
        },
        "htmlminifier": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["html", "xml"],
            "executable_path": "${packages}/User/formatter.assets/javascript/node_modules/.bin/html-minifier",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/htmlminifierrc.json"
            }
        },
        "jsonmin": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["json"]
            /* no config */
        },
        "terser": {
            "disable": false,
            "format_on_save": false,
            "syntaxes": ["js"],
            "executable_path": "${packages}/User/formatter.assets/javascript/node_modules/.bin/terser",
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/terserrc.json"
            }
        }
    }
}
```


## Usage

Formatter has been designed to detect the syntax of files according to file scopes. In the most cases Sublime Text already does this job for you when you open a file. For the rest you must explicit assign syntax via the syntax menu on the righ-hand bottom corner or via:

        Sublime Text > View > Syntax

Setting wrong syntax when format code will cause error: _`Syntax out of the scope.`_

Formatting actions can be triggered in different ways:

- Tools > Command Palette (<kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>) and type `Formatter`.
- Tools > Formatter
- Right-click > Context-Menu > Formatter


## License

Formatter is licensed under the [MIT license](https://github.com/bitst0rm-pub/Formatter/blob/master/LICENSE).
