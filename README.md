# Formatter

Formatter is a config-file-driven plugin for Sublime Text `3` & `4` to beautify and minify source code.

Key features:

- Support for more than 20 major programming languages
- Capability to format entire file, single or multi selections
- Capability to format entire folder recursively
- Works with both saved and unsaved files
- Shared config files available for each 3rd-party plugin
- Displays real-time word and character counts
- Automatically remembers and restores text position
- Open source and works offline

Formatter aims to achieve:

- Flexibility: Users benefit from a wide range of flexible config options.
- Freedom: Third-party plugin updates are not tied to the Formatter itself.
- Modularity: Designed for seamless integration with a variety of additional plugins.
- Convenience: An all-in-one tool for beautifying and minifying code.
- Versatility: As a platform potentially capable of going beyond beautification and minification, eg. Text to QR code, ASCII art, ULM conversion etc. _see_ [Development](#development) to integrate your own modules with ease.


_Formatter in action..._

![Formatter](https://raw.githubusercontent.com/bitst0rm-pub/meta/master/formatter/screenshot.png)


## Guides

- Table of Contents
  - [Plugins](#plugins)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Usage](#usage)
    - [The Quick Options](#the-quick-options)
  - [Development: Guide to Create Your Own Modules](#development)
  - [License](#license)


## Plugins

Formatter is useless without third-party plugins. It relies on external plugins in order to format code. These plugins need to be installed by the end-user.

**The complete list of plugins that work with Formatter:** _Need more? see_ [Development](#development)

1. [Artistic Style](https://astyle.sourceforge.net): A source code formatter for C, C++, C#, and Java that automatically adjusts the formatting.
2. [ASMfmt](https://github.com/klauspost/asmfmt): A tool for formatting assembly code.
3. [Autopep8](https://github.com/hhatto/autopep8): A tool that automatically formats Python code to comply with the PEP 8 style guide.
4. [Beautysh](https://github.com/lovesegfault/beautysh): A shell script beautifier that formats shell scripts for better readability.
5. [Black](https://github.com/ambv/black): A code formatter for Python that enforces a consistent style by automatically reformatting.
6. [ClangFormat](https://clang.llvm.org/docs/ClangFormat.html): A tool that formats C, C++, Objective-C, and other languages based on coding style rules.
7. [CleanCSS](https://github.com/jakubpawlowicz/clean-css-cli): A tool that minifies CSS files, removing unnecessary spaces, comments, etc.
8. [CSScomb](https://github.com/csscomb/csscomb.js): A coding style formatter for CSS files that rearranges properties in a predefined order.
9. [Crystal](https://github.com/crystal-lang/crystal): The official formatter for Crystal with a syntax similar to Ruby but with a focus on performance.
10. [Dart Format](https://dart.dev/tools/dart-format): The official Dart formatter for formatting Dart code according to the Dart style guide.
11. [ESLint](https://github.com/eslint/eslint): A popular linting tool for JavaScript that identifies and fixes common coding errors.
12. [Fourmolu](https://github.com/fourmolu/fourmolu): A formatter for Haskell source code, allowing arbitrary configuration.
13. [Gofmt](https://pkg.go.dev/cmd/gofmt): A tool that formats Go code according to the Go Programming Language style guide.
14. [Goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports): A tool that automatically updates your Go import lines and removes unreferenced ones.
15. [Gofumpt](https://github.com/mvdan/gofumpt): A stricter, opinionated fork of gofmt that enforces additional formatting rules for Go code.
16. [Google Java Format](https://github.com/google/google-java-format): A tool that reformats Java code to comply with the Google Java Style Guide.
17. [Hindent](https://github.com/mihaimaruseac/hindent): A Haskell code formatter that formats code according to a consistent style guide.
18. [HTMLMinifier](https://github.com/kangax/html-minifier): A tool to minify HTML code by removing unnecessary white spaces, comments, etc.
19. [HTML Tidy](https://github.com/htacg/tidy-html5): A library and command-line tool for cleaning up and formatting HTML code.
20. [JS Beautifier](https://github.com/beautify-web/js-beautify): A tool to beautify and format JavaScript, JSON, and CSS code.
21. JSONMax (built-in): A JSON beautifier.
22. JSONMin (built-in): A JSON minifier.
23. [NASMfmt](https://github.com/yamnikov-oleg/nasmfmt): A tool for formatting NASM (Netwide Assembler) assembly code.
24. [Ormolu](https://github.com/tweag/ormolu): A formatter for Haskell source code, with a focus on strict and consistent style.
25. [Perltidy](https://github.com/perltidy/perltidy): A code formatter for Perl, which indents and aligns Perl code according to specified rules.
26. [PHP-CS-Fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer): A tool that fixes PHP coding standards issues and enforces a consistent coding style.
27. [Prettier](https://github.com/prettier/prettier): An opinionated code formatter that supports various languages and focuses on code consistency.
28. [Pretty Diff](https://github.com/prettydiff/prettydiff): A language-aware code comparison tool that can also format and minify code.
29. [PrettyTable](https://github.com/jazzband/prettytable): A Python library for displaying tabular data in a visually appealing ASCII table format.
30. [Python Minifier](https://github.com/dflook/python-minifier): A tool to minify Python code, making it smaller and harder to read.
31. [RuboCop](https://github.com/rubocop-hq/rubocop): A code analyzer and formatter for Ruby, enforcing various style guidelines and best practices.
32. [Rubyfmt](https://github.com/fables-tales/rubyfmt): A Ruby code formatter that aims to provide consistent formatting for Ruby code.
33. [Rustfmt](https://github.com/rust-lang/rustfmt): A tool for formatting Rust code.
34. [ShellCheck](https://github.com/koalaman/shellcheck): A shell script static analysis tool that provides warnings and suggestions for shell scripts.
35. [Shfmt](https://github.com/mvdan/sh): A shell script formatter that helps maintain consistent formatting and style in shell scripts.
36. [SQL Formatter](https://github.com/sql-formatter-org/sql-formatter): A library and command-line tool for formatting SQL queries to improve readability.
37. SQLMin (built-in): A SQL minifier to reduce size and improve performance.
38. [Stylelint](https://github.com/stylelint/stylelint): A linter for CSS and SCSS code that helps maintain a consistent style and avoid errors.
39. [Stylish-Haskell](https://github.com/haskell/stylish-haskell): A Haskell code stylist that formats Haskell source code according to a set of rules.
40. [SVGO](https://github.com/svg/svgo): A Node.js tool for optimizing SVG files, removing unnecessary data for better performance.
41. [SwiftFormat](https://github.com/nicklockwood/SwiftFormat): A code formatter and linter that automatically formats Apple Swift code.
42. [Terser](https://github.com/terser-js/terser): A JavaScript minifier that removes unnecessary characters and renames variables, etc.
43. [Uncrustify](https://github.com/uncrustify/uncrustify): A configurable source code beautifier for C, C++, Objective-C, and other related languages.
44. [YAPF](https://github.com/google/yapf): Yet Another Python Formatter, a tool to format Python code according to specified style guidelines.


And now a same table sorted by languages. Note: This table does not contain the complete languages that each plugin does support.
For example, Pretty Diff supports 45 languages, that would blow up the frame of this list here.<br/>
`build-in` plugins are integrated plugins that do not need to install by end-users.

| Languages | Beautify | Minify | Requirements | Config-Online |
| ------ | :------: | :------: | :------: | :------: |
| CSS, SCSS, Sass, Less, SugarSS | [Stylelint](https://github.com/stylelint/stylelint), [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), [CSScomb](https://github.com/csscomb/csscomb.js) | [CleanCSS CLI](https://github.com/jakubpawlowicz/clean-css-cli), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| HTML, XML | [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), [HTML Tidy](https://github.com/htacg/tidy-html5) | [HTMLMinifier](https://github.com/kangax/html-minifier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| SVG | [SVGO max](https://github.com/svg/svgo) | [SVGO min](https://github.com/svg/svgo) | Node.js | -- |
| JavaScript | [ESLint](https://github.com/eslint/eslint), [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [Pretty Diff](https://github.com/prettydiff/prettydiff), [`ClangFormat`](https://clang.llvm.org/docs/ClangFormat.html) | [Terser](https://github.com/terser-js/terser), [Pretty Diff](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://zed0.co.uk/clang-format-configurator) |
| JSON | [JS Beautifier](https://github.com/beautify-web/js-beautify), [Prettier](https://github.com/prettier/prettier), [`Pretty Diff`](https://github.com/prettydiff/prettydiff), JSONMax (build-in) | [`Pretty Diff`](https://github.com/prettydiff/prettydiff), JSONMin (build-in) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| GraphQL | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| Markdown | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| TypeScript | [Prettier](https://github.com/prettier/prettier), [JS Beautifier](https://github.com/beautify-web/js-beautify), [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | [`Pretty Diff`](https://github.com/prettydiff/prettydiff) | Node.js | [`Yes`](https://prettydiff.com/tool.xhtml) |
| Vue | [Prettier](https://github.com/prettier/prettier), [JS Beautifier](https://github.com/beautify-web/js-beautify) | -- | Node.js | -- |
| YAML | [Prettier](https://github.com/prettier/prettier) | -- | Node.js | -- |
| Go | [Gofmt](https://pkg.go.dev/cmd/gofmt), [Goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports), [Gofumpt](https://github.com/mvdan/gofumpt) | -- | None | -- |
| Perl | [Perltidy](https://github.com/perltidy/perltidy) | -- | Perl | -- |
| PHP | [PHP-CS-Fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer) | -- | PHP >=`7.4.0` | [Yes](https://mlocati.github.io/php-cs-fixer-configurator) |
| Python | [YAPF](https://github.com/google/yapf), [`Black`](https://github.com/ambv/black), [autopep8](https://github.com/hhatto/autopep8) | [Python Minifier](https://github.com/dflook/python-minifier) | Python `>=3.7.0` | [Yes](https://python-minifier.com) |
| Ruby | [`RuboCop`](https://github.com/rubocop-hq/rubocop), [rubyfmt](https://github.com/fables-tales/rubyfmt) | -- | `Ruby`, None | -- |
| Rust | [Rustfmt](https://github.com/rust-lang/rustfmt) | -- | Rust >= 1.24 | -- |
| Haskell | [Ormolu](https://github.com/tweag/ormolu), [`Fourmolu`](https://github.com/fourmolu/fourmolu), [hindent](https://github.com/mihaimaruseac/hindent), [stylish-haskell](https://github.com/haskell/stylish-haskell) | -- | Haskell | [`Yes`](https://fourmolu.github.io) |
| Java | [`Google Java Format`](https://github.com/google/google-java-format), [Uncrustify](https://github.com/uncrustify/uncrustify), [ClangFormat](https://clang.llvm.org/docs/ClangFormat.html), [Artistic Style](https://sourceforge.net/projects/astyle) | -- | `Java`, None | -- |
| Dart | [Dart Format](https://dart.dev/tools/dart-format) | -- | Dart | -- |
| Swift | [SwiftFormat](https://github.com/nicklockwood/SwiftFormat) | -- | None | -- |
| Crystal | [Crystal](https://github.com/crystal-lang/crystal) | -- | None | -- |
| Bash, Shell | [`Beautysh`](https://github.com/lovesegfault/beautysh), [shfmt](https://github.com/mvdan/sh), [ShellCheck](https://github.com/koalaman/shellcheck) | [shfmt](https://github.com/mvdan/sh) | `Python` | -- |
| SQL, SQL dialects | [SQL Formatter](https://github.com/sql-formatter-org/sql-formatter) | SQLMin (build-in) | Node.js | [Yes](https://sql-formatter-org.github.io/sql-formatter) |
| CSV, TSV, DSV, Text | [PrettyTable](https://github.com/jazzband/prettytable) (build-in) | -- | Python | -- |
| ASM assembly | [asmfmt](https://github.com/klauspost/asmfmt), [nasmfmt](https://github.com/yamnikov-oleg/nasmfmt) | -- | None | -- |
| C, C++, C#, Objective-C, D, Java, Pawn, VALA | [Uncrustify](https://github.com/uncrustify/uncrustify) | -- | None | [Yes](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| C, C++, C#, Objective-C, Java, Json, JavaScript, Proto, TableGen, TextProto, Verilog | [ClangFormat](https://clang.llvm.org/docs/ClangFormat.html) | -- | None | [Yes](https://zed0.co.uk/clang-format-configurator) |
| C, C++, C#, Objective-C, Java, JavaScript | [Artistic Style](https://sourceforge.net/projects/astyle) | -- | None | -- |

💡 **Tips**:

- [Prettier](https://github.com/prettier/prettier) and [Stylelint](https://github.com/stylelint/stylelint) and can cooperate together to format CSS. Config example:

        stylelint_rc.json:
        {"extends":["stylelint-config-recommended","stylelint-config-standard"],"plugins":["stylelint-group-selectors","stylelint-no-indistinguishable-colors","@double-great/stylelint-a11y","stylelint-prettier"],"rules":{"plugin/stylelint-group-selectors":true,"plugin/stylelint-no-indistinguishable-colors":true,"a11y/content-property-no-static-value":false,"a11y/font-size-is-readable":false,"a11y/line-height-is-vertical-rhythmed":[true,{"severity":"warning"}],"a11y/media-prefers-color-scheme":false,"a11y/media-prefers-reduced-motion":false,"a11y/no-display-none":false,"a11y/no-obsolete-attribute":[true,{"severity":"warning"}],"a11y/no-obsolete-element":[true,{"severity":"warning"}],"a11y/no-outline-none":false,"a11y/no-spread-text":false,"a11y/no-text-align-justify":false,"a11y/selector-pseudo-class-focus":false,"prettier/prettier":[true,{"parser":"css","printWidth":120,"semi":true,"singleQuote":false,"tabWidth":4,"useTabs":false}]}}

        Then in Formatter settings > "stylelint": { ... "args": ["--config-basedir", "/absolute/path/to/javascript/node_modules"] ... }

- [Prettier](https://github.com/prettier/prettier) and [ESLint](https://github.com/eslint/eslint) can cooperate together to format JS. Config example:

        eslint_rc.json:
        {"env":{"es2022":true,"node":true,"browser":true},"parserOptions":{"ecmaVersion":13,"sourceType":"module","ecmaFeatures":{"jsx":true}},"extends":["../javascript/node_modules/eslint-config-prettier","../javascript/node_modules/eslint-config-airbnb-base"],"plugins":["eslint-plugin-prettier"],"rules":{"prettier/prettier":["error",{"bracketSpacing":true,"jsxSingleQuote":true,"parser":"babel","printWidth":120,"semi":true,"singleQuote":true,"tabWidth":4,"useTabs":false},{"usePrettierrc":false}],"indent":["error",4]}}


## Installation

- **Using [Package Control](https://packagecontrol.io/packages/Formatter):** run `Package Control: Install Package` and select `Formatter`
- **or Download:** the latest source from [GitHub](https://github.com/bitst0rm-pub/Formatter) to your sublime `Packages` directory and rename it to `Formatter`

The `Packages` directory is located in:

- MacOSX: `~/Library/Application Support/Sublime Text 3/Packages/`
- Linux: `~/.config/sublime-text-3/Packages/`
- Windows: `%APPDATA%/Sublime Text 3/Packages/`


## Configuration

Formatter stores third-party plugin [config files](https://github.com/bitst0rm-pub/Formatter/tree/master/config) in:

        Sublime Text > Packages > User > formatter.assets > config

You can use these files directly or place them in a location of your choice. Formatter provides only a set of default (original) config files to illustrate how it works. You might want to tweak and refine them to fit your needs. The full list of supported options and parameters can be found on plugins dev websites.<br/>
Note: Do **not** use files with the suffix `.master.` as they serve as _reference_ files for your configuration and could be overwritten by any package updates.<br/>
It is recommended to explore this folder, as it may contain additional config files for the same plugin.

Formatter settings can be accessed from: `Preferences > Package Settings > Formatter > Settings`

The following settings example should give you direction on how to setup Formatter:

```js
{
    // Enable debug mode to view errors in the console.
    "debug": false,

    // Auto open the console panel whenever formatting failed.
    // This is useful when combined with "debug": true
    "open_console_on_failure": false,

    // Display results in the status bar.
    // The displayed abbreviation for the current settings mode:
    // PUS: Persistent User Settings
    // PQO: Persistent Quick Options
    // TQO: Temporary Quick Options
    "show_statusbar": true,

    // Display a real-time word and character count in the status bar.
    // By default, whitespace is not included in the character count.
    "show_words_count": {
        "enable": true,
        "ignore_whitespace_char": true
    },

    // Remember and restore cursor position, selections and bookmarks
    // each time a file is closed and re-opened.
    // This is helpful to resume your work from where you left off.
    // It does not remember the whole session as one might assume.
    "remember_session": true,

    // Configure the layout when opening new files.
    // This setting takes effect when the "new_file_on_format" option is enabled.
    // Available choices include 2-columns, 2-rows or single layout.
    // To revert to the Sublime default layout:
    // View > Layout > Single
    // Accepted values: "2cols", "2rows", "single" or false
    "layout": {
        "enable": "2cols",
        "sync_scroll": true
    },

    // A set of directories where executable programs are located.
    // It can be absolute paths to module directories, python zipfiles.
    // Any environment variables like PATH, PYTHONPATH, GEM_PATH, GOPATH,
    // GOROOT, GOBIN, TMPDIR, WHATEVER, etc. can be added here.
    // This option is similar to running 'export PYTHONPATH="/path/to/my/site-packages"'
    // from terminal. But it is only temporary in the memory and will only apply
    // for the current formatting session. Your system environment remains untouched.
    // Non-existent environment directories and files will be silently ignored.
    // This option can be ommitted, but for python and ruby you probably need
    // to add it, either persistently via ~/.bashrc, ~/.zshrc, ~/.profile or here.
    "environ": {
        "PATH": [],
        "GEM_PATH": ["${HOME}/to/my/ruby"],
        "PYTHONPATH": ["${packages}/User/MyFolder/python/lib/python3.7/site-packages"],
        "OLALA": ["$HOME/.cabal/bin:$PATH", "~/.olala/bin:$PATH"]
    },

    // This option addresses the syntaxes impact described in "format_on_save".
    // It serves as a global helper and only applies to the following options:
    // 1. "format_on_save"
    // 2. "format_on_paste"
    // To use this option the "format_on_save" and/or "format_on_paste" options
    // at the plugins level must also be enabled. This option takes precedence
    // over the syntaxes specified there.
    // All syntaxes in this option must be unique without any duplicates.
    "format_on_unique": {
        "enable": false,
        "jsbeautifier": ["css", "js"],
        "black": ["python"]
    },

    // THIRD-PARTY PLUGINS LEVEL
    "formatters": {
        "example": {
            // Disable and remove plugin from being shown in the menu.
            "disable": false,

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
            // Solution: Use the Quick Options feature or the "format_on_unique" option,
            // as both are designed for this purpose to help in this scenario.
            "format_on_save": false,

            // Auto formatting whenever code is pasted into the current file/view.
            // The syntaxes impact and its solutions for this option are identical to
            // those of the "format_on_save" option mentioned above.
            "format_on_paste": false,

            // Create a new file containing formatted codes.
            // The value of this option is the suffix of the new file being renamed.
            // Suffix must be of type string. =true, =false and all other types imply =false
            // Note: It will overwrite any existing file that has the same new name in
            // the same location.
            // For example:
            // "new_file_on_format": "min", will create a new file:
            // myfile.raw.js -> myfile.raw.min.js
            "new_file_on_format": false,

            // Recursively format the entire folder with unlimited depth.
            // This option requires an existing and currently opened file
            // to serve as the starting point.
            // For the sake of convenience, two new folders will be created at
            // the same level as the file, which will contain all failed and
            // successfully formatted files. The "new_file_on_format" option
            // might be useful for renaming at the same time if needed.
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

            // Syntax support based on the scope name, not file extension.
            // Syntax name is part of the scope name and can be retrieved from:
            // Tools > Developer > Show Scope Name
            // End-users are advised to consult plugin documentation to add more syntaxes.
            "syntaxes": ["css", "html", "js", "php"],

            // Exclude a list of syntaxes for an individual syntax key.
            // A list of excluded syntaxes can be applied to all syntax definitions.
            // In this case, the key must be named: "all".
            // This option is useful to exclude part of the scope selector.
            // For example: text.html.markdown, want html but wish to filter out html.markdown.
            "exclude_syntaxes": {
                "html": ["markdown"],
                "all": ["markdown"]
            },

            // Path to the interpreter to run the third-party plugin.
            // Just for the sake of completeness, but it is unlikely that you will ever need
            // to use this option. Most of the programs you have installed are usually set
            // to run in the global environment, such as Python, Node.js, Ruby, PHP, etc.
            // Formatter is able to detect and automatically set them for you.
            // However, if you do need to use a specific interpreter, you can provide the path.
            "interpreter_path": "${HOME}/example/path/to\\$my/java.exe",

            // Path to the third-party plugin executable to process formatting.
            // System variable expansions like ${HOME} and Sublime Text specific
            // ${packages}, ${file_path} etc. can be used to assign paths. More:
            // https://www.sublimetext.com/docs/build_systems.html#variables
            // Note: Again, any literal "$" must be escaped to "\\$" to distinguish
            // it from the variable expansion "${...}".
            "executable_path": "${HOME}/example/path/to\\$my/php-cs-fixer.phar",

            // Path to the config file for each individual syntaxes.
            // Syntax keys must match those in the "syntaxes" option above.
            // A single config file can be used to assign to all syntaxes.
            // In this case, the key must be named: "default"
            // Formatter provides a set of default config files under
            // "formatter.assets/config" folder for your personal use.
            // Do not use the reference files with suffix '.master.' directly.
            // These files could be overwritten by any release updates.
            "config_path": {
                "css": "${packages}/User/formatter.assets/config/only_css_rc.json",
                "php": "${packages}/User/formatter.assets/config/only_php_rc.json",
                "default": "${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json"
            },

            // Array of additional arguments for the command line.
            "args": ["--basedir", "./example/my/baseball", "--show-tits", "yes"],

            // Manipulate hardcoded command-line arguments.
            // This option allow you to modify hardcoded parameters, values and
            // their positions without digging into the source code.
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
            // - position: @type:int (move old index pos. to new/old one, -1 = delete index); required!
            "fix_commands": [
                ["--autocorrect", "--autocorrect-all", 4, 0, 4], // no index pos change
                ["^.*?auto.*\\$", "--with", 4, 1, 5], // using escaped "\\$" regex, move index 4 to pos 5
                ["${packages}/to/old", "${packages}/to/new", 3, 0, 3], // variable expansion, no escaped "$"
                ["css", 5, 0, 7], // replace the value in index 5 with "css", move it to pos 7
                [3, 0, 4], // just move index 3 to the new pos 4. (count 0 irrelevant)
                [2, 0, -1], // just delete the index 2. (count 0 irrelevant)
                ["--show-tits", "xxx", 2, 0, -1] // enough tits, pop it out. ("xxx", 2, 0 irrelevant)
            ]
        },
        "stylelint": {
            "info": "https://github.com/stylelint/stylelint",
            "disable": false,
            "format_on_paste": false,
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
            "info": "https://github.com/uncrustify/uncrustify",
            "disable": false,
            "format_on_paste": false,
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
        },
        ...
    }
}
```


## Usage

Formatter has been designed to detect the syntax of files according to file scopes, not file extension. In the most cases, Sublime Text already does this job for you when you open a file. For the rest, you must explicit assign the syntax via the syntax menu in the righ-hand bottom corner or via:

        Sublime Text > View > Syntax

Setting wrong syntax when formatting code will cause error:

        Syntax out of the scope.

Formatting actions can be triggered in different ways:

- Tools > Command Palette (<kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>) and type `Formatter`.
- Tools > Formatter
- Right-click > Context-Menu > Formatter
- Settings > Key Bindings

### The Quick Options

This feature is designed to help users quickly access and switch between options, without the need to navigate the Settings file. It comprises 3 modes:

- **Temporary Quick Options**: By default, all options are temporary and only take effect during the current Sublime session. They will be automatically reset when you close Sublime.
- **Persistent User Settings**: Clicking the `Reset` option will reset all current Temporary Quick Options and switch to using your User Settings from `Formatter.sublime-settings`.
- **Persistent Quick Options**: Clicking the `Save` option will make all current Temporary Quick Options persistently. This means that closing and reopening Sublime will retain these options. To exit this mode just clicking the `Reset` option.

None of the modes will ever alter your Settings file.


## Development:

Starting from version 1.0.6, you now have the ability to create your own module for a third-party plugin that hasn't yet been integrated into Formatter. This allows you to extend your personal needs while remaining independent from the original plugin modules provided by Formatter. In theory, you can use Formatter as a platform to convert _any_ form of text, as long as third-party plugins operate in a text-to-text manner, such as text-to-ASCII image conversion.

### 1. Prerequisite:

1. Create a config file specific to your third-party plugin. Please note that the format and content of this config file may vary among different plugins. Consult the documentation provided by the third-party plugin for detailed instructions.
Config files for third-party plugins must be placed in the following folder:

        Formatter > config

2. Activate the debug mode with the secret key `dev` in your Formatter settings. The `dev` key should never be used in a production environment.

_Formatter.sublime-settings_

```js
{
    "debug": true,  // controls printing error messages
    "dev": true     // controls modules reloading to update modified files
    ...
}
```

### 2. Creating a module:

Developing a module for Formatter is straightforward. All you need to do is creating a python file with just a few lines of code as below:

1. Create a file with the file name pattern `formatter_thisismyfirstpluginmodule.py` inside the `Formatter > modules` folder. Ensure to follow these conventions:

    - Create only **one** file per plugin in the `Formatter > modules` folder:
        - All functions and other necessary components should reside inside this file.

    - The file name is all **lowercase** and contains only **alphanumeric** characters (no spaces or underscores):
        - Prefix: `formatter_` (indicating that it's a module for a third-party plugin)
        - Suffix: `thisismyfirstpluginmodule` (serving as the unique Formatter ID, also known as uid)
        - Extension: `.py`

    - External libraries that the third-party plugin relies on should be placed in the folder: `Formatter > libs`
        - Libraries must not contain proprietary elements, including the LICENSE file or license notices.

2. The content of this module file should follow the structure outlined below:

_formatter_thisismyfirstpluginmodule.py_

```py
#!/usr/bin/env python3

INTERPRETERS = []                                           # optional: Fallback list of interpreter names
EXECUTABLES = []                                            # REQUIRED: Fallback list of executable names
MODULE_CONFIG = {}                                          # REQUIRED: template to create several sublime config files

class ThisismyfirstpluginmoduleFormatter(common.Module):    # REQUIRED: the Capitalized of uid and the Capitalized word "Formatter", nothing else!
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)                   # REQUIRED: initialize the module APIs from common.Module

    def get_cmd(self):                                      # optional: get commands, e.g get the "config_path", "executable_path" etc...

    def format(self):                                       # REQUIRED: the entry point, predefined function name exact as written
```

Details as an example:

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @rev          $Format:%H$ ($Format:%h$)
# @tree         $Format:%T$ ($Format:%t$)
# @date         $Format:%ci$
# @author       you
# @copyright    you
# @link         you
# @license      The MIT License (MIT)

import logging                                              # REQUIRED: logging system for debugging this file
from ..core import common                                   # REQUIRED: a collection of APIs to assist in running this file

log = logging.getLogger(__name__)                           # REQUIRED: logger setup
INTERPRETERS = ['node']                                     # optional: case-sensitive fallback names (without extension) if interpreter is not found
EXECUTABLES = ['terser']                                    # optional: case-sensitive fallback names (without extension) if executable is not found
MODULE_CONFIG = {                                           # REQUIRED: template to create several sublime config files
    'source': 'https://thirdparty-plugin.com',              # REQUIRED: info on where the user can download the plugin
    'name': 'My First Plugin',                              # REQUIRED: a freely chosen plugin name, preferably short and comprehensive
    'uid': 'thisismyfirstpluginmodule',                     # REQUIRED: must match the suffix of "formatter_thisismyfirstpluginmodule.py"
    'type': 'minifier',                                     # REQUIRED: "minifier" OR "beautifier" (both defaults), OR "converter" (for other purposes, e.g., Text-to-QR),
                                                            #           OR any string of your choice (for private purposes).
    'syntaxes': ['js', 'html'],                             # REQUIRED: array of syntaxes, obtained from: Tools > Developer > Show Scope Name
    'exclude_syntaxes': {                                   # optional: blacklist syntaxes per syntax or None to omit it.
        'html': ['markdown']
    },
    "executable_path": "",                                  # optional: use an empty string "" to include this key in config files or None to omit it
    'args': None,                                           # optional: an array ['arg1', 'args2', ...] to include this key in config files or None to omit it
    'config_path': {                                        # optional: a dictionary to include this key in config files or None to omit it
        'js': 'my_first_plugin_js_rc.json'                  # optional: a key-value pair or just omit it. See Formatter.sublime-settings for explanation
        'default': 'my_first_plugin_rc.json'                # optional: a key-value pair or just omit it. See Formatter.sublime-settings for explanation
    },
    'comment': 'build-in, no executable'                    # optional: a single short comment, limited to 80 chars or just omit it
}


class ThisismyfirstpluginmoduleFormatter(common.Module):    # REQUIRED: the Capitalized of uid and the Capitalized word "Formatter", nothing else!
    def __init__(self, *args, **kwargs):                    # REQUIRED: initialization
        super().__init__(*args, **kwargs)                   # REQUIRED: initialize the module APIs from common.Module

    def get_cmd(self):                                      # optional: get commands e.g get the "config_path", "executable_path" etc...
        cmd = self.get_combo_cmd(runtime_type='node')       # See API below
        if not cmd:
            return None

        path = self.get_config_path()                       # See API below
        if path:
            cmd.extend(['--config-file', path])             # an array of args to run the third-party plugin

        cmd.extend(['--compress', '--mangle', '--'])

        log.debug('Current arguments: %s', cmd)             # REQUIRED: to debug the input command
        cmd = self.fix_cmd(cmd)                             # REQUIRED: to finally process the "fix_commands" option, just right before the return

        return cmd

    def format(self):                                       # REQUIRED: the entry point, predefined function name exact as written
        cmd = self.get_cmd()
        if not self.is_valid_cmd(cmd):                      # REQUIRED: is command ok?
            return None

        try:
            exitcode, stdout, stderr = self.exec_cmd(cmd)   # REQUIRED: process command

            if exitcode > 0:                                # REQUIRED: please consult the plugin documentation for the exit codes
                log.error('File not formatted due to an error (exitcode=%d): "%s"', exitcode, stderr)
            else:
                return stdout                               # REQUIRED: return the formatted code on success
        except OSError:
            log.error('Error occurred while running: %s', ' '.join(cmd))

        return None                                         # REQUIRED: return None to indicate failure

```
**That's all**. Happy coding o_O

New keys will be created in the _Default_ settings.<br/>
Do not forget to update/adjust your _User_ settings:<br/>
`Preferences > Package Settings > Formatter > Settings`

### 3. APIs:

The entire set of Formatter APIs can be found in the file: `core > common.py`<br/>
Responsible for handling plugin modules is the class: `class Module(object)`<br/>
Starting from version 1.1.0, all previous APIs have been deprecated. Please update to the new APIs accordingly:

- Essentially for the `def get_cmd(self)` function:

```py
# An alias for get_interpreter(), get_executable() and get_args() together
# Set runtime_type=(None|'node'|'python'|'perl'|'ruby') to enable local executable search
cmd = self.get_combo_cmd(runtime_type=None)

# Get the interpreter path or None
interpreter = self.get_interpreter()

# Get the executable path or None
# Set runtime_type=(None|'node'|'python'|'perl'|'ruby') to enable local executable search
executable = self.get_executable(runtime_type=None)

# Get the input arguments "args" from the User settings or None
args = self.get_args()

# Get the input "config_path" from the User settings or None
path = self.get_config_path()

# Get the detected syntax of the current file or None
syntax = self.get_assigned_syntax()

# Get a dictionary of file path components:
# {'path':, 'cwd':, 'base':, 'stem':, 'suffix':, 'ext':} or None
components = self.get_pathinfo()

# Create and get the temp file path
# Useful for plugins lacking a built-in mechanism to fix files inplace
tmp_file = self.create_tmp_file(suffix=None)

# Remove temp file
self.remove_tmp_file(tmp_file)

# To finally process the "fix_commands" option, just right before exec_cmd()
cmd = self.fix_cmd(cmd)
```

- Essentially for the `def format(self)` function:

```py
# To quickly perform a formal test on the command
is_valid = self.is_valid_cmd(cmd)

# To process the formatting with all input (fixed) arguments
exitcode, stdout, stderr = self.exec_cmd(cmd)
```

### 4. Send pull requests:
Customized modules that have not yet been integrated into Formatter will be wiped out by any Formatter updates via Package Control. Consider downloading Formatter directly from this repository instead of installing it through Package Control. The downside is that you'll need to update Formatter manually.<br/>
Modules focused on beautifying and minifying have the best chance of being accepted.


## License

Formatter is licensed under the [MIT license](https://github.com/bitst0rm-pub/Formatter/blob/master/LICENSE).
