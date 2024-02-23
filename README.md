# Formatter

Formatter is a config-file-driven plugin for Sublime Text `3` & `4` to beautify and minify source code.

Key features:

- Support for more than 2 major programming languages.
- Capability to format entire file, single or multi selections.
- Capability to format entire folder recursively.
- Works with both saved and unsaved files.
- Capability to format on Save.
- Capability to format on Paste.
- Shared config files available for each 3rd-party plugin.
- Displays real-time word and character counts.
- Automatically remembers and restores text position.
- Customizable through 2 methods to add 3rd-party plugins:
    - Generic: Adding json settings (no coding needed). _see_ [Configuration](#configuration)
    - Modules: The integration of your own modules. _see_ [Development](#development)
- Open source and works offline.


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

Formatter is useless without third-party plugins. It relies on external plugins in order to format code. These plugins need to be installed by the end-user. This means, Formatter is not responsible for:
  - The quality of formatted code.
  - The speed of the formatting process.

**The complete list of compatible plugins:** _Need more? see_ [Development](#development)

  - This table does not contain the complete languages that each plugin does support. For example, `prettydiff` supports 45 languages, that would blow up the frame of this list here.
  - Languages such as `Svelte` are not listed here, but can be used through the [prettier plugin](https://github.com/sveltejs/prettier-plugin-svelte). [deno](https://github.com/denoland/deno) and [dprint](https://github.com/dprint/dprint) should have the similar concept.
  - `build-in` = do not need to install by end-users.
  - `None` = mostly standalone binary

| Languages | Beautify | Minify | Requirements | Config-Online |
| ------ | :------: | :------: | :------: | :------: |
| Angular | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd) | -- | Node.js | -- |
| Arduino | [uncrustify](https://github.com/uncrustify/uncrustify)[1], [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[2], [artistic style](https://sourceforge.net/projects/astyle) | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html), [[2]](https://zed0.co.uk/clang-format-configurator) |
| Assembly | [asmfmt](https://github.com/klauspost/asmfmt), [nasmfmt](https://github.com/yamnikov-oleg/nasmfmt) | -- | None | -- |
| Astro | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd) | -- | Node.js | -- |
| BibTeX | [bibtex-tidy](https://github.com/FlamingTempura/bibtex-tidy)[1] | -- | Node.js >= 12.0 | [[1]](https://flamingtempura.github.io/bibtex-tidy/) |
| C, C++, C#, Objective-C | [uncrustify](https://github.com/uncrustify/uncrustify)[1], [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[2], [artistic style](https://sourceforge.net/projects/astyle) | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html), [[2]](https://zed0.co.uk/clang-format-configurator) |
| Cabal | [cabal-fmt](https://github.com/phadej/cabal-fmt) | -- | Haskell | -- |
| Caddyfile | [caddy-fmt](https://github.com/caddyserver/caddy) | -- | None | -- |
| Clojure | [cljfmt](https://github.com/weavejester/cljfmt), [zprint](https://github.com/kkinnear/zprint) | -- | None, (Java) | -- |
| CMake | [cmake-format](https://github.com/cheshirekow/cmake_format) | -- | Python | -- |
| Crystal | [crystal tool format](https://github.com/crystal-lang/crystal) | -- | None | -- |
| CSS, SCSS, Sass, Less, SugarSS | [stylelint](https://github.com/stylelint/stylelint), [js-beautifier](https://github.com/beautify-web/js-beautify), [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [prettydiff](https://github.com/prettydiff/prettydiff)[1], [csscomb](https://github.com/csscomb/csscomb.js) | [cleancss CLI](https://github.com/jakubpawlowicz/clean-css-cli), [prettydiff](https://github.com/prettydiff/prettydiff)[1] | Node.js | [[1]](https://prettydiff.com/tool.xhtml) |
| CSV, TSV, DSV, Text | [prettytable](https://github.com/jazzband/prettytable) `(build-in)`, [prettydiff](https://github.com/prettydiff/prettydiff)[1][2] | -- | Python, Node.js[2] | [[1]](https://prettydiff.com/tool.xhtml) |
| D | [uncrustify](https://github.com/uncrustify/uncrustify)[1] | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| Dart | [dart-format](https://dart.dev/tools/dart-format) | -- | Dart | -- |
| Dhall | [dhall format](https://github.com/dhall-lang/dhall-haskell) | -- | None | -- |
| Dockerfile | [dockfmt](https://github.com/jessfraz/dockfmt) | -- | None | -- |
| Elixir | [mix format](https://github.com/elixir-lang/elixir) | -- | Erlang | -- |
| Elm | [elm-format](https://github.com/avh4/elm-format) | -- | None | -- |
| Erlang | [erlfmt](https://github.com/WhatsApp/erlfmt)[1], [efmt](https://github.com/sile/efmt) | -- | rebar3[1], None | -- |
| Fortran | [fprettify](https://github.com/pseewald/fprettify) | -- | Python | -- |
| Gleam | [gleam format](https://github.com/gleam-lang/gleam) | -- | None | -- |
| GLSL | [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[1] | -- | None | [[1]](https://zed0.co.uk/clang-format-configurator) |
| Go | [gofmt](https://pkg.go.dev/cmd/gofmt), [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports), [gofumpt](https://github.com/mvdan/gofumpt) | -- | None | -- |
| GraphQL | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd) | -- | Node.js | -- |
| Haskell | [ormolu](https://github.com/tweag/ormolu), [fourmolu](https://github.com/fourmolu/fourmolu)[1], [hindent](https://github.com/mihaimaruseac/hindent), [stylish-haskell](https://github.com/haskell/stylish-haskell), [floskell](https://github.com/ennocramer/floskell) | -- | Haskell | [[1]](https://fourmolu.github.io) |
| HCL | [hclfmt](https://github.com/hashicorp/hcl) | -- | None | -- |
| HTML, XHTML, XML | [js-beautifier](https://github.com/beautify-web/js-beautify), [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [prettydiff](https://github.com/prettydiff/prettydiff)[1], [html-tidy](https://github.com/htacg/tidy-html5) | [html-minifier](https://github.com/kangax/html-minifier), [prettydiff](https://github.com/prettydiff/prettydiff)[1] | Node.js | [[1]](https://prettydiff.com/tool.xhtml) |
| Java | [google java format](https://github.com/google/google-java-format)[1], [uncrustify](https://github.com/uncrustify/uncrustify)[2], [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[3], [artistic style](https://sourceforge.net/projects/astyle) | -- | Java[1], None | [[2]](https://cdanu.github.io/uncrustify_config_preview/index.html), [[3]](https://zed0.co.uk/clang-format-configurator) |
| JavaScript | [eslint](https://github.com/eslint/eslint), [eslint_d](https://github.com/mantoni/eslint_d.js), [js-beautifier](https://github.com/beautify-web/js-beautify), [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [standard js](https://github.com/standard/standard), [standardx js](https://github.com/standard/standardx), [semistandard js](https://github.com/standard/semistandard), [prettydiff](https://github.com/prettydiff/prettydiff), [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[1][2], [deno](https://github.com/denoland/deno)[2], [dprint](https://github.com/dprint/dprint)[2] | [terser](https://github.com/terser-js/terser), [prettydiff](https://github.com/prettydiff/prettydiff) | Node.js, None[2] | [[1]](https://zed0.co.uk/clang-format-configurator) |
| JSON | [js-beautifier](https://github.com/beautify-web/js-beautify), [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [prettydiff](https://github.com/prettydiff/prettydiff)[1], [deno](https://github.com/denoland/deno)[2], [topiary](https://github.com/tweag/topiary)[2], [dprint](https://github.com/dprint/dprint)[2], jsonmax `(build-in)` | [prettydiff](https://github.com/prettydiff/prettydiff)[1], jsonmin `(build-in)` | Node.js, None[2] | [[1]](https://prettydiff.com/tool.xhtml) |
| Kotlin | [ktlint](https://github.com/pinterest/ktlint) | -- | Java | -- |
| LaTeX | [latexindent](https://github.com/cmhughes/latexindent.pl) | -- | Perl, None | -- |
| Lua | [stylua](https://github.com/JohnnyMorganz/StyLua), [luaformatter](https://github.com/Koihik/LuaFormatter) | -- | None | -- |
| Markdown | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [deno](https://github.com/denoland/deno)[1], [dprint](https://github.com/dprint/dprint)[1] | -- | Node.js, None[1] | -- |
| Nginx | [nginxfmt](https://github.com/slomkowski/nginx-config-formatter) | -- | Python >= 3.4 | -- |
| Nickel | [topiary](https://github.com/tweag/topiary) | -- | None | -- |
| OCaml | [ocamlformat](https://github.com/ocaml-ppx/ocamlformat), [ocp-indent](https://github.com/OCamlPro/ocp-indent), [topiary](https://github.com/tweag/topiary) | -- | None | -- |
| Perl | [perltidy](https://github.com/perltidy/perltidy) | -- | Perl | -- |
| Pawn | [uncrustify](https://github.com/uncrustify/uncrustify)[1] | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| PHP | [php-cs-fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer)[1], [php_codesniffer](https://github.com/squizlabs/PHP_CodeSniffer) | -- | PHP >=7.4.0[1] | [[1]](https://mlocati.github.io/php-cs-fixer-configurator) |
| Proto | [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[1] | -- | None[1] | [[1]](https://zed0.co.uk/clang-format-configurator) |
| Python | [ruff](https://github.com/astral-sh/ruff), [yapf](https://github.com/google/yapf), [black](https://github.com/ambv/black)[1], [autopep8](https://github.com/hhatto/autopep8), [isort](https://github.com/PyCQA/isort) | [python-minifier](https://github.com/dflook/python-minifier)[2] | Python >=3.7.0[1] | [[2]](https://python-minifier.com) |
| R | [styler](https://github.com/r-lib/styler), [formatR](https://github.com/yihui/formatR)[1] | -- | R | [[1]](https://yihui.shinyapps.io/formatR/) |
| Racket | [raco fmt](https://github.com/sorawee/fmt) | -- | Racket >= 8.0 | -- |
| Ruby | [rubocop](https://github.com/rubocop-hq/rubocop)[1], [rubyfmt](https://github.com/fables-tales/rubyfmt), [standardrb](https://github.com/standardrb/standard), [rufo](https://github.com/ruby-formatter/rufo)[1] | -- | Ruby[1], None | -- |
| Rust | [rustfmt](https://github.com/rust-lang/rustfmt) | -- | Rust >= 1.24 | -- |
| Scala | [scalafmt](https://github.com/scalameta/scalafmt) | -- | None | -- |
| Shell, Bash | [beautysh](https://github.com/lovesegfault/beautysh)[1], [shfmt](https://github.com/mvdan/sh), [shellcheck](https://github.com/koalaman/shellcheck) | [shfmt](https://github.com/mvdan/sh) | Python[1], None | -- |
| SQL, SQL dialects | [sql-formatter](https://github.com/sql-formatter-org/sql-formatter)[1] | sqlmin `(build-in)` | Node.js[1] | [[1]](https://sql-formatter-org.github.io/sql-formatter) |
| Swift | [apple swift-format](https://github.com/apple/swift-format), [swiftformat](https://github.com/nicklockwood/SwiftFormat) | -- | None | -- |
| SVG | [svgo max](https://github.com/svg/svgo) | [svgo min](https://github.com/svg/svgo) | Node.js | -- |
| TableGen | [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[1] | -- | None | [[1]](https://zed0.co.uk/clang-format-configurator) |
| Terraform | [terraform fmt](https://developer.hashicorp.com/terraform/cli/commands/fmt) | -- | None | -- |
| TextProto | [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[1] | -- | None | [[1]](https://zed0.co.uk/clang-format-configurator) |
| TOML | [taplo](https://github.com/tamasfe/taplo), [topiary](https://github.com/tweag/topiary), [dprint](https://github.com/dprint/dprint) | -- | None | -- |
| TypeScript | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [js-beautifier](https://github.com/beautify-web/js-beautify), [ts-standard](https://github.com/standard/ts-standard), [prettydiff](https://github.com/prettydiff/prettydiff)[1], [tsfmt](https://github.com/vvakame/typescript-formatter), [deno](https://github.com/denoland/deno), [dprint](https://github.com/dprint/dprint) | [prettydiff](https://github.com/prettydiff/prettydiff)[1] | Node.js | [[1]](https://prettydiff.com/tool.xhtml) |
| VALA | [uncrustify](https://github.com/uncrustify/uncrustify)[1] | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| Verilog | [clang-format](https://clang.llvm.org/docs/ClangFormat.html)[1] | -- | None | [[1]](https://zed0.co.uk/clang-format-configurator) |
| Vue | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [js-beautifier](https://github.com/beautify-web/js-beautify) | -- | Node.js | -- |
| YAML | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd) | -- | Node.js | -- |


💡 **Tips**:

- [prettier](https://github.com/prettier/prettier) and [stylelint](https://github.com/stylelint/stylelint) and can cooperate together to format CSS. Config example:

        stylelint_rc.json:
        {"extends":["stylelint-config-recommended","stylelint-config-standard"],"plugins":["stylelint-group-selectors","stylelint-no-indistinguishable-colors","@double-great/stylelint-a11y","stylelint-prettier"],"rules":{"plugin/stylelint-group-selectors":true,"plugin/stylelint-no-indistinguishable-colors":true,"a11y/content-property-no-static-value":false,"a11y/font-size-is-readable":false,"a11y/line-height-is-vertical-rhythmed":[true,{"severity":"warning"}],"a11y/media-prefers-color-scheme":false,"a11y/media-prefers-reduced-motion":false,"a11y/no-display-none":false,"a11y/no-obsolete-attribute":[true,{"severity":"warning"}],"a11y/no-obsolete-element":[true,{"severity":"warning"}],"a11y/no-outline-none":false,"a11y/no-spread-text":false,"a11y/no-text-align-justify":false,"a11y/selector-pseudo-class-focus":false,"prettier/prettier":[true,{"parser":"css","printWidth":120,"semi":true,"singleQuote":false,"tabWidth":4,"useTabs":false}]}}

        Then in Formatter settings > "stylelint": { ... "args": ["--config-basedir", "/absolute/path/to/javascript/node_modules"] ... }

- [prettier](https://github.com/prettier/prettier) and [eslint](https://github.com/eslint/eslint) can cooperate together to format JS. Config example:

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
Note: Do **not** use files with the suffix `.master.` as they serve as _reference_(_example_) files for your final configuration and could be overwritten by any package updates. Some exotic plugins do not handle input config file, while others do not understand stdio. To overcome this limitation, you will need these _example_ files as reference to configure them.<br/>
It is recommended to explore this folder, as it may contain additional config files for the same plugin.

Formatter settings can be accessed from: `Preferences > Package Settings > Formatter > Settings`

The following setting details, along with their default values and examples, are provided to guide you on how to set it up. Options are flexible, you do not need to take the whole set of options. Just take the ones you need, but keep the json structure be intact.

Starting from version 1.2.0, Formatter provides 2 methods to adding third-party plugins:

- Generic: simple, no need coding, using just a simple json dict.
- Modules: advanced, more powerful but needs writing and adding python modules to hack.

Both methods with examples are in this settings guide:

```js
{
    // Enable debug mode to view errors in the console.
    "debug": false,

    // Auto open the console panel whenever formatting failed.
    // This is useful when combined with "debug": true
    "open_console_on_failure": false,

    // Timeout to abort subprocess in seconds.
    // Default to 10 seconds. Set to false to disable the timeout.
    "timeout": 10,

    // Integrate your custom modules into the Formatter ecosystem.
    // This option ensures that your own modules won't be automatically removed
    // from Packages Control during any release updates. It also spares you the trouble
    // of having to submit pull requests on GitHub to have your own modules integrated.
    // For security reasons, Formatter never communicates over the Internet.
    // All paths to files and folders must be local.
    "custom_modules": {
        "config": ["/path/to/foo_rc.json", "/path/to/bar_rc.cfg"],
        "modules": ["/path/to/formatter_foo.py", "/path/to/formatter_bar.py"],
        "libs": ["/path/to/foolib", "/path/to/mylib"]
    },

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
    // This option can be ommitted, but for python, ruby and erlang you probably need
    // to add it, either persistently via ~/.bashrc, ~/.zshrc, ~/.profile or here.
    // In debug mode, Formatter will display your current system environments
    // to assist you in configuration. On Windows, you can use either escaped
    // backslashes (e.g., "C:\\a\\b\\c") or forward slashes (e.g., "C:/a/b/c")
    // as path separators for all other options as well.
    "environ": {
        "PATH": ["/path/to/erlang@22/bin:$PATH", "$PATH:/path/to/elixir/bin", "/path/to/.cache/rebar3/bin:$PATH"],
        "GEM_PATH": ["${HOME}/to/my/ruby"],
        "PYTHONPATH": ["${packages}/User/MyFolder/python/lib/python3.7/site-packages"],
        "OLALA": ["$HOME/.cabal/bin:$PATH", "~/.olala/bin:$PATH"]
    },

    // This option addresses the syntaxes conflict described in "format_on_save".
    // It serves as a takeover and only applies to the following options:
    // 1. "format_on_save"
    // 2. "format_on_paste"
    // Syntaxes in this option always take precedence over the syntaxes specified there.
    // All syntaxes must be unique without any duplicates.
    "format_on_unique": {
        "enable": false,
        "csscomb": ["css"],
        "jsbeautifier": ["js"]
    },

    // THIRD-PARTY PLUGINS LEVEL
    "formatters": {
        "examplegeneric": { // GENERIC METHOD
            // Formatter provides 2 methods to adding plugins:
            // - Generic: this one, you design the bridge yourself. Suitable for simple tasks.
            // - Modules: hacking on commands where generic cannot, needs writing python modules.
            // Note: Generic method requires an Sublime Text restart after adding an new generic
            // plugin or making changes to the keys: "name" and "type"!

            // Plugin name. REQUIRED!
            // This will appear on the sublime menu and on other commands.
            "name": "Example Generic",
            // Plugin type. REQUIRED!
            // This will be assigned to a category. Accepted values:
            // "minifier" OR "beautifier" OR "converter" OR any string of your choice.
            "type": "beautifier",
            // The exit code of the third-party plugin.
            // This option can be omitted. Type integer, default to 0.
            "success_code": 0,

            // Same as examplemodules options.
            "disable": true,
            // Same as examplemodules options.
            "format_on_save": false,
            // Same as examplemodules options.
            "format_on_paste": false,
            // Same as examplemodules options.
            "new_file_on_format": false,
            // Same as examplemodules options.
            "recursive_folder_format": {},
            // Same as examplemodules options.
            "syntaxes": ["css", "html", "js", "php"],
            // Same as examplemodules options.
            "exclude_syntaxes": {},
            // Same as examplemodules options.
            "interpreter_path": ["${HOME}/example/path/to\\$my/php.exe"],
            // Same as examplemodules options.
            "executable_path": ["${HOME}/example/path/to\\$my/php-cs-fixer.phar"],
            // Same as examplemodules options.
            "config_path": {
                "css": "${packages}/User/formatter.assets/config/only_css_rc.json",
                "php": "${packages}/User/formatter.assets/config/only_php_rc.json",
                "default": "${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json"
            },

            // These are the commands to trigger the formatting process.
            // You can either pass paths directly or use variable substitution for the following options:
            // - "interpreter_path": "{{i}}"
            // - "executable_path" : "{{e}}", "{{e=node}}" (to auto resolve the local executable with runtime type node)
            // - "config_path"     : "{{c}}"
            // Variable substitution offers more advanced mechanisms such as auto-search path, etc.
            "args": ["{{i}}", "{{e=node}}", "--config", "{{c}}", "--basedir", "./example/my/foo", "--"],

            // Same as examplemodules options.
            "fix_commands": []
        },
        "examplemodules": { // MODULE METHOD
            // Plugin activation.
            // By default, all plugins are disabled and disappear from the menu.
            "disable": true,

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
            // Solution: Use the "format_on_unique" option to workaround this.
            "format_on_save": false,

            // Auto formatting whenever code is pasted into the current file/view.
            // This option is affected by the same syntax impact, and its solutions
            // are identical to those mentioned above for the "format_on_save" option.
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
                "exclude_folders_regex": ["Spotlight-V100", "temp", "cache", "logs", "^_.*foo\\$"],
                "exclude_files_regex": ["^._.*$", ".*bar.exe"],
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
            // Alternatively, you can set the basename as the interpreter name to search on
            // PATH, similar to how it is done with the executable_path option.
            "interpreter_path": ["${HOME}/example/path/to\\$my/java.exe"],

            // Path to the third-party plugin executable to process formatting.
            // This option can be either a string or a list of executable paths.
            // - If this option is omitted or set to null, then the global executable
            //   on PATH will be used, if found.
            // - If this option is exactly the basename, then it will be used as the
            //   executable name and searched for on the PATH.
            //   Basename can be with or without dot.extension as both variants are the same.
            //   For example: "fiLe.exe" (Windows only), "fiLe" (Windows + Unix + Linux)
            // System variable expansions like ${HOME}, ${USER} etc... and the Sublime Text
            // specific ${packages} can be used to assign paths.
            // Note: Again, any literal "$" must be escaped to "\\$" to distinguish
            // it from the variable expansion "${...}".
            "executable_path": ["${HOME}/example/path/to\\$my/php-cs-fixer.phar"],

            // Path to the config file for each individual syntaxes.
            // Syntax keys must match those in the "syntaxes" option above.
            // A single config file can be used to assign to all syntaxes.
            // In this case, the key must be named: "default"
            // Formatter provides a set of default config files under
            // "formatter.assets/config" folder for your personal use.
            // Do not use the reference files with suffix '.master.' directly.
            // These files could be overwritten by any release updates.
            // Note: Options from this config file always have precedence over
            // the options from any local project (per-project config file).
            // To disable this option in favor of the local project config:
            // 1. Set the config path of this option to null, OR
            // 2. Use the Quick Options: Prioritize Per-project Basis Config, OR
            // 3. Place an empty '.cfgignore' file inside the project root folder.
            // Formatter will start to search up the file tree until a
            // '.cfgignore' file is (or isn’t) found.
            "config_path": {
                "css": "${packages}/User/formatter.assets/config/only_css_rc.json",
                "php": "${packages}/User/formatter.assets/config/only_php_rc.json",
                "default": "${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json"
            },

            // Array of additional arguments for the command line.
            "args": ["--basedir", "./example/my/foo", "--show-bar", "yes"],

            // Manipulate hardcoded command-line arguments.
            // This option allow you to modify hardcoded parameters, values and
            // their positions without digging into the source code.
            // This feature is primarily intended to temporarily fix the bug until
            // an official solution is implemented. Therefore bug report is required.
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
                ["--show-bar", "xxx", 2, 0, -1] // enough bar, pop it out. ("xxx", 2, 0 irrelevant)
            ]
        },
        "stylelint": { // MODULE METHOD
            "info": "https://github.com/stylelint/stylelint",
            "disable": false,
            "format_on_paste": false,
            "format_on_save": false,
            "new_file_on_format": false,
            "recursive_folder_format": {
                "enable": false,
                "exclude_folders_regex": ["Spotlight-V100", "temp", "cache", "logs", "^_.*foo\\$"],
                "exclude_files_regex": ["^._.*$", ".*bar.exe"],
                "exclude_extensions": ["DS_Store", "localized", "TemporaryItems", "Trashes", "db", "ini", "git", "svn", "tmp", "bak"],
                "exclude_syntaxes": []
            },
            "syntaxes": ["css", "scss", "sass", "less", "sss", "sugarss"],
            "executable_path": ["${packages}/User/myjs/node_modules/.bin/stylelint"],
            "args": ["--config-basedir", "/path/to/js/node_modules"],
            "config_path": {
                "default": "${packages}/User/formatter.assets/config/stylelint_rc.json"
            }
        },
        "mygeneric": { // GENERIC METHOD. Restart ST after adding this setting dict
            "name": "Uncrustify",
            "type": "beautifier",
            "success_code": 0,
            "args": ["{{e}}", " --style=file:{{c}} ", "--"],

            "info": "https://github.com/uncrustify/uncrustify",
            "disable": false,
            "format_on_save": false,
            // "new_file_on_format": false, // Add this, if needed
            // "recursive_folder_format": {...} // Add this, if needed
            "syntaxes": ["c", "c++", "cs", "objc", "objc++", "d", "java", "pawn", "vala"],
            "executable_path": ["${HOME}/path/to/bin/uncrustify"],
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

- **Temporary Quick Options (TQO)**: By default, all options are temporary and only take effect during the current Sublime session. They will be automatically reset when you close Sublime.
- **Persistent User Settings (PUS)**: Clicking the `Reset` option will reset all current Temporary Quick Options and switch to using your User Settings from `Formatter.sublime-settings`.
- **Persistent Quick Options (PQO)**: Clicking the `Save` option will make all current Temporary Quick Options persistently. This means that closing and reopening Sublime will retain these options. To exit this mode just clicking the `Reset` option.

Summary:

- The `Reset` option is the exclusive method to exit any mode.
- Clicking on the same selected item will remove it from the list.
- None of the modes will ever modify your Settings file.
- The current mode is indicated on the status bar for your reference.


## Development:

Starting from version 1.0.6, you now have the ability to create your own module for a third-party plugin that hasn't yet been integrated into Formatter. This allows you to extend your individual needs. In theory, you can use Formatter as a platform to convert **_any_** form of text, as long as third-party plugins operate in a text-to-text manner, such as Text-to-QR code, text-to-ASCII image conversion.

### 1. Prerequisite:

1. Create a config file specific to your third-party plugin _if needed_. Config files for third-party plugins must be placed in the following folder:

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
        - No communication over the Internet.

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
    "interpreter_path": ["/path/to/bin/node"],              # optional: use an empty string "" to include this key in config files or None to omit it
    "executable_path": ["/path/to/bin/terser"],             # optional: use an empty string "" to include this key in config files or None to omit it
    'args': None,                                           # optional: an array ['arg1', 'args2', ...] to include this key in config files or None to omit it
    'config_path': {                                        # optional: a dictionary to include this key in config files or None to omit it
        'js': 'my_first_plugin_js_rc.json'                  # optional: a key-value pair or just omit it. See Formatter.sublime-settings for explanation
        'default': 'my_first_plugin_rc.json'                # optional: a key-value pair or just omit it. See Formatter.sublime-settings for explanation
    },
    'comment': 'build-in, no executable'                    # optional: a single short comment, limited to 200 chars or just omit it
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

New keys will be automatically created in the _Default_ settings.<br/>
Do not forget to update/adjust your _User_ settings:<br/>
`Preferences > Package Settings > Formatter > Settings`

### 3. Integrating modules:

You have the choice to either submit a pull request or integrate your modules yourself using:
```js
    "custom_modules": {
        "config": ["/path/to/foo_rc.json", "/path/to/bar_rc.cfg"],
        "modules": ["/path/to/formatter_foo.py", "/path/to/formatter_bar.py"],
        "libs": ["/path/to/foolib", "/path/to/mylib"]
    },
```

### 4. APIs:

The entire set of Formatter APIs can be found in the file: `core > common.py`<br/>
Responsible for handling plugin modules is the class: `class Module(object)`<br/>
Starting from version 1.1.0, all previous APIs have been deprecated. Please update to the new APIs accordingly:

- Essentially for the `def get_cmd(self)` function:

```py
# An alias for get_interpreter(), get_executable() and get_args() together
# Set runtime_type=(None|'node'|'python'|'perl'|'ruby') to enable local executable search
# Currently only None|node makes sense. 'python'|'perl'|'ruby' are just placeholder for future.
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

## License

Formatter is licensed under the [MIT license](https://github.com/bitst0rm-pub/Formatter/blob/master/LICENSE).
