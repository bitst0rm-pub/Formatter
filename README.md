# 🧜‍♀️ Formatter

Formatter is a versatile config-file-driven plugin for Sublime Text `3` & `4` to beautify and minify source code.<br />
In _theory_, it can also serve as a platform to transform any form of text, beyond beautifying and minifying.

**Key features:**

- Supports over 70 major programming languages via [plugins](#plugins).
- Transforms text in various ways:
  - Text-to-Text (Text diagramms, ASCII art, etc.)
  - Text-to-Image (Image diagramms, QR-code images, etc.)
- Capable to format entire file, single or multiple selections.
- Capable to format entire directory recursively.
- Operates more accurately based on syntax scope, **not** file extension.
- Works with both saved and unsaved dirty files (buffer).
- Unified settings across different systems.
- Supports [auto-detect formatting](#auto-detect-formatting).
  - with the ability to _chain_ multiple formatters sequentially in a single run.
- Supports [per-project formatting](#per-project-formatting).
- Capable to format on Save.
  - with options to _exclude_ dirs, files, extensions, syntaxes.
- Capable to format on Paste.
  - dito
- Shared config files available to get started.
- Displays real-time word and character counts.
- Automatically remembers and restores text position.
- Customizable and extendable through 2 methods to add **_your_** own plugins:
  - Generic: Adding a portion JSON settings (no coding needed). _see_ [Configuration](#configuration)
  - Modules: Integration of your own modules (easy API). _see_ [Development](#development)
- Zero dependencies to install.

**Limitations:**

- Text-to-Image: Third-party plugins often rely on a headless browser to render images, making the process very time-consuming. Consequently:

  - `"dir_format"` will not be implemented or is disabled.
  - `"new_file_on_format"` will not be implemented or is disabled.
  - Third-party plugins **must** support exporting `PNG` format as Sublime Text only supports `PNG`, `JPG`, and `GIF` images.

_**Formatter in action:**_

| _Text-to-Text_ | _Text-to-Image_ |
| :------------: | :------------: |
| ![Formatter](https://raw.githubusercontent.com/bitst0rm-pub/meta/master/formatter/screenshot1.png) | ![Formatter](https://raw.githubusercontent.com/bitst0rm-pub/meta/master/formatter/screenshot2.png) |

| _Pretty-printing..._ | _Converting..._ |
| :------------: | :------------: |
| ![Formatter](https://raw.githubusercontent.com/bitst0rm-pub/meta/master/formatter/screenshot3.png) | ![Formatter](https://raw.githubusercontent.com/bitst0rm-pub/meta/master/formatter/screenshot4.png) |

| _Not OllyDbg, IDA but..._ | _Assembling..._ |
| :------------: | :------------: |
| ![Formatter](https://raw.githubusercontent.com/bitst0rm-pub/meta/master/formatter/screenshot5.png) | ![Formatter](https://raw.githubusercontent.com/bitst0rm-pub/meta/master/formatter/screenshot6.png) |

<sub>Theme used: **[theme-dosa](https://github.com/bitst0rm-pub/theme-dosa)** and **[color-scheme-two](https://github.com/bitst0rm-pub/color-scheme-two)**</sub>

## Guides

- Table of Contents
  - [Plugins](#plugins)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Auto-detect Formatting](#auto-detect-formatting)
  - [Per-project Formatting](#per-project-formatting)
  - [Usage](#usage)
    - [The Quick Options](#the-quick-options)
  - [Development: Creating Your Own Modules](#development)
    1. [Prerequisite](#1-prerequisite)
    2. [Creating a module](#2-creating-a-module)
    3. [Integrating modules](#3-integrating-modules)
    4. [API](#4-api)
  - [Deprecated API and Settings](#deprecated-api-and-settings)
  - [License](#license)

## Plugins

Formatter requires third-party plugins to work, as it relies on external plugins to format code. Users must install these plugins themselves. This means, Formatter is not responsible for:

- The quality of formatted code.
- Keeping third-party plugins up-to-date.

## Table of supported plugins

_Need more? see:_ [Configuration](#configuration) and [Development](#development) to add your own.

- The same table with clear names, auto generated: [_summary.txt](/modules/_summary.txt)
- **`(I)`** = **`(integrated/build-in)`** No installation required; specifically designed for Formatter.
- `None` = Mostly standalone binaries.
- `Req.` = Requirements might not be up-to-date.

| Langs | Beautifiers | Minifiers | Graphics | Req. | Config |
| ------ | :------: | :------: | :------: | :------: | :------: |
| Angular | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd) | -- | -- | Node.js | -- |
| Arduino | [uncrustify](https://github.com/uncrustify/uncrustify) [1], [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [2], [artistic style](https://sourceforge.net/projects/astyle) | -- | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html), [[2]](https://zed0.co.uk/clang-format-configurator) |
| Assembly | [asmfmt](https://github.com/klauspost/asmfmt), [nasmfmt](https://github.com/yamnikov-oleg/nasmfmt) | -- | -- | None | -- |
| Astro | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd) | -- | -- | Node.js | -- |
| BibTeX | [bibtex-tidy](https://github.com/FlamingTempura/bibtex-tidy) [1] | -- | -- | Node.js 12.0+ | [[1]](https://flamingtempura.github.io/bibtex-tidy/) |
| Blade | [blade-formatter](https://github.com/shufo/blade-formatter) | -- | -- | Node.js | -- |
| C, C++, C#, Objective-C | [uncrustify](https://github.com/uncrustify/uncrustify) [1], [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [2], [artistic style](https://sourceforge.net/projects/astyle) | -- | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html), [[2]](https://zed0.co.uk/clang-format-configurator) |
| Cabal | [cabal-fmt](https://github.com/phadej/cabal-fmt) | -- | -- | Haskell | -- |
| Caddyfile | [caddy-fmt](https://github.com/caddyserver/caddy) | -- | -- | None | -- |
| Clojure | [cljfmt](https://github.com/weavejester/cljfmt), [zprint](https://github.com/kkinnear/zprint) | -- | -- | None, (Java) | -- |
| CMake | [cmake-format](https://github.com/cheshirekow/cmake_format) | -- | -- | Python | -- |
| Crystal | [crystal tool format](https://github.com/crystal-lang/crystal) | -- | -- | None | -- |
| CSS, SCSS, Sass, Less, SugarSS | [stylelint](https://github.com/stylelint/stylelint) [1], [js-beautifier](https://github.com/beautify-web/js-beautify), [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [prettydiff](https://github.com/prettydiff/prettydiff) [2], [csscomb](https://github.com/csscomb/csscomb.js), [stylefmt](https://github.com/masaakim/stylefmt) | [cleancss CLI](https://github.com/jakubpawlowicz/clean-css-cli), [prettydiff](https://github.com/prettydiff/prettydiff) [2] | -- | Node.js | [[1]](https://maximgatilin.github.io/stylelint-config/), [[2]](https://prettydiff.com/tool.xhtml) |
| CSV, TSV, DSV, Text | [prettytable](https://github.com/jazzband/prettytable) **`(I)`**, [prettydiff](https://github.com/prettydiff/prettydiff) [1] [2] | -- | -- | Python, Node.js [2] | [[1]](https://prettydiff.com/tool.xhtml) |
| D | [uncrustify](https://github.com/uncrustify/uncrustify) [1] | -- | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| D2 | [d2 fmt](https://github.com/terrastruct/d2) | -- | [d2](https://github.com/terrastruct/d2) | None | -- |
| Dart | [dart-format](https://dart.dev/tools/dart-format) | -- | -- | Dart | -- |
| Dhall | [dhall format](https://github.com/dhall-lang/dhall-haskell) | -- | -- | None | -- |
| Dockerfile | [dockfmt](https://github.com/jessfraz/dockfmt) | -- | -- | None | -- |
| Drawio | -- | -- | [draw.io](https://github.com/jgraph/drawio-desktop) | None | -- |
| Elixir | [mix format](https://github.com/elixir-lang/elixir) | -- | -- | Erlang | -- |
| Elm | [elm-format](https://github.com/avh4/elm-format) | -- | -- | None | -- |
| Erlang | [erlfmt](https://github.com/WhatsApp/erlfmt) [1], [efmt](https://github.com/sile/efmt) | -- | -- | rebar3 [1], None | -- |
| Fortran | [fprettify](https://github.com/pseewald/fprettify) | -- | -- | Python | -- |
| Gleam | [gleam format](https://github.com/gleam-lang/gleam) | -- | -- | None | -- |
| GLSL | [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [1] | -- | -- | None | [[1]](https://zed0.co.uk/clang-format-configurator) |
| Go | [gofmt](https://pkg.go.dev/cmd/gofmt), [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports), [gofumpt](https://github.com/mvdan/gofumpt) | -- | -- | None | -- |
| GraphQL | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd) | -- | -- | Node.js | -- |
| Graphviz | -- | -- | [graphviz](https://gitlab.com/graphviz/graphviz) | None | -- |
| Groovy, Gradle | [npm-groovy-lint](https://github.com/nvuillam/npm-groovy-lint) | -- | -- | Node.js 12.0+ | -- |
| Haskell | [ormolu](https://github.com/tweag/ormolu), [fourmolu](https://github.com/fourmolu/fourmolu) [1], [hindent](https://github.com/mihaimaruseac/hindent), [stylish-haskell](https://github.com/haskell/stylish-haskell), [floskell](https://github.com/ennocramer/floskell) | -- | -- | Haskell | [[1]](https://fourmolu.github.io) |
| HCL | [hclfmt](https://github.com/hashicorp/hcl) | -- | -- | None | -- |
| HTML, XHTML, XML | [js-beautifier](https://github.com/beautify-web/js-beautify), [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [prettydiff](https://github.com/prettydiff/prettydiff) [1], [html-tidy](https://github.com/htacg/tidy-html5) | [html-minifier](https://github.com/kangax/html-minifier), [prettydiff](https://github.com/prettydiff/prettydiff) [1] | -- | Node.js | [[1]](https://prettydiff.com/tool.xhtml) |
| Java | [google java format](https://github.com/google/google-java-format) [1], [uncrustify](https://github.com/uncrustify/uncrustify) [2], [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [3], [artistic style](https://sourceforge.net/projects/astyle) | -- | -- | Java [1], None | [[2]](https://cdanu.github.io/uncrustify_config_preview/index.html), [[3]](https://zed0.co.uk/clang-format-configurator) |
| JavaScript | [eslint](https://github.com/eslint/eslint), [eslint_d](https://github.com/mantoni/eslint_d.js) [3], [js-beautifier](https://github.com/beautify-web/js-beautify), [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [standard js](https://github.com/standard/standard), [standardx js](https://github.com/standard/standardx), [semistandard js](https://github.com/standard/semistandard), [prettydiff](https://github.com/prettydiff/prettydiff), [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [1] [2], [deno](https://github.com/denoland/deno) [2], [dprint](https://github.com/dprint/dprint) [2], [biome](https://github.com/biomejs/biome) [2] | [terser](https://github.com/terser-js/terser), [prettydiff](https://github.com/prettydiff/prettydiff) | -- | 14.0+ [3], Node.js, None [2] | [[1]](https://zed0.co.uk/clang-format-configurator) |
| JSON | jsonmax **`(I)`**, [js-beautifier](https://github.com/beautify-web/js-beautify), [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [prettydiff](https://github.com/prettydiff/prettydiff) [1], [deno](https://github.com/denoland/deno) [2], [topiary](https://github.com/tweag/topiary) [2], [dprint](https://github.com/dprint/dprint) [2], [biome](https://github.com/biomejs/biome) [2] | jsonmin **`(I)`**, [prettydiff](https://github.com/prettydiff/prettydiff) [1] | -- | Node.js, None [2] | [[1]](https://prettydiff.com/tool.xhtml) |
| Julia | [juliaformatter](https://github.com/domluna/JuliaFormatter.jl) | -- | -- | Julia 0.6+ | -- |
| Kotlin | [ktlint](https://github.com/pinterest/ktlint) | -- | -- | Java | -- |
| LaTeX | [latexindent](https://github.com/cmhughes/latexindent.pl) | -- | -- | Perl, None | -- |
| Lua | [stylua](https://github.com/JohnnyMorganz/StyLua), [luaformatter](https://github.com/Koihik/LuaFormatter) | -- | -- | None | -- |
| Markdown | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [deno](https://github.com/denoland/deno) [1], [dprint](https://github.com/dprint/dprint) [1] | -- | -- | Node.js, None [1] | -- |
| Mermaid | -- | -- | [mermaid](https://github.com/mermaid-js/mermaid-cli) [1] | Node.js | [[1]](https://mermaid.live) |
| Nginx | [nginxfmt](https://github.com/slomkowski/nginx-config-formatter) | -- | -- | Python 3.4+ | -- |
| Nickel | [topiary](https://github.com/tweag/topiary) | -- | -- | None | -- |
| OCaml | [ocamlformat](https://github.com/ocaml-ppx/ocamlformat), [ocp-indent](https://github.com/OCamlPro/ocp-indent), [topiary](https://github.com/tweag/topiary) | -- | -- | None | -- |
| Perl | [perltidy](https://github.com/perltidy/perltidy) | -- | -- | Perl | -- |
| Pawn | [uncrustify](https://github.com/uncrustify/uncrustify) [1] | -- | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| PHP | [php-cs-fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer) [1], [php_codesniffer](https://github.com/squizlabs/PHP_CodeSniffer) | -- | -- | PHP 7.4+ [1] | [[1]](https://mlocati.github.io/php-cs-fixer-configurator) |
| Plantuml | [plantumlascii](https://github.com/plantuml/plantuml) | -- | [plantuml](https://github.com/plantuml/plantuml) | Java | -- |
| Proto | [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [1] | -- | -- | None [1] | [[1]](https://zed0.co.uk/clang-format-configurator) |
| Python | [ruff](https://github.com/astral-sh/ruff), [yapf](https://github.com/google/yapf) [1], [black](https://github.com/ambv/black) [1], [autopep8](https://github.com/hhatto/autopep8), [isort](https://github.com/PyCQA/isort), [docformatter](https://github.com/PyCQA/docformatter), [pyment](https://github.com/dadadel/pyment) | [python-minifier](https://github.com/dflook/python-minifier) [2] | -- | Python 3.7+ [1] | [[2]](https://python-minifier.com) |
| R | [styler](https://github.com/r-lib/styler), [formatR](https://github.com/yihui/formatR) [1] | -- | -- | R | [[1]](https://yihui.shinyapps.io/formatR/) |
| Racket | [raco fmt](https://github.com/sorawee/fmt) | -- | -- | Racket 8.0+ | -- |
| Ruby | [rubocop](https://github.com/rubocop-hq/rubocop) [1], [rubyfmt](https://github.com/fables-tales/rubyfmt), [standardrb](https://github.com/standardrb/standard), [rufo](https://github.com/ruby-formatter/rufo) [1] | -- | -- | Ruby [1], None | -- |
| Rust | [rustfmt](https://github.com/rust-lang/rustfmt) | -- | -- | Rust 1.24+ | -- |
| Scala | [scalafmt](https://github.com/scalameta/scalafmt), [scalariform](https://github.com/scala-ide/scalariform) [1] | -- | -- | None, Java [1] | -- |
| Shell, Bash | [beautysh](https://github.com/lovesegfault/beautysh) [1], [shfmt](https://github.com/mvdan/sh), [shellcheck](https://github.com/koalaman/shellcheck) | [shfmt](https://github.com/mvdan/sh) | -- | Python [1], None | -- |
| SQL, SQL dialects, PostgreSQL | [sql-formatter](https://github.com/sql-formatter-org/sql-formatter) [1], [pg_format](https://github.com/darold/pgFormatter) [2], [sqlparse](https://github.com/andialbrecht/sqlparse) [3] | sqlmin **`(I)`** | -- | Node.js [1], Perl [2], Python 3.6+ [3] | [[1]](https://sql-formatter-org.github.io/sql-formatter), [[2]](https://sqlformat.darold.net) |
| Swift | [apple swift-format](https://github.com/apple/swift-format), [swiftformat](https://github.com/nicklockwood/SwiftFormat) | -- | -- | None | -- |
| SVG | [svgo max](https://github.com/svg/svgo) | [svgo min](https://github.com/svg/svgo) | -- | Node.js | -- |
| TableGen | [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [1] | -- | -- | None | [[1]](https://zed0.co.uk/clang-format-configurator) |
| Terraform | [terraform fmt](https://developer.hashicorp.com/terraform/cli/commands/fmt) | -- | -- | None | -- |
| TextProto | [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [1] | -- | -- | None | [[1]](https://zed0.co.uk/clang-format-configurator) |
| TOML | [taplo](https://github.com/tamasfe/taplo), [topiary](https://github.com/tweag/topiary), [dprint](https://github.com/dprint/dprint) | -- | -- | None | -- |
| TypeScript | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [js-beautifier](https://github.com/beautify-web/js-beautify), [ts-standard](https://github.com/standard/ts-standard), [prettydiff](https://github.com/prettydiff/prettydiff) [1], [tsfmt](https://github.com/vvakame/typescript-formatter), [deno](https://github.com/denoland/deno) [2], [dprint](https://github.com/dprint/dprint) [2], [biome](https://github.com/biomejs/biome) [2] | [prettydiff](https://github.com/prettydiff/prettydiff) [1] | -- | Node.js, None [2] | [[1]](https://prettydiff.com/tool.xhtml) |
| VALA | [uncrustify](https://github.com/uncrustify/uncrustify) [1] | -- | -- | None | [[1]](https://cdanu.github.io/uncrustify_config_preview/index.html) |
| Verilog | [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [1] | -- | -- | None | [[1]](https://zed0.co.uk/clang-format-configurator) |
| Vue | [prettier](https://github.com/prettier/prettier), [prettierd](https://github.com/fsouza/prettierd), [js-beautifier](https://github.com/beautify-web/js-beautify) | -- | -- | Node.js | -- |
| YAML | yamlmax **`(I)`**, [yamlfmt](https://github.com/google/yamlfmt) [1], [prettier](https://github.com/prettier/prettier) [2], [prettierd](https://github.com/fsouza/prettierd) [2] | -- | -- | None [1], Node.js [2] | -- |
| Zig | [zigfmt](https://github.com/ziglang/zig) | -- | -- | None | -- |

> [!NOTE]
>
> - The `sfhexenc` (Hex encoder) operates on bytes. To convert a Decimal value to Hexadecimal you need to use `sfbaseenc` (Base encoder) with a `"--radix"` of `16`.

| Converters | Input | Output | Req. | Note |
| ------ | :------: | :------: | :------: | :------: |
| [yq](https://github.com/mikefarah/yq) | YAML, JSON, CSV, TSV, XML, TOML, LUA, TEXT | YAML, JSON, PROPS, CSV, TSV, XML, BASE64, URI, TOML, SHELL, LUA | None | -- |
| [yj](https://github.com/sclevine/yj) | YAML, JSON, TOML, HCL | YAML, JSON, TOML, HCL | None | -- |
| sfloremipsum **`(I)`** | any | TEXT | None | lorem |
| sfurienc **`(I)`** | any | TEXT | None | uri |
| sfuridec **`(I)`** | any | TEXT | None | uri |
| sfhtmlentitize **`(I)`** | any | TEXT | None | html |
| sfhtmldeentitize **`(I)`** | any | TEXT | None | html |
| sfhtmlstriptags **`(I)`** | any | TEXT | None | html |
| sfregexescape **`(I)`** | any | TEXT | None | regex |
| sfregexunescape **`(I)`** | any | TEXT | None | regex |
| sfstringescape **`(I)`** | any | TEXT | None | string |
| sfstringunescape **`(I)`** | any | TEXT | None | string |
| sfunicodeescape **`(I)`** | any | TEXT | None | unicode |
| sfunicodeunescape **`(I)`** | any | TEXT | None | unicode |
| sfcharcodeenc **`(I)`** | any | TEXT | None | charcode |
| sfcharcodedec **`(I)`** | any | TEXT | None | charcode |
| sfpunycodeenc **`(I)`** | any | TEXT | None | punycode |
| sfpunycodedec **`(I)`** | any | TEXT | None | punycode |
| sfbrailleenc **`(I)`** | any | TEXT | None | braille |
| sfbrailledec **`(I)`** | any | TEXT | None | braille |
| sfquotedprintableenc **`(I)`** | any | TEXT | None | QP |
| sfquotedprintabledec **`(I)`** | any | TEXT | None | QP |
| sflzmacompress **`(I)`** | any | TEXT | None | LZMA |
| sflzmadecompress **`(I)`** | any | TEXT | None | LZMA |
| sfgzipcompress **`(I)`** | any | TEXT | None | GZIP |
| sfgzipdecompress **`(I)`** | any | TEXT | None | GZIP |
| sfbase16enc **`(I)`** | any | TEXT | None | base16 |
| sfbase16dec **`(I)`** | any | TEXT | None | base16 |
| sfbase32enc **`(I)`** | any | TEXT | None | base32 |
| sfbase32dec **`(I)`** | any | TEXT | None | base32 |
| sfbase64enc **`(I)`** | any | TEXT | None | base64 |
| sfbase64dec **`(I)`** | any | TEXT | None | base64 |
| sfbaseenc **`(I)`** | any | TEXT | None | base |
| sfbasedec **`(I)`** | any | TEXT | None | base |
| sfbinaryenc **`(I)`** | any | TEXT | None | binary |
| sfbinarydec **`(I)`** | any | TEXT | None | binary |
| sfdecimalenc **`(I)`** | any | TEXT | None | decimal |
| sfdecimaldec **`(I)`** | any | TEXT | None | decimal |
| sfoctalenc **`(I)`** | any | TEXT | None | octal |
| sfoctaldec **`(I)`** | any | TEXT | None | octal |
| sfhexenc **`(I)`** | any | TEXT | None | hex |
| sfhexdec **`(I)`** | any | TEXT | None | hex |
| sfhexdumpenc **`(I)`** | any | TEXT | None | hexdump |
| sfhexdumpdec **`(I)`** | any | TEXT | None | hexdump |
| sfromannumeralenc **`(I)`** | any | TEXT | None | roman |
| sfromannumeraldec **`(I)`** | any | TEXT | None | roman |
| sfx2diacritics **`(I)`** | any | TEXT | None | diacritics |
| sfx2uuid **`(I)`** | any | TEXT | None | UUID |
| sfx2randpass **`(I)`** | any | TEXT | None | random |
| sfx2crc32 **`(I)`** | any | TEXT | None | crc32 |
| sfx2md5 **`(I)`** | any | TEXT | None | md5 |
| sfx2sha1 **`(I)`** | any | TEXT | None | sha1 |
| sfx2sha256 **`(I)`** | any | TEXT | None | sha256 |
| sfx2sha512 **`(I)`** | any | TEXT | None | sha512 |
| sfx2sha3256 **`(I)`** | any | TEXT | None | sha3_256 |
| sfx2sha3512 **`(I)`** | any | TEXT | None | sha3_512 |
| sfx2shake256 **`(I)`** | any | TEXT | None | shake_256 |
| sfx2shake512 **`(I)`** | any | TEXT | None | shake_512 |
| sfextractemailaddr **`(I)`** | any | TEXT | None | emails |
| sfextractipaddr **`(I)`** | any | TEXT | None | IPaddr |
| sfextractmacaddr **`(I)`** | any | TEXT | None | MACaddr |
| sfextracturls **`(I)`** | any | TEXT | None | URLs,domains |
| sfextractfilepaths **`(I)`** | any | TEXT | None | filepaths |
| sfextractdates **`(I)`** | any | TEXT | None | dates |
| sfunixtimestampenc **`(I)`** | any | TEXT | None | timestamp |
| sfunixtimestampdec **`(I)`** | any | TEXT | None | timestamp |
| sfx2asm **`(I)`** | any | TEXT | Node.js | arm,x86 32/64 assembler |
| sfx2disasm **`(I)`** | any | TEXT | Node.js | arm,x86 32/64 disassembler |

<sub>`sf` = **S**ublime **F**ormatter</sub>

## Installation

- **Using [Package Control](https://packagecontrol.io/packages/Formatter):** run `Package Control: Install Package` and select `Formatter`
- **_or_** **Download:** the latest source from [GitHub](https://github.com/bitst0rm-pub/Formatter) to your sublime `Packages` directory and rename it to `Formatter`

The `Packages` directory is located in:

- MacOSX: `~/Library/Application Support/Sublime Text 3/Packages/`
- Linux: `~/.config/sublime-text-3/Packages/`
- Windows: `%APPDATA%/Sublime Text 3/Packages/`

## Configuration

This section is the head of Formatter. While the configuration is easy and self-explained, it still needs a detailed explanation of the underlying principles and context.<br />

Formatter stores third-party plugin [config files](https://github.com/bitst0rm-pub/Formatter/tree/master/config) in:

```text
Sublime Text > Packages > User > formatter.assets > config
```

- You can use these files directly or place them in a location of your choice. Formatter provides only a set of default (original) config files to illustrate how it works. You might want to tweak and refine them to fit your needs. The full list of supported options and parameters can be found on plugins dev websites.
- You can use a different config file format than the default one provided by Formatter. For example, while Formatter typically uses JSON or YAML (`xxx_rc.json`) by default, you can write your own config in JavaScript format (`xxx_rc.mjs`) or any other format supported by third-party plugins.

> [!NOTE]
>
> Do **not** use files with the suffix `.master.` as they serve as _reference_(_example_) files for your final configuration and could be overwritten by any package updates.<br />
> Reason: Some exotic plugins do not support input config file, while others do not understand stdio. To overcome this limitation, you will need these _example_ files as reference to configure them.<br />
> It is recommended to explore this folder, as it may contain additional config files for the same plugin.

Formatter settings can be accessed from: `Preferences > Package Settings > Formatter > Settings`

The following setting details - along with their default values and examples - are provided to guide you on how to set it up:

> [!TIP]
>
> - Options are _optional_: you do not need to take the whole set of options. Take only what you need, but keep the JSON structure intact.
> - You do not have to use the preset modules. Instead, you can create new ones with a unique UID using either generic or module methods.
> - Not all syntax highlighting plugins exist for every language. Syntaxes like `"text"` or `"plain"` can serve as workarounds.

1. **Example setting options:** _Formatter.sublime-settings_

   ```js
   {
        // Enable debug mode to view errors in the console.
        // Accepted values: true (verbose), false, OR "status" (recommended)
        "debug": false,

        // By default, all previous console messages will be cleared. (ST4088+ only)
        // If you want to retain the console message history, set this to false.
        "clear_console": true

        // Auto open the console panel whenever formatting fails.
        // This is useful if "debug" is "status" or true
        "open_console_on_failure": false,

        // The counterpart for success.
        "close_console_on_success": false,

        // Timeout to abort subprocess in seconds.
        // Default to 10 seconds. Set to false to disable the timeout.
        "timeout": 10,

        // Limit the total number of characters in the file.
        // A max of 1 MB = 1024 * 1024 ≈ 1.048.576 chars seems reasonable.
        // Accepted values: int OR false
        "file_chars_limit": false,

        // Integrate your custom modules into the Formatter ecosystem.
        // Modules can be located either locally or remotely (with or without signing).
        // This option must be of type string pointing to the JSON metata file path.
        // More about the format of this file, see README.md > Integrating modules
        "custom_modules_manifest": "",

        // Display results in the status bar with the current settings mode info:
        // PUS: Persistent User Settings
        // PQO: Persistent Quick Options
        // TQO: Temporary Quick Options
        "show_statusbar": true,

        // Display a real-time word and character count in the status bar.
        // By default, whitespace is not included in the character count.
        "show_words_count": {
            "enable": true,
            "use_short_label": false,
            "ignore_whitespace_char": true
        },

        // Remember and restore cursor position, selections, bookmarks,
        // and foldings each time a file is closed and re-opened.
        // This is helpful to resume your work from where you left off.
        // It does not remember any sublime sessions as name might suggest.
        "remember_session": true,

        // Configure the layout when opening new files.
        // This only takes effect if the "new_file_on_format" option is true.
        // Accepted values: "2cols", "2rows", "single" OR false
        "layout": {
            "enable": "2cols",
            "sync_scroll": true
        },

        // A set of directories where executable programs are located.
        // These can be absolute paths to module directories or Python zipfiles.
        // Any environment variables like PATH, PYTHONPATH, GEM_PATH, GOPATH,
        // GOROOT, GOBIN, TMPDIR, WHATEVER, etc. can be added here.
        // This is similar to running 'export PYTHONPATH="/path/to/my/site-packages"'
        // from the terminal. It is temporary, your system environment remains untouched.
        // On Windows, you can use either escaped backslashes (e.g., "C:\\a\\b\\c") or
        // forward slashes (e.g., "C:/a/b/c") as path separators for all other options.
        // Tip: Activating "print_on_console" will help to set the correct environment.
        "environ": {
            "print_on_console": false,
            "PATH": ["/path/to/erlang@22/bin:$PATH", "$PATH:/path/to/elixir/bin", "/path/to/.cache/rebar3/bin:$PATH"],
            "GEM_PATH": ["${HOME}/to/my/ruby"],
            "PYTHONPATH": ["${packages}/User/MyFolder/python/lib/python3.7/site-packages"],
            "OLALA": ["$HOME/.cabal/bin:$PATH", "~/.olala/bin:$PATH"]
        },

        // This option resolves the syntax conflicts described in "format_on_save".
        // It acts as an override and only applies to the following options:
        // 1. "format_on_save"
        // 2. "format_on_paste"
        // Syntaxes in this option always take precedence over the syntaxes specified there.
        // All syntaxes must be unique without any duplicates.
        "format_on_priority": {
            "enable": false,
            "csscomb": ["css"],
            "jsbeautifier": ["js"]
        },

        // This option enables auto-detect formatting for file.
        // Configure it here and/or by using the dot files in your working folder.
        // If both methods are used, the config from the dot files will override this embedded one.
        // Advantage: The embedded one can handle both saved and unsaved files,
        // while the dot files variant only applies to saved files, as unsaved files
        // (puffer in view) never have a working dir to contain dot files.
        //
        // This option supports chaining multiple formatters in a single run.
        // Chaining requires a list type with a maximum of 10 items in a list.
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
        // More about this feature, see README.md > Auto-detect Formatting
        "auto_format": {
            "config": {
                "format_on_save": false,
                "format_on_paste": false
            },
            "python": ["isort", "black"],  // chaining sequentially in a single run, type list
            "json": "jsbeautifier",        // as type string
            "php": {                       // OR as type dictionary
                "uid": "phpcsfixer"
            },
            "html": {                      // dict can be used as a list item in chaining list
                "uid": "jsbeautifier",
                "exclude_syntaxes": {
                    "html": ["markdown"]
                }
            }
        },

        // THIRD-PARTY PLUGINS LEVEL
        // Info: Preferences > Package Settings > Formatter > Modules Info
        "formatters": {
            "examplemodule": { // MODULE METHOD
                // Plugin activation.
                // By default, all plugins are disabled.
                "enable": false,

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
                // Terminology: Hidden dot files, like .bashrc, do not have an extension to exclude.
                "format_on_save": false,

                // Auto formatting whenever code is pasted into the current file.
                // This option works the same way as "format_on_save".
                // So the mentioned syntax conflicts and solution are the same.
                //
                // Also you can use the same dictionary format to exclude:
                // dirs, files, extensions, and syntaxes
                "format_on_paste": false,

                // Create a new file containing formatted code.
                // The value of this option is the suffix of the new file being renamed.
                // Suffix must be of type string. =true, =false means =false
                // Note: It will overwrite any existing file that has the same new name in
                // the same location.
                // For example:
                // "new_file_on_format": "min", will create a new file:
                // myfile.raw.js -> myfile.raw.min.js
                "new_file_on_format": false,

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
                // }
                "dir_format": false,

                // Syntax support based on the scope name, not file extension.
                // Syntax name is part of the scope name and can be retrieved from:
                // Tools > Developer > Show Scope Name
                // End-users are advised to consult plugin manpages to add more syntaxes.
                // The wildcard syntax "*" will accept any syntax, regardless of syntax type.
                "syntaxes": ["css", "html", "js", "php"],

                // Exclude a list of syntaxes associated with an individual syntax key.
                // The wildcard syntax "*" will accept any key, regardless of syntax type.
                // This option is useful to exclude part of the scope selector.
                // For example: text.html.markdown, want html but wish to filter out html.markdown.
                "exclude_syntaxes": {
                    "html": ["markdown"],
                    "*": ["markdown"]
                },

                // Path to the interpreter.
                // Omit this option will force Formatter to detect interpreter on PATH and
                // automatically set them for you.
                // Or you can set the basename as the interpreter name to search on PATH or
                // locally, similar to how it is done with the "executable_path" option.
                "interpreter_path": ["${HOME}/example/path/to\\$my/java.exe"],

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
                // it from the variable expansion "${...}".
                "executable_path": ["${HOME}/example/path/to\\$my/php-cs-fixer.phar"],

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
                //    explained in README.md > Auto-detect Formatting
                "config_path": {
                    "ignore_dotfiles": false,
                    "css": "${packages}/User/formatter.assets/config/only_css_rc.json",
                    "php": "${packages}/User/formatter.assets/config/only_php_rc.json",
                    "default": "${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json"
                },

                // Array of additional arguments for the command line.
                "args": ["--basedir", "./example/my/foo", "--show-bar", "yes"],

                // This option is specifically designed for type graphic.
                // It enables SVG image generation for saving.
                // Enable it if you need SVG image at the cost of processing time.
                // Unlike the generic method, this method only supports SVG generation.
                "render_extended": false,

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
            "examplegeneric": { // GENERIC METHOD
                // Formatter provides 2 methods to add custom plugins:
                // - Generic: this one, you design the bridge yourself. Suitable for simple tasks.
                // - Modules: requires writing Python modules for complex tasks.
                // Note: The Generic method requires a Sublime Text restart after adding or changing
                // the "name" and "type" keys. Also, avoid reusing existing UID keys in JSON.

                // The Capitalized plugin name, preferred in PascalCase style (REQUIRED!)
                // This will appear in the Sublime menu and other commands.
                "name": "ExampleGeneric",

                // The plugin type (REQUIRED!)
                // This will categorize the plugin. Accepted values:
                // "beautifier", "minifier", "converter", "graphic", or any string of your choice.
                "type": "beautifier",

                // This will activate the "args_extended" option for the graphic type
                // to generate extended files like SVG for saving.
                "render_extended": false,

                // The exit code for the third-party plugin (optional, default to 0).
                "success_code": 0,

                // Local config dotfiles supported by your plugin (optional).
                // These files will be auto detected and used as config file within your project.
                "dotfiles": [".pluginrc", "pyproject.toml", ".pycodestyle", "setup.cfg", "tox.ini", ".pep8", ".editorconfig"],

                // Keywords to identify special local config dotfiles (optional).
                // Special dotfiles: "pyproject.toml", ".pycodestyle", "setup.cfg", "tox.ini", ".pep8", ".editorconfig"
                // contain specific sections, such as "[tool.autopep8]" for identification.
                // This is only necessary if the uid, here "examplegeneric", differs from "autopep8".
                "df_ident": ["juliet", "romeo", "autopep8"],

                // Same as the one in the examplemodule.
                "enable": false,
                // Same as the one in the examplemodule.
                "format_on_save": false,
                // Same as the one in the examplemodule.
                "format_on_paste": false,
                // Same as the one in the examplemodule, but disabled/unused for type graphic.
                "new_file_on_format": false,
                // Same as the one in the examplemodule, but disabled/unused for type graphic.
                "dir_format": false,
                // Same as the one in the examplemodule.
                "syntaxes": ["css", "html", "js", "php"],
                // Same as the one in the examplemodule.
                "exclude_syntaxes": {},
                // Same as the one in the examplemodule.
                "interpreter_path": ["${HOME}/example/path/to\\$my/php.exe"],
                // Same as the one in the examplemodule.
                "executable_path": ["${HOME}/example/path/to\\$my/php-cs-fixer.phar"],
                // Same as the one in the examplemodule.
                "config_path": {
                    "ignore_dotfiles": false,
                    "css": "${packages}/User/formatter.assets/config/only_css_rc.json",
                    "php": "${packages}/User/formatter.assets/config/only_php_rc.json",
                    "default": "${packages}/User/formatter.assets/config/css_plus_js_plus_php_rc.json"
                },

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
                // In all other cases, output may not be as a file; use "-" or "--" instead.
                "args": ["{{i}}", "{{e=node}}", "--config", "{{c}}", "--basedir", "./example/my/foo", "--"],

                // This is for the SPECIAL CASE GRAPHIC to saving extended graphic files.
                // To use this, the trigger option "render_extended" above must be activated.
                // Sublime Text only supports PNG, JPG, and GIF images. Formatter uses PNG to display
                // image in view and generates the same image in various formats for you.
                // WARNING: Formatter will loop subprocess to render extended files. This means, process
                // will takes more time. This option might be useful for the final step to production.
                // "key":["value",..], where key is the output file extension, value is the command arguments.
                "args_extended": {
                    "svg": ["{{e}}", "--config", "{{c}}", "--blabla-format", "svgv5", "--output", "{{o}}"],
                    "pdf": ["{{e}}", "--config", "{{c}}", "--blabla-format", "pdf2001", "--output", "{{o}}"]
                }
            },
            // -- END of explanation --
        }
   }
   ```

2. **Example setting plugins:** _Formatter.sublime-settings_

   ```js
   {
        "debug": true,

        "environ": {
            "print_on_console": true,
            "PATH": ["/path/to/erlang@22/bin:$PATH", "$PATH:/path/to/elixir/bin", "/path/to/.cache/rebar3/bin:$PATH"],
            "GEM_PATH": ["${HOME}/to/my/ruby"],
            "PYTHONPATH": ["${packages}/User/MyFolder/python/lib/python3.7/site-packages"],
            "OLALA": ["$HOME/.cabal/bin:$PATH", "~/.olala/bin:$PATH"]
        },

        "formatters": {
            "stylelint": {  // EXAMPLE: MODULE METHOD
                "info": "https://github.com/stylelint/stylelint",
                "enable": true,
                "format_on_paste": false,
                "format_on_save": false,
                "new_file_on_format": false,
                "dir_format": {
                    "exclude_dirs_regex": [".*(\\.git|node_modules|__pycache__|env).*", ".*/project/test"],
                    "exclude_files_regex": [".*test_file\\.py\\$", ".*/project/test/config\\.json"],
                    "exclude_extensions_regex": ["DS_Store", "localized", "tmp", "bak", "ya?ml", "mjs", "json"],
                    "exclude_syntaxes": []
                },
                "syntaxes": ["css", "scss", "sass", "less", "sss", "sugarss"],
                "executable_path": ["${packages}/User/myjs/node_modules/.bin/stylelint"],
                "args": ["--config-basedir", "/path/to/js/node_modules"],
                "config_path": {
                    "ignore_dotfiles": false,
                    "default": "${packages}/User/formatter.assets/config/stylelint_rc.json"
                }
            },
            "uncrustify": {  // EXAMPLE: GENERIC METHOD: Text-to-Text. Restart ST.
                "name": "Uncrustify",
                "type": "beautifier",
                "success_code": 0,
                "dotfiles": [".uncrusifyrc", "pyproject.toml"],
                "args": ["{{e}}", " --style=file:{{c}} ", "--"],

                "info": "https://github.com/uncrustify/uncrustify",
                "enable": true,
                "format_on_save": false,
                // "new_file_on_format": false, // Add this, if needed
                "dir_format": false
                "syntaxes": ["c", "c++", "cs", "objc", "objc++", "d", "java", "pawn", "vala"],
                "executable_path": ["${HOME}/path/to/bin/uncrustify"],
                "config_path": {
                    "ignore_dotfiles": true,
                    "objc": "${packages}/User/formatter.assets/config/uncrustify_objc_rc.cfg",
                    "objc++": "${packages}/User/formatter.assets/config/uncrustify_objc_rc.cfg",
                    "java": "${packages}/User/formatter.assets/config/uncrustify_sun_java_rc.cfg",
                    "default": "${packages}/User/formatter.assets/config/uncrustify_rc.cfg"
                }
            },
            "d2": {  // EXAMPLE: GENERIC METHOD: Text-to-Image. Restart ST.
                "name": "D2",
                "type": "graphic",
                "success_code": 0,
                "render_extended": true,

                "info": "https://github.com/terrastruct/d2",
                "enable": true,
                "format_on_save": false,
                "format_on_paste": false,
                "syntaxes": ["d2"],
                "args": ["{{e}}", "--theme", "300", "--dark-theme", "200", "-l", "elk", "--pad", "0", "-", "{{o}}"],
                "args_extended": {
                    "svg": ["{{e}}", "--theme", "300", "--dark-theme", "200", "-l", "elk", "--pad", "0", "-", "{{o}}"],
                    "pdf": ["{{e}}", "--theme", "300", "--dark-theme", "200", "-l", "elk", "--pad", "0", "-", "{{o}}"]
                },
                "executable_path": "/path/to/bin/d2",
                "config_path": {
                    "ignore_dotfiles": true,
                    "default": "${packages}/User/formatter.assets/config/d2_rc.yaml"
                }
            }
        }
   }
   ```

## Auto-detect Formatting

Starting from version 1.4.0, Formatter introduces a configuration mechanism to auto-detect formatter for itself (Special thanks to @[midrare](https://github.com/midrare) for ideas, tests and suggestions). There are 2 methods to achieve this:

- Using embedded settings in your User `Formatter.sublime-settings`
- Placing dot files inside the working folder, similar to per-project basis.

**_Advantage:_** The embedded one can handle both saved and unsaved files, while the dot files variant only applies to saved file, as unsaved files (puffer on view) never have a working dir in order to contain a dot file.

> [!NOTE]
>
> This option supports chaining multiple formatters in a single run.<br />
> Chaining multiple formatters is limited to max. **10** items in a list.

1. **The dot files variant**: will start to search up the file tree inside the working folder until a following file is found: `.sublimeformatter.json` OR `.sublimeformatter`

   _.sublimeformatter.json_, _.sublimeformatter_

   ```js
   {
       // Comments are allowed.
       "python": ["isort", "black"],  // chaining sequentially in a single run, type list
       "json": "jsbeautifier",        // as type string
       "php": {                       // OR as type dictionary
           "uid": "phpcsfixer"
       },
       "html": {                      // dict can be used as a list item in chaining list
           "uid": "jsbeautifier",
           "exclude_syntaxes": {
               "html": ["markdown"]
           }
       }
   }
   ```

   - User-specific actions can be set using: `.sublimeformatter.user.json` OR `.sublimeformatter-user`

   _.sublimeformatter.user.json_, _.sublimeformatter-user_

   ```js
   {
       "format_on_save": true,
       "format_on_paste": false
   }
   ```

   Or if you prefer the dictionary format:

   ```js
   {
       "format_on_save": {
           "exclude_dirs_regex": [".*(\\.git|node_modules|__pycache__|env).*", ".*/project/test"],
           "exclude_files_regex": [".*test_file\\.py\\$", ".*/project/test/config\\.json"],
           "exclude_extensions_regex": ["ya?ml", "mjs", "json"],
           "exclude_syntaxes": []
       },
       "format_on_paste": false
   }
   ```

   - To ignore a specific syntax and its associated plugin, you can use: `.sublimeformatter.ignore.json` OR `.sublimeformatter.ignore`<br />
   For example, if you want to ignore the local config dotfile `.prettierrc` in your working folder in favor of your own config file specified in the option `"config_path":`

   _.sublimeformatter.ignore.json_, _.sublimeformatter.ignore_

   ```js
   {
       "ignore_dotfiles": true,           // type boolen: false OR true
       "json": ["jsbeautifier", "deno"],  // to ignore "config_path" option
       "python": ["autopep8"],
       "default": ["scalafmt", "stylelint"]
   }
   ```

2. **The embedded variant**: embeds your auto-detect config within your User `Formatter.sublime-settings`. In cases where both the dot files and embedded methods coexist, then the config from dot files will take precedence over the embedded one.

   _Formatter.sublime-settings_

   ```js
   {
       "debug": "status",

       "auto_format": {
           "config": {
               "format_on_save": false,  // OR use the dictionary format to exclude
               "format_on_paste": false  // OR use the dictionary format to exclude
           },
           "python": ["isort", "black"],  // chaining sequentially in a single run, type list
           "json": "jsbeautifier",        // as type string
           "php": {                       // OR as type dictionary
               "uid": "phpcsfixer"
           },
           "html": {                      // dict can be used as a list item in chaining list
               "uid": "jsbeautifier",
               "exclude_syntaxes": {
                   "html": ["markdown"]
               }
           }
       },

       "formatters": {}
   }
   ```

This is a one-command/one-keybinding feature. Both the app and context menu will now indicate whether a current folder is ready for Formatter with a new item: `Auto Format File`

## Per-project Formatting

Project-specific formatting can be configured using 3 methods in the following order:

- User project config dotfile.
- Third-party plugin project config dotfile.
- Sublime Text project config file (`.sublime-project`)

1. **User project config dotfile**:

This file is actually the config file you specify in the `"config_path"` setting, but renamed and placed in the root folder of your project.<br />
The naming pattern should follow: `.sf` + `uid` + `rc`<br />
For example: `.sfautopep8rc` (`sf` = Sublime Formatter)

2. **Third-party plugin project config dotfile**:

This refers to common dotfiles used by popular plugins, such as `.prettierrc`, `.clang-format`, etc.

3. **Sublime Text project config file**:

Formatter is able to add and override any setting on per-project basis using `.sublime-project` files.<br />
You might want to restart Sublime Text to apply the changes to the `.sublime-project` file.

_.sublime-project_

```js
{
    "folders": [
        {
            "path": "/path/to/my/project"
        }
    ],

    "settings": {
        "Formatter": {
            "debug": "status",
            "formatters": {
                "htmltidy": {
                    "format_on_save": true
                },
                "jsbeautifier": {
                    "config_path": {
                        "js": null,  // here, override to invalidate
                        "default": "${HOME}/path/to/new/jsbeautify_rc.json"  // here, override to update
                    }
                }
            }
        }
    }
}
```

## Usage

Formatter has been designed to detect the syntax of files according to file scopes, not file extension. In the most cases, Sublime Text already does this job for you when you open a file. For the rest, you must explicit assign the syntax via the syntax menu in the righ-hand bottom corner or via:

```text
Sublime Text > View > Syntax
```

Setting wrong syntax when formatting code will cause error:

```text
Syntax out of the scope
```

Formatting actions can be triggered in different ways:

- Tools > Command Palette (<kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>) and type `Formatter`.
- Tools > Formatter
- Right-click > Context-Menu > Formatter
- Preferences > Package Settings > Formatter > Key Bindings

### The Quick Options

This feature is designed to help users quickly access and switch between options, without the need to navigate the Settings file.
It has no default values and is _primarily_ intended for temporarily toggling between File Format and Dir Format modes, given the limited UI and API design of Sublime Text.<br />
It includes 3 modes:

- **Temporary Quick Options (TQO)**: By default, all options are temporary and only take effect during the current Sublime session. They will be automatically reset when you close Sublime.
- **Persistent User Settings (PUS)**: Clicking the `Reset` option will reset all current `Temporary Quick Options` and switch to using your User Settings from `Formatter.sublime-settings`.
- **Persistent Quick Options (PQO)**: Clicking the `Save` option will make all current `Temporary Quick Options` persistently. This means that closing and reopening Sublime will retain these options. To exit this mode just clicking the `Reset` option.

**Summary:**

- The `Reset` option is the exclusive method to exit any mode.
- Clicking on the **_same_** selected item will remove it from the list.
- None of the modes will ever modify your Settings file.
- The current mode is indicated on the status bar for your reference.

## Development

Starting from version 1.0.6, you now are able to create your own module for a third-party plugin that hasn't yet been integrated into Formatter. This allows you to extend your individual needs. In theory, you can use Formatter as a platform to convert **_any_** form of text, as long as third-party plugins operate in a text-to-text manner, such as Text-to-QR code, text-to-ASCII image conversion.

### 1. Prerequisite

1. Create a config file specific to your third-party plugin _if needed_. Config files for third-party plugins must be placed in the following folder:

   ```text
   Formatter > config
   ```

2. Activate the debug mode with the secret key `dev` in your Formatter settings. The `dev` key should never be used in a production environment.

   _Formatter.sublime-settings_

   ```js
   {
       "debug": true,  // printing error messages
       "dev": true     // updating modified files
       ...
   }
   ```

### 2. Creating a module

Developing a module for Formatter is straightforward. All you need to do is creating a python file with just a few lines of code as below:

1. Create a file with the file name pattern `formatter_thisismyfirstpluginmodule.py` inside the `Formatter > modules` folder. Ensure to follow these conventions:

   - Create only **one** file per plugin in the `Formatter > modules` folder:
     - All functions and other necessary components should reside inside this file.
   - The file name is all **lowercase** and contains only **alphanumeric** characters (no spaces or underscores):
     - Prefix: `formatter_` (indicating that it's a module for a third-party plugin)
     - Suffix: `thisismyfirstpluginmodule` (serving as the unique Formatter ID, also known as `uid`)
     - Extension: `.py`
   - External libraries that the third-party plugin relies on should be placed in the folder: `Formatter > libs`
     - Libraries must not contain proprietary elements, including the LICENSE file or license notices.
     - No communication over the Internet.

> [!IMPORTANT]
>
> It is recommended to add an arbitrary char to your `uid` to prevent your plugin from being overwritten by future Formatter updates that may introduce new plugins with the same `uid`.<br />
>
> For plugins that rely on the following special local config dotfiles:<br />
> `pyproject.toml`, `.pycodestyle`, `setup.cfg`, `tox.ini`, `.pep8`, `.editorconfig`<br />
> you should use a `uid` matching the relevant section name, such as `[tool.autopep8]`. Otherwise, Formatter will not be able to identify and apply the correct local config dotfile.<br />
> For example, a correct `uid` would be: formatter_`autopep8`.py<br />
> Alternatively, you can achieve the same result by using the keywords identifier: `DF_IDENT = ['autopep8']`

2. The content of this module file should follow the structure outlined below:

   _formatter_thisismyfirstpluginmodule.py_

   ```py
   INTERPRETERS = []                                           # optional: fallback list of interpreter names
   EXECUTABLES = []                                            # optional: fallback list of executable names
   DOTFILES = []                                               # optional: list of the local config dotfile names
   DF_IDENT = []                                               # optional: list of keywords to identify special dotfiles
   MODULE_CONFIG = {}                                          # REQUIRED: template to create several sublime config files


   class ThisismyfirstpluginmoduleFormatter(Module):           # REQUIRED: the Capitalized uid and the Capitalized word "Formatter", nothing else!
       def __init__(self, *args, **kwargs):
           super().__init__(*args, **kwargs)                   # REQUIRED: initialize the module APIs from common.Module

       def get_cmd(self):                                      # optional: get commands, e.g get the "config_path", "executable_path" etc...

       def format(self):                                       # REQUIRED: the entry point, predefined function name exact as written
   ```

   Details as an example:

   ```py
   from ..core import log                                      # optional: log to debugging this file
   from ..core import Module                                   # REQUIRED: a collection of APIs to assist in running this file


   INTERPRETERS = ['node']                                     # optional: case-sensitive fallback names (without extension) if interpreter is not found
   EXECUTABLES = ['terser']                                    # optional: case-sensitive fallback names (without extension) if executable is not found
   DOTFILES = ['.terser.json']                                 # optional: to auto-detecting the local config dotfile
   DF_IDENT = []                                               # optional: a list of keywords to identify special local config dotfiles
   MODULE_CONFIG = {                                           # REQUIRED: template to create several sublime config files
       'source': 'https://thirdparty-plugin.com',              # REQUIRED: info on where the user can download the plugin
       'name': 'MyFirstPlugin',                                # REQUIRED: a Capitalized plugin name of your choice, preferred in PascalCase style
       'uid': 'thisismyfirstpluginmodule',                     # REQUIRED: must match the suffix of "formatter_thisismyfirstpluginmodule.py"
       'type': 'minifier',                                     # REQUIRED: "beautifier" OR "minifier" OR "converter" OR "graphic",
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
       'comment': 'Build-in, no executable.'                    # optional: a single short comment, limited to 200 chars or just omit it
   }


   class ThisismyfirstpluginmoduleFormatter(Module):           # REQUIRED: the Capitalized of uid and the Capitalized word "Formatter", nothing else!
       def __init__(self, *args, **kwargs):                    # REQUIRED: initialization
           super().__init__(*args, **kwargs)                   # REQUIRED: initialize the module APIs from common.Module

       def get_cmd(self):                                      # optional: get commands e.g get the "config_path", "executable_path" etc...
           cmd = self.get_combo_cmd(runtime_type='node')       # See API below, with important note to use with Node.js
           if not cmd:
               return None

           path = self.get_config_path()                       # See API below
           if path:
               cmd.extend(['--config-file', path])             # an array of args to run the third-party plugin

           cmd.extend(['--compress', '--mangle', '--'])

           # cmd.extend(['--output', self.get_output_image()]) # REQUIRED: only for special case of "type": "graphic"

           return cmd

       def format(self):                                       # REQUIRED: the entry point, predefined function name exact as written
           cmd = self.get_cmd()

           try:
               exitcode, stdout, stderr = self.exec_cmd(cmd)   # REQUIRED: process command

               if exitcode > 0:                                # REQUIRED: please consult the plugin documentation for the exit codes
                   self.print_exiterr(exitcode, stderr)
               else:
                   # if self.is_render_extended():             # is render extended mode activated?
                   #     cmd = self.all_png_to_svg_cmd(cmd)
                   #     try:
                   #         self.exec_cmd(cmd)                # REQUIRED: only for special case of "type": "graphic" to generate SVG image.
                   #     except Exception as e:
                   #         self.print_oserr(cmd, e)

                   return stdout                               # REQUIRED: return the formatted code on success
           except Exception as e:
               self.print_oserr(cmd, e)

           return None                                         # REQUIRED: return None to indicate failure

   ```

   **That's all**. Lean and easy. Happy coding 🤪

   Restart Sublime Text.<br />
   New keys will be automatically created in the _Default_ settings.<br />
   Do not forget to update/adjust your _User_ settings:<br />
   `Preferences > Package Settings > Formatter > Settings`

### 3. Integrating modules

You have the choice to either submit a pull request or integrate your modules yourself by configuring:

_Formatter.sublime-settings_

```js
{
    "custom_modules_manifest": "/path/to/local/metadata.json",  // or
    "custom_modules_manifest": "https://raw.githubusercontent.com/you/repo/main/metadata.json",
}
```

The structure of the metadata JSON file should follow this format:

```js
{
    "version": "0.0.1",                              // tells to update
    "ca_cert": "/path/to/ca_cert.pem",               // optional, CA Certificate path for ssl
    "public_key": "/path/to/public_key.asc",         // optional, but required for .sig file
    "gpg": "gpg.exe (on PATH) or /path/to/gpg.exe",  // optional, omit this to auto-detect gpg on PATH
    "local": {
        "config": ["/path/to/dir", "/path/to/file"],
        "libs": ["/path/to/dir", "/path/to/file"],
        "modules": ["/path/to/dir", "/path/to/file"]
    },
    "remote": [
        "http|s|ftp://example.com/archive/refs/heads/myproject1.zip",      // only zip or tar.gz
        "http|s|ftp://example.com/archive/refs/heads/myproject1.zip.sig",  // optional, but pattern: filename + '.sig'
        "http|s|ftp://example.com/archive/refs/heads/myproject2.tar.gz",
        "http|s|ftp://example.com/archive/refs/heads/myproject2.tar.gz.sig"
    ]
}
```

> [!IMPORTANT]
>
> - Each remote archive file (_myproject.zip_) must include at least one of the fixed folders: `config`, `libs`, `modules`
> - All files must be placed within these 3 **predefined** folders.
> - To update your code, just reset the `.custom` file in the Formatter root folder.
> - The following Formatter libs are not exchangeable: `dateutil`, `prettytable`, `sqlmin`, `stone`, `toml`, `wcswidth`, `yaml`
>
> _Python is not JS. You are responsible for handling any operations over the internet._

### 4. API

> [!IMPORTANT]
>
> Formatter is designed to work with input puffer of file content instead of file as file path.<br />
> If a plugin requires a file path as input and does not support reading from `stdin`, then you must use `self.create_tmp_file(suffix=None)`
> in place of file path to get file content as puffer. Otherwise, the auto format chaining will not work with that plugin.

The entire set of Formatter API can be found in the file: `core > common.py`<br />
Responsible for interacting with plugin modules is the class: `class Module:`<br />
There are more methods in this class you can use, but Formatter only uses these:

1. Essentially for the `def get_cmd(self)` function:

   ```py
   # This alias method combines get_interpreter() and get_executable().
   # Set runtime_type=(None|'node'|'python'|'perl'|'ruby') to enable local executable search.
   # Currently, only None and 'node' are functional. All others are placeholders for future implementation.
   # Note: Always use this method instead of self.get_interpreter() when runtime_type='node',
   #       as it includes a mechanism to auto detect the local executable for node.
   cmd = self.get_iprexe_cmd(runtime_type=None)

   # This alias method just extends get_iprexe_cmd(runtime_type=) by adding get_args().
   # Note: Always use this method instead of self.get_interpreter() when runtime_type='node',
   #       as it includes a mechanism to auto detect the local executable for node.
   cmd = self.get_combo_cmd(runtime_type=None)

   # Get the interpreter path or None.
   # Note: Do not use this directly for runtime_type='node'
   interpreter = self.get_interpreter()

   # Get the executable path or None.
   # Set runtime_type=(None|'node'|'python'|'perl'|'ruby') to enable local executable search.
   executable = self.get_executable(runtime_type=None)

   # Get the input "args" option from the User settings.
   # The returned args is a list of string items or [].
   args = self.get_args()

   # Parse the input "args" option from the User settings.
   # The returned args is a dict of string items or {}.
   # If convert is set to True, string items will be converted to their real type.
   parse_args = self.parse_args(convert=False)

   # Get the input "config_path" from the User settings or
   # the path to the local config dotfile if found or None.
   path = self.get_config_path()

   # Get the current text content in view or the current selected text.
   text = self.get_text_from_region(self.region)

   # Get the detected syntax of the current file or None.
   syntax = self.get_assigned_syntax()

   # Get the path to the output PNG image. Applicable only to the special case of type: graphic
   output_image = self.get_output_image()

   # Get a dictionary of file path components:
   # {'path':, 'cwd':, 'base':, 'stem':, 'suffix':, 'ext':} or None.
   components = self.get_pathinfo()

   # Create and remove temp file automatically (recommended).
   # Useful for plugins that lack a built-in mechanism for in-place file modification.
   tmp_file_path = self.create_tmp_file(suffix=None, autodel=True)

   # Create and get the temp file path for manually removing.
   # Useful for plugins that lack a built-in mechanism for in-place file modification.
   tmp_file_path = self.create_tmp_file(suffix=None)

   # Remove temp file manually.
   self.remove_tmp_file(tmp_file_path)
   ```

2. Essentially for the `def format(self)` function:

   ```py
   # To replace cmd list items to generate SVG file for download.
   # It is applicable only to the special case of type: graphic.
   # Note: extended_cmd MUST be executed right before return stdout (=success)!
   extended_cmd = self.ext_png_to_svg_cmd(cmd)  # replace extension .png -> .svg
   extended_cmd = self.all_png_to_svg_cmd(cmd)  # replace all occurred png -> svg

   # To process the formatting with all input (fixed) arguments.
   # stdout as PIPE. 99% of plugins use this way.
   exitcode, stdout, stderr = self.exec_cmd(cmd)

   # stdout as file. 1% are just retarded.
   exitcode, stdout, stderr = self.exec_cmd(cmd, outfile='/path/to/save/outfile')

   # To print formatting exit error.
   self.print_exiterr(exitcode, stderr)

   # To print executing commands error.
   self.print_oserr(cmd)
   ```

## Deprecated API and Settings

The following API and settings are deprecated and will be **removed** in the next versions:

_Custom modules API (only if you wrote your own modules):_

- `log = logging.getLogger(__name__)` (deprecated, in favor of `from ..core import log`)
- `self.is_valid_cmd(cmd)` (deprecated)
- `self.fix_cmd(cmd)` (deprecated)
- `self.print_oserr(cmd)` (deprecated, in favor of `self.print_oserr(cmd, e)`)

_Formatter.sublime-settings_ options:

- `"custom_modules":` (deprecated, in favor of `"custom_modules_manifest":`)
- `"format_on_unique":` (renamed, in favor of `"format_on_priority":`)
- `"recursive_folder_format"` (renamed, in favor of `"dir_format"`)
  - `"enable"` (deprecated, removed)
  - `"exclude_folders_regex"` (renamed, in favor of `"exclude_dirs_regex"`)
  - `"exclude_extensions"` (renamed, in favor of `"exclude_extensions_regex"`)
- `"disable":` (renamed, in favor of `"enable":`)

## License

[MIT](https://github.com/bitst0rm-pub/Formatter/blob/master/LICENSE)
