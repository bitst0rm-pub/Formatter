# Changelog

All notable changes to this project will be automatically documented in this file.

## [[1.6.5](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.6.5)] - 2024-09-13

### 🚜 Refactor

- [`dca16d9`](https://github.com/bitst0rm-pub/Formatter/commit/dca16d9c0d4c0df1b974c4789f2f6bfed9e84a2f) Refactor import statement

### ⚙️ Miscellaneous Tasks

- [`5250e6e`](https://github.com/bitst0rm-pub/Formatter/commit/5250e6ece40c2fae83f6f6e0d1db61c11bc5cebe) Remove redundant threading.Lock() on TextCommand
- [`2c9eb18`](https://github.com/bitst0rm-pub/Formatter/commit/2c9eb18020131b3fce20c96ac714c2d1b99577f7) Update to avoid using `__init__` in EventListener

## [[1.6.4](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.6.4)] - 2024-09-11

### ⚙️ Miscellaneous Tasks

- [`ff80024`](https://github.com/bitst0rm-pub/Formatter/commit/ff8002468f98296290ed66404c380d63e19d0c88) Implement bulk operation guard decorator for wcounter and smanager
- [`8dfdf62`](https://github.com/bitst0rm-pub/Formatter/commit/8dfdf62426d95c181b0188fa32b8452f84078738) Revise code

## [[1.6.3](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.6.3)] - 2024-09-08

### 🐛 Bug Fixes

- [`16b3ece`](https://github.com/bitst0rm-pub/Formatter/commit/16b3ecee70db25a788391a901510fe650fc2a026) Fix dir format to correctly handle excluded item types
- [`3c0a08c`](https://github.com/bitst0rm-pub/Formatter/commit/3c0a08c1a897ec7cb81d41291538e481c6d4a0f3) Resolve cursor jumping issue on save caused by `'ensure_newline_at_eof_on_save'` ST setting

### ⚙️ Miscellaneous Tasks

- [`f192f90`](https://github.com/bitst0rm-pub/Formatter/commit/f192f90a2a1770d06e7cb1fbb9ec5430a9a0ba28) Change to use `perf_counter()` instead of `time()` to measure time
- [`4b59d20`](https://github.com/bitst0rm-pub/Formatter/commit/4b59d208f48cffc1e016ca4f871786d2243c543f) Minor update
- [`c13bbd2`](https://github.com/bitst0rm-pub/Formatter/commit/c13bbd22347bc8951c6497b5b52fa3b1b977db56) Reorder of executable/interpreter detection

## [[1.6.2](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.6.2)] - 2024-09-04

### ⚙️ Miscellaneous Tasks

- [`1a50cc2`](https://github.com/bitst0rm-pub/Formatter/commit/1a50cc2304224d16577421df0e359c0b8ac3e16b) Cosmetic enhancements 🍒

## [[1.6.1](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.6.1)] - 2024-09-02

### 🐛 Bug Fixes

- [`08b372a`](https://github.com/bitst0rm-pub/Formatter/commit/08b372abbaa884c0d7625cbbe5b74070d1b11446) Minor fix temp_dir path

### 🚜 Refactor

- [`72cae5f`](https://github.com/bitst0rm-pub/Formatter/commit/72cae5fd0ab05cb15f28fc166c8bd20441883aab) Revise and enhance code for better performance and efficiency

## [[1.6.0](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.6.0)] - 2024-08-30

### 🐛 Bug Fixes

- [`8db25e6`](https://github.com/bitst0rm-pub/Formatter/commit/8db25e6bbb90f4399b2f73c1ba43e8b19dc38881) Various fixes for ST3

### ⚙️ Miscellaneous Tasks

- [`0cf7a18`](https://github.com/bitst0rm-pub/Formatter/commit/0cf7a18e1dadf9c5648273a9e47dd3c738bf5a96) Optimize InstanceManager
- [`eb30cb5`](https://github.com/bitst0rm-pub/Formatter/commit/eb30cb5a5fd6b41e9d472a45e1873ec795bb5442) Optimize with singleton decorator to reuse instances
- [`037b40c`](https://github.com/bitst0rm-pub/Formatter/commit/037b40c62ac4f54dac51e0ba2472c65adf37af5e) Remove `InstanceManager` in favor of `ClassManager` and Singleton design pattern

## [[1.5.22](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.22)] - 2024-08-27

### 🚜 Refactor

- [`a28237e`](https://github.com/bitst0rm-pub/Formatter/commit/a28237e50fd8957a8e2972ebb9048cc9082f5974) Refactor word counter to limit to max. 1.000.000 chars

### ⚙️ Miscellaneous Tasks

- [`8565f9f`](https://github.com/bitst0rm-pub/Formatter/commit/8565f9f0d89e8e7459298b323735aac011355de2) Increase word counter max. chars to `6.000.000` chars ≈ 1.000.000 words (6MB)
- [`e7f5e2c`](https://github.com/bitst0rm-pub/Formatter/commit/e7f5e2c2c222589e3506b74d2489bc065f761043) Optimize code

## [[1.5.21](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.21)] - 2024-08-24

### 🚀 Features

- [`4235a72`](https://github.com/bitst0rm-pub/Formatter/commit/4235a7288be4e086575767dd49b5bbaa72f50baf) Add settings option `"file_chars_limit"`

### ⚡ Performance

- [`3ca630a`](https://github.com/bitst0rm-pub/Formatter/commit/3ca630aaf7ba9d60bf6b0b0841056218cd2d7033) Optimize words counter

## [[1.5.20](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.20)] - 2024-08-22

### 🐛 Bug Fixes

- [`2340ede`](https://github.com/bitst0rm-pub/Formatter/commit/2340edef9c7d1fda13b68d56e3541b7c2597be89) Fix the broken changelog as unescaped HTML characters were mistakenly interpreted as HTML tags

### ⚙️ Miscellaneous Tasks

- [`6d547a6`](https://github.com/bitst0rm-pub/Formatter/commit/6d547a68d57591e7749cd427a03db54604db3f0d) Add `ModuleMeta` metaclass for module-specific configuration enforcement
- [`123a61d`](https://github.com/bitst0rm-pub/Formatter/commit/123a61d866d073c82b5ef002abd04523f9dedad1) Change vars to lower case

## [[1.5.19](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.19)] - 2024-08-21

### ⚙️ Miscellaneous Tasks

- [`b86663f`](https://github.com/bitst0rm-pub/Formatter/commit/b86663f13895f07c723282f178a634d95babbdd4) Add more styles to the activity indicator
- [`35a087d`](https://github.com/bitst0rm-pub/Formatter/commit/35a087d5b15810e0dce72f0248dd874fc4f7172c) Remove potential carriage return character `<0x0d>` in subprocess stderr on Windows (ref [#54](https://github.com/bitst0rm-pub/Formatter/issues/54))
- [`fb566af`](https://github.com/bitst0rm-pub/Formatter/commit/fb566af282dcd28981c99e0f1f60c2e01643310b) Use signal to kill subprocess

## [[1.5.18](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.18)] - 2024-08-16

### ⚙️ Miscellaneous Tasks

- [`93a18de`](https://github.com/bitst0rm-pub/Formatter/commit/93a18de9e8afad1ed6d8c88510f210c3d759bce0) Improve text file detection
- [`c7ba061`](https://github.com/bitst0rm-pub/Formatter/commit/c7ba0618ab8c7af6c4a02972b3ccf448d2b1f307) Show progress indicator if formatting takes longer than 1s
- [`1bb48e3`](https://github.com/bitst0rm-pub/Formatter/commit/1bb48e35de6b662449daf447026ed47e1f5397b3) Temporarily disable smanager and wcounter while performing dir formatting
- [`132c874`](https://github.com/bitst0rm-pub/Formatter/commit/132c87443a2eb01c8e7a947ea4ccb0bfbcb639db) Isort imports

## [[1.5.17](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.17)] - 2024-08-11

### 🚀 Features

- [`913f15a`](https://github.com/bitst0rm-pub/Formatter/commit/913f15a204243d81724c94d68f6fd386a5132527) Add settings option `"clear_console"` to clear all previous console messages, for ST4088+ only

### 🐛 Bug Fixes

- [`f307122`](https://github.com/bitst0rm-pub/Formatter/commit/f307122c99eaeaba56418d0e6d76cd77fedbdec2) Fix issue where dot files config for auto-formatting is not being respected

### ⚙️ Miscellaneous Tasks

- [`f0f7233`](https://github.com/bitst0rm-pub/Formatter/commit/f0f7233c0b8b6658a24b38730de27f499c2ab3ca) Return the auto format config as soon as the first dot file is found

## [[1.5.16](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.16)] - 2024-08-09

### ⚙️ Miscellaneous Tasks

- [`4e3708a`](https://github.com/bitst0rm-pub/Formatter/commit/4e3708a8bd648468e2331a30e2b03934febf25f1) Suspend formatting status when there is no operation

## [[1.5.15](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.15)] - 2024-08-09

### 🚀 Features

- [`d2f26c0`](https://github.com/bitst0rm-pub/Formatter/commit/d2f26c04dd952f10f21d7bb42b6b16cea4941acc) Add `"exclude_syntaxes": []` to `"format_on_save"` and `"format_on_paste"` to use regular
- [`3992334`](https://github.com/bitst0rm-pub/Formatter/commit/3992334f1eef068fbf0e57f7272a2637c734e5ae) Add `"exclude_syntaxes": []` to `"format_on_save"` and `"format_on_paste"` to use with `Auto Format File`

### ⚙️ Miscellaneous Tasks

- [`297e913`](https://github.com/bitst0rm-pub/Formatter/commit/297e913765734aa7b2344c5c35c37e21242eb15f) Update README.md
- [`e17b170`](https://github.com/bitst0rm-pub/Formatter/commit/e17b170594539cbc3b9af68c411c34bf1ac005bd) Auto_format setting items can now be a type string `"auto_format": {{"json": "jsbeautifier"}}` or a dictionary `"auto_format": {{"json": {"uid": "jsbeautifier"}}}`

## [[1.5.14](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.14)] - 2024-08-07

### 🚀 Features

- [`9f9cbc1`](https://github.com/bitst0rm-pub/Formatter/commit/9f9cbc18386a98c63882fc7efa8db5081dadc0d1) Change settings option name from `"recursive_folder_format"` to `"dir_format"`; `"dir_format"` can now exclude specific dirs, files, extensions and syntaxes using: `"exclude_dirs_regex"`, `"exclude_files_regex"`, `"exclude_extensions_regex"`, `"exclude_syntaxes"` in config
- [`d0a0117`](https://github.com/bitst0rm-pub/Formatter/commit/d0a0117509563ffb8171f587804dbc1e888613c3) `"format_on_save"`, `"format_on_paste"` and `auto format file` can now exclude specific dirs, files and extensions using: `"exclude_dirs_regex"`, `"exclude_files_regex"`, `"exclude_extensions_regex"` in config

### 🐛 Bug Fixes

- [`e3c2daf`](https://github.com/bitst0rm-pub/Formatter/commit/e3c2daf961e0c56d636738d675ce5b3d7af3cffc) *(prettier)* Fix OSError: [WinError 193] %1 is not a valid Win32 application. On Windows, shortcuts (symbolic links) are not considered application by subprocess (closes [#62](https://github.com/bitst0rm-pub/Formatter/issues/62))

### ⚙️ Miscellaneous Tasks

- [`4e3d27f`](https://github.com/bitst0rm-pub/Formatter/commit/4e3d27f90f7fabf698ec90338f9ea1896cc1351b) *(prettier)* Add `'prettier.cmd'` to `EXECUTABLES` list
- [`7d2f09f`](https://github.com/bitst0rm-pub/Formatter/commit/7d2f09fc4f54a00fd329466392e76dcf71b4b559) Add line break to `print_oserr()`
- [`67afd6f`](https://github.com/bitst0rm-pub/Formatter/commit/67afd6f55462a0fb92e497074f62e2163176aac0) Improve `print_oserr()` with more details (ref [#62](https://github.com/bitst0rm-pub/Formatter/issues/62))

## [[1.5.13](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.13)] - 2024-08-04

### ⚙️ Miscellaneous Tasks

- [`876b5c5`](https://github.com/bitst0rm-pub/Formatter/commit/876b5c5e79667ec9125192c2f251a63b630fb8fe) Add markdownlint
- [`99deeec`](https://github.com/bitst0rm-pub/Formatter/commit/99deeec506265012e3642e2a5426cc4386b031d2) Polish sublime-settings file
- [`91a78d2`](https://github.com/bitst0rm-pub/Formatter/commit/91a78d25bc8dfd5396c62d6b59a4a99612093664) Update README.md
- [`6c8bce6`](https://github.com/bitst0rm-pub/Formatter/commit/6c8bce6b897189520ac316b668ce6300c711e386) Update ci

## [[1.5.12](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.12)] - 2024-08-03

### 🚀 Features

- [`7b4e813`](https://github.com/bitst0rm-pub/Formatter/commit/7b4e8135a27a84c721c35def6eea4dd7234c2650) Add the ability to stop the `"recursive_folder_format"` process by pressing any arrow key (up, down, left, or right) on your keyboard

### 📚 Documentation

- [`357d1cc`](https://github.com/bitst0rm-pub/Formatter/commit/357d1cc30a933135d44c4f2a34730f474f76a56d) Update README.md

### ⚙️ Miscellaneous Tasks

- [`53d2841`](https://github.com/bitst0rm-pub/Formatter/commit/53d2841c029630ea18b6047dc3915f92540866fb) Remove all threading-related logic to dir formatting
- [`59b3e39`](https://github.com/bitst0rm-pub/Formatter/commit/59b3e399a7b243e070ff9fd3c41c5908f52676af) Rename file and dir formatting classes
- [`91d4796`](https://github.com/bitst0rm-pub/Formatter/commit/91d47969722d44d0a53acabbf755b98ca73c0f37) Shorten some debug messages

## [[1.5.11](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.11)] - 2024-08-01

### 🐛 Bug Fixes

- [`5cb019a`](https://github.com/bitst0rm-pub/Formatter/commit/5cb019aa6495807c9e637fdc5450e9aa5d9fae77) Cmd item can be empty string

### 🚜 Refactor

- [`5f7b75a`](https://github.com/bitst0rm-pub/Formatter/commit/5f7b75a3a1ecad181ced8c9e414ef11f834f3c03) Restructuring `FormatterListener()`
- [`f626aaa`](https://github.com/bitst0rm-pub/Formatter/commit/f626aaa5f5abccd3d525d8dd72a2516abf63f1a4) Restructuring main.py

### ⚙️ Miscellaneous Tasks

- [`50f29b5`](https://github.com/bitst0rm-pub/Formatter/commit/50f29b52d9c36447485dca8b847620484adb3229) Add `collapse_setting_sections_command` for `Formatter.sublime-settings`
- [`3b811b2`](https://github.com/bitst0rm-pub/Formatter/commit/3b811b2ced4bae34dae794ebeca765b42b8d4156) Ensure sync scroll listener is terminated
- [`1506b1d`](https://github.com/bitst0rm-pub/Formatter/commit/1506b1df9ce4a91ce60731af2fc671ec9c4ca130) Improve deprecated option warning messages
- [`991cac0`](https://github.com/bitst0rm-pub/Formatter/commit/991cac0def8d58fcd9dcaf32a8832d6fc07a6b20) Refactor code to conform to flake8 standards
- [`923a7a7`](https://github.com/bitst0rm-pub/Formatter/commit/923a7a7aa35fabafbd8682f701eb9adb36d86146) Update
- [`db4efd0`](https://github.com/bitst0rm-pub/Formatter/commit/db4efd030ce916b6631ae7e9e1417acf67d22e88) Update GitHub workflows

## [[1.5.10](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.10)] - 2024-07-29

### 🐛 Bug Fixes

- [`3b8da99`](https://github.com/bitst0rm-pub/Formatter/commit/3b8da9950fc69f493e36ca8cd2f5f161466feafa) Exclude dirs starting with '.' or '_', such as '__MACOSX', which might contain incorrect custom module files when creating ZIP archives

## [[1.5.9](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.9)] - 2024-07-29

### 🐛 Bug Fixes

- [`fb2004f`](https://github.com/bitst0rm-pub/Formatter/commit/fb2004f0e97adde7d93cf04dc5b29341f459819d) Replace `subprocess.run()` with `subprocess.Popen()`to work with py33

### ⚙️ Miscellaneous Tasks

- [`90bf5ba`](https://github.com/bitst0rm-pub/Formatter/commit/90bf5ba963001ab516b62d039289b2528b594967) Typo

## [[1.5.8](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.8)] - 2024-07-28

### 🚀 Features

- [`63dbd99`](https://github.com/bitst0rm-pub/Formatter/commit/63dbd99fa7fdef78d626f6615186100c575afb8c) Add signature verification for remote custom modules archive files

### ⚙️ Miscellaneous Tasks

- [`385a924`](https://github.com/bitst0rm-pub/Formatter/commit/385a924a9a4ece1dcaa1ff957f84dce63c2182ba) Add `"ca_cert":` option to the custom modules manifest to use the optional CA Certificate
- [`7685080`](https://github.com/bitst0rm-pub/Formatter/commit/76850809e25197a274228e1fe887b434a23430f4) Add `check_deprecated_options()` decorator to warn user about using obsolete settings options
- [`e14eb80`](https://github.com/bitst0rm-pub/Formatter/commit/e14eb80402f692806baf7112681513eff3a56fe4) Improve downloads folder detection

## [[1.5.7](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.7)] - 2024-07-27

### ⚙️ Miscellaneous Tasks

- [`7a160a5`](https://github.com/bitst0rm-pub/Formatter/commit/7a160a5563ec5e56b4d4e7040efc57c6bebe6aff) Add `deprecated()` decorator to auto deactivate methods on time
- [`0bef7c4`](https://github.com/bitst0rm-pub/Formatter/commit/0bef7c4605fc6ec29339d5c90724c287358477bf) Add delay flag to `retry_on_exception()` decorator
- [`fdf772d`](https://github.com/bitst0rm-pub/Formatter/commit/fdf772d2844de36a0b15b3baa04474feb834dce0) Convert some instance methods to class methods
- [`36b1543`](https://github.com/bitst0rm-pub/Formatter/commit/36b15432b0a442d91bd1bd010a16d61d72e32672) Deprecated `fix_cmd()` in favor of `transform_args()` decorator
- [`c9a372a`](https://github.com/bitst0rm-pub/Formatter/commit/c9a372a26e1372e89f91e48b826b3b2fcfa02294) Deprecated `is_valid_cmd()` in favor of `validate_args()` decorator
- [`a572a67`](https://github.com/bitst0rm-pub/Formatter/commit/a572a67504849908b4ae0ac4e03a2e142ee11496) Improve `retry_on_exception()` logic to avoid circular calls on `cls.build_config(settings)`
- [`eeb40d7`](https://github.com/bitst0rm-pub/Formatter/commit/eeb40d7557c61db24cd4b1478676553ff5db0870) Replace `build_config()` exception with `retry_on_exception()` decorator
- [`700c49d`](https://github.com/bitst0rm-pub/Formatter/commit/700c49df65818b512da688a590d2f14f20a3edea) Typo
- [`b6b34ad`](https://github.com/bitst0rm-pub/Formatter/commit/b6b34ad1bad8e6998388543537426f98947b3745) Update README.md

## [[1.5.6](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.6)] - 2024-07-25

### 🐛 Bug Fixes

- [`247a606`](https://github.com/bitst0rm-pub/Formatter/commit/247a606aec9728e22a8fcdfabb88ee30cc01320c) Fix getLogger arg
- [`3d2a29d`](https://github.com/bitst0rm-pub/Formatter/commit/3d2a29d51177bc4f2d052a45df7a9c4e23cd3813) Fix multi project configurations not reloading (closes [#60](https://github.com/bitst0rm-pub/Formatter/issues/60), closes [#61](https://github.com/bitst0rm-pub/Formatter/issues/61)) Thanks [@husanjun](https://github.com/husanjun)

## [[1.5.5](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.5)] - 2024-07-23

### 🐛 Bug Fixes

- [`121550c`](https://github.com/bitst0rm-pub/Formatter/commit/121550c3a1f80457c305bade84671b8d0feeb6e1) Update config to use multi per-projects opening at once (closes [#60](https://github.com/bitst0rm-pub/Formatter/issues/60)) Thanks [@husanjun](https://github.com/husanjun)

### ⚙️ Miscellaneous Tasks

- [`83e155a`](https://github.com/bitst0rm-pub/Formatter/commit/83e155a07fcd66a6cdcdc3319a297f39d2084a83) Add shortcut command for setting options (closes [#59](https://github.com/bitst0rm-pub/Formatter/issues/59)) Credit & Thanks [@husanjun](https://github.com/husanjun)

## [[1.5.4](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.4)] - 2024-07-22

### 🐛 Bug Fixes

- [`15abbcd`](https://github.com/bitst0rm-pub/Formatter/commit/15abbcd53857ca8c8c2728174c0dbdfcb74b5add) Add the missing colon
- [`cab37fc`](https://github.com/bitst0rm-pub/Formatter/commit/cab37fc8d5083424e49eab954974d559955ad4e5) Create temp file in the temp file system instead of cwd (closes [#58](https://github.com/bitst0rm-pub/Formatter/issues/58)) Thanks [@husanjun](https://github.com/husanjun)
- [`042df96`](https://github.com/bitst0rm-pub/Formatter/commit/042df96675f7c6f0cc444d9497f56b85b40215dc) Fix obsolete import from common

### ⚙️ Miscellaneous Tasks

- [`694094a`](https://github.com/bitst0rm-pub/Formatter/commit/694094a4782367b80d45e44371d26b867cca0ad6) Auto remove `.custom` if fetching custom modules data fails
- [`af16b8a`](https://github.com/bitst0rm-pub/Formatter/commit/af16b8a3dc8c7a4bbc62f26e4e8d6dd4281bd7a5) Improve subprocess termination

## [[1.5.3](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.3)] - 2024-07-21

### 🚀 Features

- [`1f2ae01`](https://github.com/bitst0rm-pub/Formatter/commit/1f2ae01126748a8e5b774d8ec99f83500243b400) Add a new setting option: `"close_console_on_success":`

### 🐛 Bug Fixes

- [`4a4e347`](https://github.com/bitst0rm-pub/Formatter/commit/4a4e347f093638ee06a9a1f8a51a75fda20d2ec1) Fix modules reload for developer mode
- [`21bdf5f`](https://github.com/bitst0rm-pub/Formatter/commit/21bdf5f88cf8013cc59669d237036eec05f61c8e) Move `InstanceManager.reset_all()` to formatter.py

## [[1.5.2](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.2)] - 2024-07-19

### 🚀 Features

- [`745221e`](https://github.com/bitst0rm-pub/Formatter/commit/745221e7af22a7bdad5379b5f3648155314719cc) Deprecating the `"custom_modules":` option in favor of `"custom_modules_manifest":` Custom modules can now be used both locally and remotely

### 🐛 Bug Fixes

- [`daec479`](https://github.com/bitst0rm-pub/Formatter/commit/daec479fd36a84bd1e2cd7c06d518e8935b66568) Add `'[@noop](https://github.com/noop)@'` uid for auto-format when no syntax is detected
- [`b63d852`](https://github.com/bitst0rm-pub/Formatter/commit/b63d852749d2db19aceb95c06b2c4a1a63d64429) Add missing `self`, which caused auto_format_config to be undefined (ref: https://github.com/bitst0rm-pub/Formatter/issues/57) Thanks [@the-ge](https://github.com/the-ge)
- [`1ec2de5`](https://github.com/bitst0rm-pub/Formatter/commit/1ec2de5afa84acfbc2596b64d066d4ee9f2af6b3) Fix `create_tmp_file()` suffix for syntax of None`

## [[1.5.1](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.1)] - 2024-07-16

### 🐛 Bug Fixes

- [`cb3b5b5`](https://github.com/bitst0rm-pub/Formatter/commit/cb3b5b5f56de5237538c6134fb2ea23540241c99) Fix reloading and importing custom modules

### ⚙️ Miscellaneous Tasks

- [`5d9d69e`](https://github.com/bitst0rm-pub/Formatter/commit/5d9d69e743460bc5f61cfedc1225080b4b0feff0) Optimize `get_pathinfo()`
- [`7cb0a43`](https://github.com/bitst0rm-pub/Formatter/commit/7cb0a43cd02a0d68061d2d65fdd56f1dcc1aa1ef) Remove redundant import
- [`220503e`](https://github.com/bitst0rm-pub/Formatter/commit/220503e0b14c08c9edc70c5e8979d035e1fd28c8) Typo

## [[1.5.0](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.5.0)] - 2024-07-14

### 🚜 Refactor

- [`974da9b`](https://github.com/bitst0rm-pub/Formatter/commit/974da9b1936b473324c6d56b8b302883b9441bf2) Complete restructuring and improvement of Formatter codebase
- [`ef2a9bb`](https://github.com/bitst0rm-pub/Formatter/commit/ef2a9bb1910322e7e02dae1f1e246075b420bbed) Restructuring constants
- [`0121c8a`](https://github.com/bitst0rm-pub/Formatter/commit/0121c8a153f3e46f6cc8934977da0f22595d9ce1) Restructuring logger

## [[1.4.17](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.17)] - 2024-07-07

### 🐛 Bug Fixes

- [`1c6009e`](https://github.com/bitst0rm-pub/Formatter/commit/1c6009eb47a2f435e19c08d690235b8ac8f59443) *(smanager)* Fix the issue where the `animate` argument was unavailable for `show_at_center()` in ST3

### 🚜 Refactor

- [`c3e31ad`](https://github.com/bitst0rm-pub/Formatter/commit/c3e31ada9d938aa272b8ee11ced4ebc231b049ea) Relative import for logging. It may break your code, simply change it to: `from .. import log` and remove `log = logging.getLogger(__name__)`

### 📚 Documentation

- [`0c42aaf`](https://github.com/bitst0rm-pub/Formatter/commit/0c42aaf67ebca1c2e44e31a51ddabfcdc2a64bda) Add more screenshots

### 🎨 Styling

- [`84b0010`](https://github.com/bitst0rm-pub/Formatter/commit/84b0010a8c441311c1a613562148afffa7c645f0) Change log marker symbol from ▋to ▍

### ⚙️ Miscellaneous Tasks

- [`b9ebfc3`](https://github.com/bitst0rm-pub/Formatter/commit/b9ebfc38f4d68bb20c62604c33a10fb7b7d36416) Clear console for ST4088+
- [`3b8a6a8`](https://github.com/bitst0rm-pub/Formatter/commit/3b8a6a8ac4b653e7f451a5da5509af1485aff84b) Disable `remove_junk()` as some 💩 no longer affect `.git`
- [`f4d4c90`](https://github.com/bitst0rm-pub/Formatter/commit/f4d4c90a8f125799bec1823091877241cf4a3775) Move check for `print_sysinfo()` to common
- [`46f84b3`](https://github.com/bitst0rm-pub/Formatter/commit/46f84b3ecf1ab4be2cde115a1d0166ec27fafe01) Optimize importing modules

## [[1.4.16](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.16)] - 2024-06-28

### 🚀 Features

- [`8422a57`](https://github.com/bitst0rm-pub/Formatter/commit/8422a5710fc5df3a0658bbd239d3038e5835c520) Add `"print_on_console"` sub option to `"environ"` to help setting environment

### ⚙️ Miscellaneous Tasks

- [`54c039f`](https://github.com/bitst0rm-pub/Formatter/commit/54c039f8b49bdbd8c43b236b8726308d629df926) *(changelog)* Convert GitHub issues/pull urls to short links
- [`e046af5`](https://github.com/bitst0rm-pub/Formatter/commit/e046af55aa1ce36d7ef2d22cabb2cef1c2f4b159) *(console)* Minor update
- [`18c94d6`](https://github.com/bitst0rm-pub/Formatter/commit/18c94d6041e6e1ad7f3db5b540488b6f5a21a985) Update cliff.toml to autolink to issue numbers and person mentioning
- [`7414315`](https://github.com/bitst0rm-pub/Formatter/commit/74143158a45f8180992f22301f58a002587bda44) *(uncrustify)* Update config files to use with 0.79.0
- [`cf7d147`](https://github.com/bitst0rm-pub/Formatter/commit/cf7d1474292cc33c1a3ea7643c2214e0b93e38b9) *(clang-format)* Update config files to use with 18.1.8

## [[1.4.15](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.15)] - 2024-06-19

### 🐛 Bug Fixes

- [`60cdc50`](https://github.com/bitst0rm-pub/Formatter/commit/60cdc5045ba8eeb62cd7f527058c66fb93152139) *(efmt)* Remove rebar3-flavored efmt as upstream is not supported (ref [#55](https://github.com/bitst0rm-pub/Formatter/issues/55)) Thanks [@verbit](https://github.com/verbit)

### ⚙️ Miscellaneous Tasks

- [`0abead9`](https://github.com/bitst0rm-pub/Formatter/commit/0abead98556101aa79335f3dc1e2d2faf8df4046) *(console)* Add more rules to match error signs

## [[1.4.14](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.14)] - 2024-06-18

### 🚀 Features

- [`7400461`](https://github.com/bitst0rm-pub/Formatter/commit/74004616750999633888f54c6acfc9f6593def62) Add a new option `"use_short_label"` to `"show_words_count"`

### 🎨 Styling

- [`b2af96c`](https://github.com/bitst0rm-pub/Formatter/commit/b2af96ccfe9ec05c7eca66492612a59569ecac06) *(console)* Add rules to match path on Windows and the caret error hint symbol

### ⚙️ Miscellaneous Tasks

- [`7ef6149`](https://github.com/bitst0rm-pub/Formatter/commit/7ef6149fb67ae78fd3822218152ef8ba9b2b4f16) *(doc)* Update

## [[1.4.13](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.13)] - 2024-06-17

### 🚀 Features

- [`2d0e202`](https://github.com/bitst0rm-pub/Formatter/commit/2d0e202f06d23172dc1e39a2c7933dd6ab2eec6b) Add `Changelog` command to References and Command Palette
- [`fe73788`](https://github.com/bitst0rm-pub/Formatter/commit/fe73788fce44b9aca0928d6878e85960ee219de3) Add console color highlighting

### 🐛 Bug Fixes

- [`936ce36`](https://github.com/bitst0rm-pub/Formatter/commit/936ce36015d68dc8c273d455c34d284a762c0f56) *(eslint)* Add missing cmd check
- [`d4cd316`](https://github.com/bitst0rm-pub/Formatter/commit/d4cd3168e9ba3bc3e9617091a329ce138538a7b1) Console syntax for Target

### 📚 Documentation

- [`0aca59a`](https://github.com/bitst0rm-pub/Formatter/commit/0aca59ace739fee9e27d135ccb8c2283b8623352) Add note to cloning to README.md

### 🎨 Styling

- [`59a0e8d`](https://github.com/bitst0rm-pub/Formatter/commit/59a0e8daedf8c1f16e555f2e8d8e0604ceb116c6) *(graphic)* Change phantom LAYOUT_BLOCK to LAYOUT_INLINE
- [`a072211`](https://github.com/bitst0rm-pub/Formatter/commit/a072211b2f7ece2bab269c5e0c6895f4609dee4e) Shorten package name from `Formatter` to `F` on status bar

### ⚙️ Miscellaneous Tasks

- [`7c57023`](https://github.com/bitst0rm-pub/Formatter/commit/7c5702367c3fd7320cf6943271e127ce81d25fbf) *(git)* Add SYNTAXES field to modules summary
- [`f8e431c`](https://github.com/bitst0rm-pub/Formatter/commit/f8e431c2a193687cabdf6e861feba4b2cd2a154e) Change menu item name from `Open Config Folders` to `Browser Configs`
- [`0e6bbf4`](https://github.com/bitst0rm-pub/Formatter/commit/0e6bbf4a9298412f2fe1786c7d346d5ebec80d6c) Minor enhancements

## [[1.4.12](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.12)] - 2024-06-14

### 📚 Documentation

- [`82c2e53`](https://github.com/bitst0rm-pub/Formatter/commit/82c2e53d7d244384a20f71ea3047ed098bbfa38c) *(eslintd)* Add note to limitations

### ⚙️ Miscellaneous Tasks

- [`86f1fb5`](https://github.com/bitst0rm-pub/Formatter/commit/86f1fb54bf82fbf1ffaa10ea157ed941c7e91f20) Add `Read Modules Summary` command to help setting Formatter
- [`6693059`](https://github.com/bitst0rm-pub/Formatter/commit/6693059901d21aa95f430531df7b8a1b0270bd9e) Change option name from `"format_on_unique"` to `"format_on_priority"`
- [`6870fbb`](https://github.com/bitst0rm-pub/Formatter/commit/6870fbbd00a7d2c860e35c314f5b638131cbb0f9) *(git)* Generate modules summary text file
- [`6b89e57`](https://github.com/bitst0rm-pub/Formatter/commit/6b89e57ed4d122cfa3cb35f536bb98ff32cb0b2c) Move version.py to the root
- [`4c6a6d9`](https://github.com/bitst0rm-pub/Formatter/commit/4c6a6d9323c2bc706ccd1b34930dd02a6d34af30) Remove langref
- [`1829047`](https://github.com/bitst0rm-pub/Formatter/commit/1829047790aff131b59e4dff7eb5a05ef9004aba) Update cliff.toml to include commit links

## [[1.4.11](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.11)] - 2024-06-13

### 🚀 Features

- [`46f539e`](https://github.com/bitst0rm-pub/Formatter/commit/46f539e1e415fa5ba16a843b7fb8b7d74f4d4548) Add a new cmd API to get interpreter and executable: get_iprexe_cmd(runtimetype=None)

### 🐛 Bug Fixes

- [`6da59e4`](https://github.com/bitst0rm-pub/Formatter/commit/6da59e437efb839007e4c6fba86015e85120b0bb) *(eslintd)* Disable support for Eslint v8.57.0+ using flat config files. [@see](https://github.com/see): https://github.com/mantoni/eslint_d.js/issues/281
- [`0e9390e`](https://github.com/bitst0rm-pub/Formatter/commit/0e9390eefdc731c3b613460e5adb37bcacf76eba) *(eslint)* Improve version detection
- [`19a4e21`](https://github.com/bitst0rm-pub/Formatter/commit/19a4e2125d220794a170f24b2d89b091f70443d1) Stop searching for the per-project config dotfile *after* a .git or .hg directory is found
- [`e4997cb`](https://github.com/bitst0rm-pub/Formatter/commit/e4997cbcd5cc92a8dab7553f9fc183928c3803d0) *(eslint)* Update compatibility with both ESLint v8- and v9+ (using flat config file)
- [`097f6cd`](https://github.com/bitst0rm-pub/Formatter/commit/097f6cdc882a071fe7323cd652db524bf941d9b3) *(eslint)* Update version detection to v8.57.0 for supporting flat config files: eslint.config.(js|mjs|cjs)

## [[1.4.10](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.10)] - 2024-06-12

### 🚀 Features

- [`cb06723`](https://github.com/bitst0rm-pub/Formatter/commit/cb0672308ed24fccb5c7ae4d98f2ab3c58e37841) Introduce Auto-resolve per-project config dotfile when "config_path" is disabled.

### 🐛 Bug Fixes

- [`36b379f`](https://github.com/bitst0rm-pub/Formatter/commit/36b379f75e3b62832e151b05f0c1bd9d91141098) *(juliaformatter)* Add config DOTFILES
- [`ece056b`](https://github.com/bitst0rm-pub/Formatter/commit/ece056bd65df2747a66986bd0847d77951e1a2d1) *(plugins)* Add config DOTFILES constant
- [`9e2f45d`](https://github.com/bitst0rm-pub/Formatter/commit/9e2f45d48fb82834f679d928aa44ea4c13eb76cc) *(juliaformatter)* Add style option
- [`990f4c1`](https://github.com/bitst0rm-pub/Formatter/commit/990f4c1c9a1de0ae3df652324dda9965f5ec0c2f) Minor typo
- [`0debb25`](https://github.com/bitst0rm-pub/Formatter/commit/0debb25d9824c1275b30c6d968af3d73e14f8f21) *(juliaformatter)* Remove redundant DOTFILES constant
- [`de47793`](https://github.com/bitst0rm-pub/Formatter/commit/de47793ccde5aa0967e16877a85d79ae46217c54) Stop searching for the per-project config dotfile as reaching to .git or .hg dir
- [`63c85c7`](https://github.com/bitst0rm-pub/Formatter/commit/63c85c707f71c8233cfd59af3d7cea542a1ed357) Update black homepage url

## [[1.4.9](https://github.com/bitst0rm-pub/Formatter/releases/tag/1.4.9)] - 2024-06-11

### 🚀 Features

- [`db6986b`](https://github.com/bitst0rm-pub/Formatter/commit/db6986b752d28965b472645b1df1483337917e42) *(plugin)* Add JuliaFormatter

### 🐛 Bug Fixes

- [`d05fe01`](https://github.com/bitst0rm-pub/Formatter/commit/d05fe01dc63a1fb9f167c8c41ea9b16562ada743) Typo

### ⚙️ Miscellaneous Tasks

- [`403176c`](https://github.com/bitst0rm-pub/Formatter/commit/403176c5600e4c94a2e4710461061a3cc60c6cc3) Add cliff.toml to generate changelog

<!-- generated by git-cliff -->
