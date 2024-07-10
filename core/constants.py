from datetime import datetime
import sublime

IS_WINDOWS = sublime.platform() == 'windows'
PACKAGE_NAME = __package__.partition('.')[0]
ASSETS_DIRECTORY = 'formatter.assets'
QUICK_OPTIONS_SETTING_FILE = 'Formatter.quick-options'
RECURSIVE_SUCCESS_DIRECTORY = '__format_success__'
RECURSIVE_FAILURE_DIRECTORY = '__format_failure__'
STATUS_KEY = '86cfb48b-8010-48f2-b0de-1a9f8daacb85'
GFX_OUT_NAME = 'out_%s' % datetime.now().strftime('%Y%m%d')
LAYOUTS = {
    'single': {
        'cols': [0.0, 1.0],
        'rows': [0.0, 1.0],
        'cells': [[0, 0, 1, 1]]
    },
    '2cols': {
        'cols': [0.0, 0.5, 1.0],
        'rows': [0.0, 1.0],
        'cells': [[0, 0, 1, 1], [1, 0, 2, 1]]
    },
    '2rows': {
        'cols': [0.0, 1.0],
        'rows': [0.0, 0.5, 1.0],
        'cells': [[0, 0, 1, 1], [0, 1, 1, 2]]
    }
}
