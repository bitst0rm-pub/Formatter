from sys import version_info

import sublime

from .plugin import *  # noqa: F403


def entry():
    import_custom_modules()
    # CleanupHandler.remove_junk()
    ready = create_package_config_files()
    if ready:
        ConfigHandler.load_sublime_preferences()
        ConfigHandler.setup_config()
        ConfigHandler.setup_shared_config_files()
        ConfigHandler.set_debug_mode()

    log.info('%s version: %s (Python %s)', PACKAGE_NAME, __version__, '.'.join(map(str, version_info[:3])))
    log.debug('Plugin initialization ' + ('succeeded.' if ready else 'failed.'))


def plugin_loaded():
    ConfigHandler.setup_config()

    def call_entry():
        sublime.set_timeout_async(lambda: entry(), 100)

    try:
        from package_control import events
        if events.install(PACKAGE_NAME) or events.post_upgrade(PACKAGE_NAME):
            call_entry()
        else:
            call_entry()
    except ImportError:
        call_entry()
