import sys

try:  # python 3.8+
    from importlib import reload
except ImportError:  # python 3.3
    from imp import reload

from . import PACKAGE_NAME, log


def reload_modules(print_tree=False):
    reloaded_modules = []
    prefix = PACKAGE_NAME + '.'
    for module_name, module in tuple(filter(lambda item: item[0].startswith(prefix) and item[0] != __name__, sys.modules.items())):
        try:
            reload(module)
            if print_tree:
                reloaded_modules.append(module_name)
        except Exception as e:
            log.error('Error reloading module %s: %s', module_name, str(e))
            return None

    from ..main import entry
    entry()

    log.debug('Reloaded modules (Python %s)', '.'.join(map(str, sys.version_info[:3])))
    if print_tree:
        _generate_ascii_tree(reloaded_modules, PACKAGE_NAME)


def _generate_ascii_tree(reloaded_modules, package_name):
    tree = {}

    for module in reloaded_modules:
        parts = module.split('.')
        current_node = tree
        for part in parts:
            current_node = current_node.setdefault(part, {})

    def print_tree(node, prefix):
        sorted_keys = sorted(node.keys())
        for i, key in enumerate(sorted_keys):
            is_last = i == len(sorted_keys) - 1
            print(prefix + ('└── ' if is_last else '├── ') + key)
            print_tree(node[key], prefix + ('    ' if is_last else '│   '))

    print(package_name)
    print_tree(tree[package_name], '')
