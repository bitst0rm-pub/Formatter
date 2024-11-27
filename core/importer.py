import os
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from urllib.parse import urlparse

try:  # python 3.8+
    import importlib
except ImportError:  # python 3.3
    import imp

import sublime

from . import CONFIG, PACKAGE_NAME, HashHandler, log

EXPECTED_DIRS = ['config', 'libs', 'modules']
EXCLUDE_DIRS = ['dateutil', 'prettytable', 'sqlmin', 'stone', 'toml', 'wcswidth', 'yaml']
FETCH_TIMEOUT = 3
DOWNLOAD_TIMEOUT = 10  # sec


def import_custom_modules():
    custom_modules = CONFIG.get('custom_modules', None)  # @deprecated
    custom_modules_manifest = CONFIG.get('custom_modules_manifest', None)

    if custom_modules and isinstance(custom_modules, dict):
        import_model_v1(custom_modules)  # @deprecated
    elif custom_modules_manifest and isinstance(custom_modules_manifest, str):
        import_model_v2(custom_modules_manifest)


def import_model_v2(custom_modules_manifest):
    data = read_json(custom_modules_manifest)
    if not data:
        return

    version = data.get('version', None)
    ca_cert = data.get('ca_cert', None)
    public_key = data.get('public_key', None)
    gpg = data.get('gpg', None)
    dot_path = os.path.join(sublime.packages_path(), PACKAGE_NAME, '.custom')

    if version_up_to_date(dot_path, version):
        return

    if not process_local_sources(data.get('local', {})) or not process_remote_sources(data.get('remote', []), ca_cert, public_key, gpg):
        log.error('Failed to import custom modules.')
        remove_dotfile(dot_path)
        return

    update_import()
    update_version(dot_path, version)


def version_up_to_date(dot_path, version):
    if os.path.isfile(dot_path):
        with open(dot_path, 'r') as f:
            current_version = f.read().strip()
            return current_version == version

    update_version(dot_path, version)
    return False


def update_version(dot_path, version):
    with open(dot_path, 'w') as f:
        f.write(version)


def remove_dotfile(dot_path):
    try:
        os.remove(dot_path)
    except FileNotFoundError:
        log.error('File not found: %s', dot_path)
    except Exception as e:
        log.error('Error while trying to remove %s: %s', dot_path, e)


def process_local_sources(local_sources):
    for k, sources in local_sources.items():
        if k in EXPECTED_DIRS:
            dst = os.path.join(sublime.packages_path(), PACKAGE_NAME, k)
            for src in sources:
                if not copy(src, dst):
                    return False
    return True


def process_remote_sources(remote_sources, ca_cert=None, public_key=None, gpg=None):
    for arch_url in remote_sources:
        if arch_url.endswith(('.zip', '.tar.gz', '.tgz')):
            sig_url = arch_url + '.sig' if (arch_url + '.sig') in remote_sources else None
            src = download_and_extract_archive(arch_url, sig_url, ca_cert, public_key, gpg)
            if src:
                if not all(copy_dir(os.path.join(src, d), os.path.join(sublime.packages_path(), PACKAGE_NAME, d)) for d in EXPECTED_DIRS):
                    shutil.rmtree(src)
                    return False
                shutil.rmtree(src)
            else:
                return False
    return True


def read_json(path):
    try:
        data = fetch_data(path)
        return sublime.decode_value(data)
    except Exception as e:
        log.error('Failed to read custom modules JSON metadata from %s: %s', path, e)
        return {}


def fetch_data(path):
    if is_url(path):
        with urllib.request.urlopen(path, timeout=FETCH_TIMEOUT) as response:
            return response.read().decode('utf-8')
    else:
        with open(path, 'r') as file:
            return file.read()


def is_url(path):
    try:
        parsed = urlparse(path)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False


def copy_dir(src, dst):
    try:
        os.makedirs(dst, exist_ok=True)
        for item in os.listdir(src):
            src_path = os.path.join(src, item)
            dst_path = os.path.join(dst, item)
            if os.path.isdir(src_path):
                if not should_exclude(dst_path):
                    copy_dir(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)
        return True
    except Exception as e:
        log.error('Failed to copy directory from %s to %s: %s', src, dst, e)
        return False


def should_exclude(dst_path):
    p = os.path.normpath(dst_path).split(os.sep)
    return len(p) > 3 and p[-3] == PACKAGE_NAME and p[-2] == 'libs' and p[-1] in EXCLUDE_DIRS


def copy(src, dst):
    try:
        if os.path.isdir(src):
            return copy_dir(src, dst)
        else:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
        return True
    except Exception as e:
        log.error('Failed to copy from %s to %s: %s', src, dst, e)
        return False


def download_file(url, file_path, ca_cert=None):
    try:
        if url.startswith('https'):
            if sys.version_info >= (3, 4):  # python 3.8+
                context = ssl.create_default_context()
                if ca_cert:
                    context.load_verify_locations(cafile=ca_cert)
                with urllib.request.urlopen(url, context=context, timeout=DOWNLOAD_TIMEOUT) as response, open(file_path, 'wb') as file:
                    shutil.copyfileobj(response, file)
            else:  # python 3.3
                if ca_cert:
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_verify_locations(cafile=ca_cert)
                    with urllib.request.urlopen(url, context=context, timeout=DOWNLOAD_TIMEOUT) as response, open(file_path, 'wb') as file:
                        shutil.copyfileobj(response, file)
                else:
                    with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as response, open(file_path, 'wb') as file:
                        shutil.copyfileobj(response, file)
        else:
            with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as response, open(file_path, 'wb') as file:
                shutil.copyfileobj(response, file)
        return True
    except Exception as e:
        log.error('Failed to download %s: %s', url, e)
        return False


def verify_signature(file_path, sig_path, public_key, gpg):
    if not gpg:
        gpg = shutil.which('gpg') or shutil.which('gpg.exe')
        if not gpg:
            log.error('GPG executable not found on PATH.')
            return False

    try:
        import_process = subprocess.Popen([gpg, '--import', public_key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        import_output, import_error = import_process.communicate()

        if import_process.returncode != 0:
            log.error('Failed to import public key: %s', import_error)
            return False

        verify_process = subprocess.Popen([gpg, '--verify', sig_path, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        verify_output, verify_error = verify_process.communicate()

        if verify_process.returncode != 0:
            log.error('Signature verification failed for %s: %s', file_path, verify_error)
            return False

        log.info('Signature verification succeeded for %s', file_path)
        return True
    except Exception as e:
        log.error('Error while verifying the signature: %s', e)
    return False


def extract_archive(arch_path, dst_dir):
    try:
        if arch_path.endswith('.zip'):
            with zipfile.ZipFile(arch_path, 'r') as zip_ref:
                zip_ref.extractall(dst_dir)
        elif arch_path.endswith(('.tar.gz', '.tgz')):
            with tarfile.open(arch_path, 'r:gz') as tar_ref:
                tar_ref.extractall(dst_dir)
        else:
            log.error('Unsupported archive format. Only .zip and .tar.gz are supported.')
            return False
        return dst_dir
    except Exception as e:
        log.error('Failed to extract %s: %s', arch_path, e)
        return False


def move_extracted_contents(extract_dir, dst_dir):
    moved_dirs = set()

    try:
        entries = os.listdir(extract_dir)
        if not entries:
            log.error('Extracted directory is empty: %s', extract_dir)
            return False

        for root, dirs, files in os.walk(extract_dir):
            # Exclude directories that start with '.' or '_' like '__MACOSX'
            dirs[:] = [d for d in dirs if not (d.startswith(('.', '_')))]

            for expected_dir in EXPECTED_DIRS:
                if expected_dir in dirs:
                    if expected_dir in moved_dirs:
                        continue

                    src_dir = os.path.join(root, expected_dir)
                    cleanup_directory(src_dir)
                    shutil.move(src_dir, dst_dir)
                    moved_dirs.add(expected_dir)
        return True
    except Exception as e:
        log.error('Failed to move contents from %s to %s: %s', extract_dir, dst_dir, e)
        return False


def cleanup_directory(directory):
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            if name.startswith(('.DS_Store', '.localized', '._', 'Thumbs.db')):
                file_path = os.path.join(root, name)
                os.remove(file_path)

        for name in dirs:
            if name.startswith(('__MACOSX', '.Trashes', '.TemporaryItems')):
                dir_path = os.path.join(root, name)
                shutil.rmtree(dir_path)


def download_and_extract_archive(arch_url, sig_url=None, ca_cert=None, public_key=None, gpg=None):
    if not arch_url.endswith(('.zip', '.tar.gz', '.tgz')):
        log.error('Unsupported archive format. Only .zip and .tar.gz are supported.')
        return False

    download_path = os.path.join(tempfile.gettempdir(), os.path.basename(arch_url))
    extract_dir = tempfile.mkdtemp()
    dst_dir = tempfile.mkdtemp()
    sig_path = download_path + '.sig' if sig_url else None

    try:
        if download_file(arch_url, download_path, ca_cert):
            if sig_url and sig_path:
                if not (download_file(sig_url, sig_path, ca_cert) and verify_signature(download_path, sig_path, public_key, gpg)):
                    return False
            if extract_archive(download_path, extract_dir) and move_extracted_contents(extract_dir, dst_dir):
                return dst_dir
    except Exception as e:
        log.error('Error occurred: %s', e)
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
        for path in [download_path, sig_path] if sig_path else [download_path]:
            if os.path.isfile(path):
                os.remove(path)
    return False


def import_model_v1(custom_modules):  # @deprecated
    packages_path = sublime.packages_path()
    seen = set()

    for k, v in custom_modules.items():
        if k in EXPECTED_DIRS and isinstance(v, list):
            for src in v:
                src = sublime.expand_variables(os.path.normpath(os.path.expanduser(os.path.expandvars(src))), {'packages': packages_path})
                base = os.path.basename(src)

                if k == 'libs' and base in EXCLUDE_DIRS:
                    continue

                dst = os.path.join(packages_path, PACKAGE_NAME, k, base)

                if os.path.isfile(src):
                    if not files_are_equal(src, dst):
                        shutil.copy2(src, dst, follow_symlinks=True)
                        seen.add(True)
                elif os.path.isdir(src):
                    if not dirs_are_equal(src, dst):
                        try:
                            shutil.copytree(src, dst)
                            seen.add(True)
                        except FileExistsError:
                            shutil.rmtree(dst)
                            shutil.copytree(src, dst)
                            seen.add(True)

    if any(seen):
        update_import()


def files_are_equal(src, dst):
    src_md5 = HashHandler.md5f(src)
    dst_md5 = HashHandler.md5f(dst) if os.path.exists(dst) else None
    return src_md5 == dst_md5


def dirs_are_equal(src, dst):
    src_sum = HashHandler.md5d(src)
    dst_sum = HashHandler.md5d(dst) if os.path.exists(dst) else None
    return src_sum == dst_sum


def update_import():
    import_libs()  # import libs

    from ..modules import update_formatter_modules
    update_formatter_modules()  # import modules


def import_libs():
    libs_dir = os.path.join(sublime.packages_path(), PACKAGE_NAME, 'libs')
    for root, dirs, files in os.walk(libs_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for filename in files:
            if filename.endswith('.py'):
                _import_module(libs_dir, root, filename)


def _import_module(libs_dir, root, filename):
    module_path = os.path.join(root, filename)
    # Create the module name relative to the libs directory
    relative_path = os.path.relpath(module_path, libs_dir)
    module_name = relative_path.replace(os.sep, '.')[:-3]
    module_full_name = PACKAGE_NAME + '.libs.' + module_name

    try:
        if module_full_name in sys.modules:
            # Use fresh version instead of cached one
            del sys.modules[module_full_name]

        if sys.version_info > (3, 3):  # python 3.8+
            importlib.import_module(module_full_name, package=PACKAGE_NAME)
        else:  # python 3.3
            imp.load_source(module_full_name, module_path)
    except Exception as e:
        log.error('Error importing libs module %s from %s: %s', module_name, module_path, e)
