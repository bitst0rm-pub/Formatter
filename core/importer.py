import os
import sys
import ssl
import shutil
import zipfile
import tarfile
import tempfile
import urllib.request
from urllib.parse import urlparse

try:  # python 3.8+
    import importlib
except:  # python 3.3
    import imp

import sublime

from . import (log, CONFIG, HashHandler)
from .constants import PACKAGE_NAME


EXPECTED_DIRS = ['config', 'libs', 'modules']
EXCLUDE_DIRS = ['prettytable', 'sqlmin', 'toml', 'wcswidth', 'yaml']
DOWNLOAD_TIMEOUT = 10  # sec


def import_custom_modules():
    custom_modules = CONFIG.get('custom_modules', None)
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
    dot_path = os.path.join(sublime.packages_path(), PACKAGE_NAME, '.custom')
    if version_up_to_date(dot_path, version):
        return

    if not process_local_sources(data.get('local', {})) or not process_remote_sources(data.get('remote', []), ca_cert):
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
    else:
        update_version(dot_path, version)
    return False

def update_version(dot_path, version):
    with open(dot_path, 'w') as f:
        f.write(version)

def remove_dotfile(dot_path):
    try:
        os.remove(dot_path)
    except FileNotFoundError:
        log.error('File not found: %s' % dot_path)
    except Exception as e:
        log.error('An error occurred while trying to remove %s: %s' % (dot_path, e))

def process_local_sources(local_sources):
    for k, sources in local_sources.items():
        if k in EXPECTED_DIRS:
            dst = os.path.join(sublime.packages_path(), PACKAGE_NAME, k)
            for src in sources:
                if not copy(src, dst):
                    return False
    return True

def process_remote_sources(remote_sources, ca_cert=None):
    for arch_url in remote_sources:
        src = download_and_extract_archive(arch_url, ca_cert)
        if src:
            for d in EXPECTED_DIRS:
                dst = os.path.join(sublime.packages_path(), PACKAGE_NAME, d)
                if not copy_dir(os.path.join(src, d), dst):
                    shutil.rmtree(src)
                    return False
            shutil.rmtree(src)
        else:
            return False
    return True

def read_json(path, timeout=3):
    try:
        data = fetch_data(path, timeout)
        return sublime.decode_value(data)
    except Exception as e:
        log.error('Failed to read custom modules JSON metadata from %s: %s', path, e)
        return {}

def fetch_data(path, timeout):
    if is_url(path):
        with urllib.request.urlopen(path, timeout=timeout) as response:
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
                if should_exclude(dst_path):
                    continue
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

def extract_archive(arch_path, dst_dir):
    try:
        if arch_path.endswith('.zip'):
            with zipfile.ZipFile(arch_path, 'r') as zip_ref:
                zip_ref.extractall(dst_dir)
        elif arch_path.endswith('.tar.gz') or arch_path.endswith('.tgz'):
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
    try:
        entries = os.listdir(extract_dir)
        if not entries:
            log.error('Extracted directory is empty: %s', extract_dir)
            return False

        base_folder = os.path.join(extract_dir, entries[0])
        if len(entries) == 1 and os.path.isdir(base_folder):
            source_dirs = [os.path.join(base_folder, d) for d in EXPECTED_DIRS]
        else:
            source_dirs = [os.path.join(extract_dir, d) for d in EXPECTED_DIRS]

        for src in source_dirs:
            if os.path.exists(src):
                shutil.move(src, dst_dir)
        return True
    except Exception as e:
        log.error('Failed to move contents from %s to %s: %s', extract_dir, dst_dir, e)
        return False

def download_and_extract_archive(arch_url, ca_cert=None, dst_dir=None):
    if not arch_url.endswith(('.zip', '.tar.gz', '.tgz')):
        log.error('Unsupported archive format. Only .zip and .tar.gz are supported.')
        return False

    ext = arch_url.split('.')[-1]
    download_path = os.path.join(tempfile.gettempdir(), 'archive.' + ext)
    extract_dir = tempfile.mkdtemp()
    dst_dir = dst_dir or tempfile.mkdtemp()

    try:
        if download_file(arch_url, download_path, ca_cert) and extract_archive(download_path, extract_dir):
            if move_extracted_contents(extract_dir, dst_dir):
                shutil.rmtree(extract_dir)
                os.remove(download_path)
                return dst_dir
    except:
        shutil.rmtree(extract_dir)
        if os.path.isfile(download_path):
            os.remove(download_path)
        return False

def import_model_v1(custom_modules):  # deprecated
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
                import_module(libs_dir, root, filename)

def import_module(libs_dir, root, filename):
    module_name = filename[:-3]
    module_path = os.path.join(root, filename)
    # Create the module name relative to the libs directory
    relative_path = os.path.relpath(module_path, libs_dir)
    module_name = relative_path.replace(os.sep, '.').rsplit('.', 1)[0]

    try:
        try:  # python 3.8+
            module = importlib.import_module(PACKAGE_NAME + '.libs.' + module_name, package=PACKAGE_NAME)
        except:  # python 3.3
            module = imp.load_source(PACKAGE_NAME + '.libs.' + module_name, module_path)
    except Exception as e:
        log.error('Error importing module %s: %s', module_name, e)
