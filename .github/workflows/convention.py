import os
import sys

# Naming convention check
directory = './modules'


def is_pascal_case(name):
    return name and name[0].isupper() and all(c.isalnum() for c in name)


def is_lowercase(string):
    return string.islower()


def is_valid_class_name(class_name):
    if class_name.endswith('Formatter'):
        name_without_formatter = class_name[:-len('Formatter')]
        return (name_without_formatter[0].isupper() and all(c.islower() or c.isdigit() for c in name_without_formatter[1:]))
    return False


def check_file(file_path):
    with open(file_path, 'r') as file:
        content = file.readlines()

        name = None
        uid = None
        class_name = None
        error_found = False

        for line in content:
            if "'name':" in line:
                name = line.split("'")[3]
            elif "'uid':" in line:
                uid = line.split("'")[3]
            elif 'class ' in line and '(Module)' in line:
                parts = line.split()
                if len(parts) > 1:
                    class_name = parts[1].split('(')[0]

        if not name:
            print('File: {} - Missing name definition'.format(file_path))
            error_found = True
        elif not is_pascal_case(name):
            print('File: {} - Incorrect name format: {}'.format(file_path, name))
            error_found = True

        if uid is None:
            print('File: {} - Missing UID definition'.format(file_path))
            error_found = True
        elif not is_lowercase(uid):
            print('File: {} - UID not lowercase: {}'.format(file_path, uid))
            error_found = True

        if not class_name:
            print('File: {} - Missing class definition'.format(file_path))
            error_found = True
        elif not is_valid_class_name(class_name):
            print('File: {} - Incorrect class name format: {}'.format(file_path, class_name))
            error_found = True

        return error_found


overall_error = False

for root, dirs, files in os.walk(directory):
    for file in files:
        if file.startswith('formatter_') and file.endswith('.py') and file != 'formatter_generic.py':
            if check_file(os.path.join(root, file)):
                overall_error = True

if overall_error:
    sys.exit(1)
