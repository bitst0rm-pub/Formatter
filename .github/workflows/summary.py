import os

# Directory containing the files
directory = './modules'

# Output file
output_file = './modules/_summary.txt'

# Function to extract relevant fields from the MODULE_CONFIG dictionary
def extract_info(file_content):
    uid, name, source, type_ = None, None, None, None
    in_module_config = False

    for line in file_content.splitlines():
        line = line.strip()
        if line.startswith('MODULE_CONFIG'):
            in_module_config = True
        elif in_module_config:
            if "'uid':" in line:
                uid = line.split(':')[1].strip().strip(',').strip("'").strip('"')
            elif "'name':" in line:
                name = line.split(':')[1].strip().strip(',').strip("'").strip('"')
            elif "'type':" in line:
                type_ = line.split(':')[1].strip().strip(',').strip("'").strip('"')
            elif "'source':" in line:
                source = line.split(':', 1)[1].strip().strip(',').strip("'").strip('"')
            elif '}' in line:
                break

    if uid and name and source and type_:
        return uid, name, source, type_
    return None

# Ensure the directory exists
if not os.path.isdir(directory):
    print('Directory {} does not exist.'.format(directory))
else:
    formatter_info = {}

    # Iterate over files in the directory
    for filename in os.listdir(directory):
        if filename.startswith('formatter_') and filename.endswith('.py'):
            filepath = os.path.join(directory, filename)
            try:
                with open(filepath, 'r') as file:
                    content = file.read()
                    info = extract_info(content)
                    if info:
                        uid, name, source, type_ = info
                        if type_ not in formatter_info:
                            formatter_info[type_] = []
                        formatter_info[type_].append((uid, name, source, type_))
            except Exception as e:
                print('Error reading {}: {}'.format(filepath, e))

    # Sort categories alphabetically
    sorted_categories = sorted(formatter_info.keys())

    # Sort entries within each category by UID
    for category in sorted_categories:
        formatter_info[category].sort(key=lambda x: x[0])  # Sort by UID (x[0])

    # Write the extracted information to the output file
    try:
        with open(output_file, 'w') as file:
            # Write the header
            file.write('{:<7} {:<20} {:<20} {:<20} {:<20}\n'.format('#', 'UID', 'NAME', 'TYPE', 'INFO'))
            idx = 1
            # Write the data sorted by categories and within each category by UID
            for category in sorted_categories:
                for uid, name, source, type_ in formatter_info[category]:
                    file.write('{:<7} {:<20} {:<20} {:<20} {:<20}\n'.format(idx, uid, name, type_, source))
                    idx += 1
        print('Information extracted and written to {}'.format(output_file))
    except Exception as e:
        print('Error writing to {}: {}'.format(output_file, e))
