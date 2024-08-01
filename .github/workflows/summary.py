import os

# Directory containing the files
directory = './modules'

# Output file
output_file = './modules/_summary.txt'


# Function to extract relevant fields from the MODULE_CONFIG dictionary
def extract_info(file_content):
    uid, name, source, type_, syntaxes = None, None, None, None, None
    in_module_config = False

    for line in file_content.splitlines():
        line = line.strip()
        if line.startswith('MODULE_CONFIG'):
            in_module_config = True
        elif in_module_config:
            if "'uid':" in line:
                uid = line.split(':', 1)[1].strip().strip(',').strip("'").strip('"')
            elif "'name':" in line:
                name = line.split(':', 1)[1].strip().strip(',').strip("'").strip('"')
            elif "'type':" in line:
                type_ = line.split(':', 1)[1].strip().strip(',').strip("'").strip('"')
            elif "'source':" in line:
                source = line.split(':', 1)[1].strip().strip(',').strip("'").strip('"')
            elif "'syntaxes':" in line:
                syntaxes_str = line.split(':', 1)[1].strip().strip(',')
                if syntaxes_str.startswith('[') and syntaxes_str.endswith(']'):
                    syntaxes = syntaxes_str[1:-1].strip()
                    if syntaxes:
                        syntaxes = [s.strip().strip("'").strip('"') for s in syntaxes.split(',')]
                    else:
                        syntaxes = []
            elif '}' in line:
                break

    if uid and name and source and type_ and syntaxes:
        return uid, name, source, type_, syntaxes
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
                        uid, name, source, type_, syntaxes = info
                        if type_ not in formatter_info:
                            formatter_info[type_] = []
                        formatter_info[type_].append((uid, name, source, type_, syntaxes))
            except Exception as e:
                print('Error reading {}: {}'.format(filepath, e))

    # Sort categories alphabetically
    sorted_categories = sorted(formatter_info.keys())

    # Sort entries within each category by UID
    for category in sorted_categories:
        formatter_info[category].sort(key=lambda x: x[0])  # Sort by UID (x[0])

    # Prepare data for dynamic column width calculation
    data = []
    header = ['#', 'UID', 'NAME', 'TYPE', 'INFO', 'SYNTAXES']
    data.append(header)

    idx = 1
    for category in sorted_categories:
        for uid, name, source, type_, syntaxes in formatter_info[category]:
            data.append([str(idx), uid, name, type_, source, str(syntaxes)])
            idx += 1

    # Calculate the maximum width of each column
    col_widths = [max(len(row[i]) for row in data) for i in range(len(header))]

    # Write the extracted information to the output file
    try:
        with open(output_file, 'w') as file:
            # Write the header
            file.write('     '.join('{:<{}}'.format(header[i], col_widths[i]) for i in range(len(header))) + '\n')
            # Write the data
            for row in data[1:]:
                file.write('     '.join('{:<{}}'.format(row[i], col_widths[i]) for i in range(len(row))) + '\n')
        print('Information extracted and written to {}'.format(output_file))
    except Exception as e:
        print('Error writing to {}: {}'.format(output_file, e))
