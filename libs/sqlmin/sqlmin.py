#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)
#
# Thanks and credits to Vitaly Tomilov
# https://github.com/vitaly-t/pg-minify

__version__ = '1.0.0'


def add_space(result, space):
    if space:
        if result:
            result += ' '
        space = False
    return result, space


def minify(sql, options=None):
    if options is not None and not isinstance(options, dict):
        return {'code': 1, 'result': 'Options must be of type dict.'}

    if not isinstance(sql, str):
        return {'code': 1, 'result': 'Input SQL must be a text string.'}

    length = len(sql)
    if not length:
        return {'code': 1, 'result': 'Input SQL is empty.'}

    sql = sql.replace('\r\n', '\n')

    idx = 0  # Current index
    result = ''  # Resulting SQL
    space = False  # Add a space on the next step

    preserve_special_comments = options.get('preserve_special_comments', False)
    newlines_before_special_comments = options.get('newlines_before_special_comments', '\n')
    newlines_after_special_comments = options.get('newlines_after_special_comments', '\n')

    while idx < length - 1:
        s = sql[idx]  # Current symbol
        s1 = sql[idx + 1]  # Next symbol

        # Skip all consecutive whitespace characters
        if s.isspace():
            while idx < length and sql[idx].isspace():
                idx += 1
            space = True
            continue

        # Handling single-line comments
        if s == '-' and s1 == '-':
            lb = sql.find('\n', idx + 2)
            if lb < 0:
                break
            idx = lb + 2
            continue

        # Handling special/copyright multi-line comments (/*! ... */)
        if preserve_special_comments and s == '/' and s1 == '*' and sql[idx + 2] == '!':
            end = sql.find('*/', idx + 2)
            if end < 0:
                line_number = sql.count('\n', 0, idx) + 1
                column_number = idx - sql.rfind('\n', 0, idx) + 3
                error_message = 'Unclosed special multi-line comment at line {}, column {}'.format(line_number, column_number)
                return {'code': 1, 'result': error_message}

            result, space = add_space(result, space)

            nl_count_before = len(newlines_before_special_comments.split('\n'))
            if nl_count_before > 1:
                result += '\n' * (nl_count_before - 1)

            result += '/*!' + sql[idx + 3:end] + '*/'
            idx = end + 2

            nl_count_after = len(newlines_after_special_comments.split('\n'))
            if nl_count_after > 1:
                while idx < length and sql[idx].isspace():
                    idx += 1
                result += '\n' * (nl_count_after - 1)

            continue

        # Handling nested multi-line comments
        if s == '/' and s1 == '*':
            end = sql.find('*/', idx + 2)
            nested_start = sql.find('/*', idx + 2)
            while nested_start != -1 and nested_start < end:
                end = sql.find('*/', end + 2)
                nested_start = sql.find('/*', nested_start + 2)

            if end < 0:
                line_number = sql.count('\n', 0, idx) + 1
                column_number = idx - sql.rfind('\n', 0, idx) + 2
                error_message = 'Unclosed multiline comment at line {}, column {}'.format(line_number, column_number)
                return {'code': 1, 'result': error_message}
            idx = end + 2
            continue

        # Handling quoted strings
        close_idx = 0
        text = ''

        quotes = [(k, v) for k, v in {'single': "'", 'double': '"', 'backtick': '`'}.items() if v == s]
        if quotes:
            name = quotes[0][0]
            pattern = s
            close_idx = sql.find(pattern, idx + 1)
            if close_idx > 0:
                while close_idx > 0:
                    if sql[close_idx - 1] == '\\':
                        close_idx = sql.find(pattern, close_idx + 1)
                        continue
                    else:
                        result, space = add_space(result, space)
                        text = sql[idx:close_idx]  # Quoted content
                        result += text
                        idx = close_idx

                        if '\n' in text:
                            line_number = sql.count('\n', 0, idx) + 1
                            column_number = idx - sql.rfind('\n', 0, idx) + 1
                            error_message = '{} quotes cannot contain newlines. Error at line {}, column {}'.format(name.capitalize(), line_number, column_number)
                            return {'code': 1, 'result': error_message}
                        break
            else:
                line_number = sql.count('\n', 0, idx) + 1
                column_number = idx - sql.rfind('\n', 0, idx) + 1
                error_message = 'Unclosed {} quotes at line {}, column {}'.format(name, line_number, column_number)
                return {'code': 1, 'result': error_message}

        result, space = add_space(result, space)

        # Handling specific cases for certain symbols
        if s in [')', ']', '}', '>'] and result and result[-1].isspace():
            result = result.rstrip()  # Remove spaces before symbol
        elif s in ['(', '[', '{', '<'] and sql[idx + 1].isspace():
            while idx + 1 < length and sql[idx + 1].isspace():
                idx += 1  # Skip spaces after symbol
        elif s in ['.', ',', ';', ':', '=', '+', '-', '*', '|', '!', '?', '@', '#']:
            # Remove spaces before symbol
            if result and result[-1].isspace():
                result = result.rstrip()
            # Remove spaces after symbol
            if sql[idx + 1].isspace():
                while idx + 1 < length and sql[idx + 1].isspace():
                    idx += 1

        result += s
        idx += 1

    # Handle the last character if any
    if idx == length - 1:
        result += sql[idx]

    return {'code': 0, 'result': result}


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='SQL Minifier')
    parser.add_argument('sql', help='The input SQL to minify')
    parser.add_argument('-p', '--preserve_special_comments', action='store_true', help='Preserve special/copyright comments (/*! ... */)')
    parser.add_argument('-b', '--newlines_before_special_comments', default='"\\n"', metavar='"\\n\\n"', help='Add new lines before special comments')
    parser.add_argument('-a', '--newlines_after_special_comments', default='"\\n"', metavar='"\\n\\n"', help='Add new lines after special comments')
    parser.add_argument('-v', '--version', action='store_true', help='Show script version and exit')
    args = parser.parse_args()

    if args.version:
        print('Script version:', __version__)
        sys.exit()

    options = {
        'preserve_special_comments': args.preserve_special_comments,
        'newlines_before_special_comments': args.newlines_before_special_comments,
        'newlines_after_special_comments': args.newlines_after_special_comments
    }
    minified_sql = minify(args.sql, options)

    if minified_sql['code'] == 0:
        print(minified_sql['result'])
    else:
        sys.stderr.write(minified_sql['result'] + '\n')
        sys.exit(1)
