#!/usr/bin/env bash
#
# Usage:
# $ cd Formatter
# $ isort .
# $ flake8 .
# $ markdownlint .

python3 -m pip install --upgrade pip
pip install flake8
pip install isort
npm install markdownlint-cli2 --global
