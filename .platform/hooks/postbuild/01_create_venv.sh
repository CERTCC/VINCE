#!/bin/bash
set -xe

cd /var/app/staging

# Create a venv using Python 3.11
/usr/local/bin/python3.11 -m venv /var/app/venv/python3.11

# Activate the new venv
source /var/app/venv/python3.11/bin/activate

# Upgrade base tools
pip install --upgrade pip setuptools wheel

# Install requirements with full verbosity and log output to /tmp/pip_verbose.log
pip install -r requirements.txt
