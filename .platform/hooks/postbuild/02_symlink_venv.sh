#!/bin/bash
set -xe

# Point EB to use the Python 3.11 virtualenv
ln -sf /var/app/venv/python3.11 /var/app/venv/staging
