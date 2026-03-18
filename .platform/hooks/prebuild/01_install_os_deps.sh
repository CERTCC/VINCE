#!/bin/bash
set -xe

# Clean and refresh dnf cache
sudo dnf clean all
sudo dnf makecache

# Install OS packages
sudo dnf install -y \
    git \
    swig \
    libpq-devel \
    openssl-devel

# Activate the virtualenv
source /var/app/venv/*/bin/activate

# Install Python build tools
pip install --upgrade wheel cython

# Debug
which swig
swig -version
