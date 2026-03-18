#!/bin/bash
set -xe

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Detect package manager (AL2023 = dnf, fallback to yum for safety)
if command -v dnf >/dev/null 2>&1; then
  PM=dnf
elif command -v yum >/dev/null 2>&1; then
  PM=yum
else
  echo "No supported package manager found on this instance."
  exit 1
fi

log "Refreshing package metadata..."
sudo $PM -y makecache

log "Installing Python 3.11 from system packages..."
sudo $PM -y install python3.11 python3.11-devel python3.11-pip

log "Checking Python version..."
python3.11 --version

log "Checking pip version..."
pip3.11 --version

log "02_install_python311.sh completed successfully."

