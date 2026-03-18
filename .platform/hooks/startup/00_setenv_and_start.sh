#!/bin/bash
# This script ensures Gunicorn starts with environment variables
set -e

# Source environment variables
# source /opt/elasticbeanstalk/deployment/env

# Start Gunicorn
# exec /var/app/venv/*/bin/gunicorn bigvince.wsgi:application --bind 0.0.0.0:8000