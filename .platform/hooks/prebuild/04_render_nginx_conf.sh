#!/bin/bash
set -xe

# --- Cleanup any leftover bad configs ---
if [ -f /etc/nginx/conf.d/env.conf ]; then
  echo "Removing stale /etc/nginx/conf.d/env.conf"
  sudo rm -f /etc/nginx/conf.d/env.conf
fi

# --- Load EB environment variables ---
if [ -f /opt/elasticbeanstalk/deployment/env ]; then
  . /opt/elasticbeanstalk/deployment/env
fi

if [ -z "${ROOT_PATH:-}" ]; then
  echo "ROOT_PATH not set — skipping nginx conf rendering (worker env)."
  exit 0
fi

echo "Using ROOT_PATH=${ROOT_PATH}"

# --- Locate the template ---
if [ -f /var/app/staging/.platform/nginx/conf.d/99_proxy_pass.conf.template ]; then
  TEMPLATE_PATH=/var/app/staging/.platform/nginx/conf.d/99_proxy_pass.conf.template
elif [ -f /var/app/current/.platform/nginx/conf.d/99_proxy_pass.conf.template ]; then
  TEMPLATE_PATH=/var/app/current/.platform/nginx/conf.d/99_proxy_pass.conf.template
else
  echo "ERROR: Could not find 99_proxy_pass.conf.template"
  exit 1
fi

echo "Using template: $TEMPLATE_PATH"

# --- Render final nginx config ---
envsubst '${ROOT_PATH}' < "$TEMPLATE_PATH" | sudo tee /etc/nginx/conf.d/99_proxy_pass.conf

# --- Test nginx config before applying ---
echo "Testing nginx configuration..."
sudo nginx -t

echo "Nginx config rendered and validated successfully."
