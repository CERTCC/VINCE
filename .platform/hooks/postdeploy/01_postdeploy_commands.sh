#!/bin/bash
# Exit immediately on error
set -e

# Ensure EB-deployed environment variables are loaded and exported for this script
if [ -f /opt/elasticbeanstalk/deployment/env ]; then
  # export variables declared in that file into this shell
  set -a
  source /opt/elasticbeanstalk/deployment/env
  set +a
fi

# Ensure AWS region is available for boto3/watchtower: prefer AWS_REGION, then AWS_DEFAULT_REGION,
# otherwise fall back to instance metadata (safe default).
export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [ -z "${AWS_REGION}" ]; then
  # use metadata as last resort; timeout quickly if metadata unavailable
  metadata_region=$(timeout 2s curl -s http://169.254.169.254/latest/meta-data/placement/region || true)
  export AWS_REGION="${metadata_region:-}"
fi

# If boto3 expects AWS_DEFAULT_REGION, ensure it's consistent
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-${AWS_REGION:-}}"

# Activate the virtual environment
source /var/app/venv/*/bin/activate

echo "Running postdeploy commands..."

# 01_migrate_vincetrack
if [ "X${VINCE_NAMESPACE}" == "Xvince" ]; then
    echo "Running migrate on 'default' DB (VINCE_NAMESPACE == vince)..."
    python3 manage.py migrate --database=default --noinput
else
    echo "Skipping migrate on 'default' DB (VINCE_NAMESPACE != vince)"
fi

# 02_migrate_vincecomm
if [ "X${VINCE_NAMESPACE}" != "Xvincepub" ]; then
    echo "Running migrate on 'vcomm' DB (VINCE_NAMESPACE != vincepub)..."
    python3 manage.py migrate --database=vincecomm --noinput
else
    echo "Skipping migrate on 'vcomm' DB (VINCE_NAMESPACE == vincepub)"
fi

# 03_collectstatic
echo "Running collectstatic..."
python3 manage.py collectstatic --noinput

# 04_createsu
if [ "X${VINCE_NAMESPACE}" != "Xvincepub" ]; then
    echo "Running createsu (VINCE_NAMESPACE != vincepub)..."
    python3 manage.py createsu
else
    echo "Skipping createsu (VINCE_NAMESPACE == vincepub)"
fi

# 05_migrate_vincepub — run only on leader instance
IS_LEADER=$(curl -s http://169.254.169.254/latest/meta-data/instance-id | grep -q "$(cat /var/leader_instance_id)" && echo "yes" || echo "no")
if [ "$IS_LEADER" == "yes" ]; then
    echo "Running migrate on 'vincepub' DB (leader instance)..."
    python3 manage.py migrate --database=vincepub --noinput
else
    echo "Skipping migrate on 'vincepub' DB (not leader)"
fi

# 07_loadinitialdata
if [ "X${VINCE_NAMESPACE}" != "Xvincepub" ]; then
    echo "Running loadinitialdata (VINCE_NAMESPACE != vincepub)..."
    python3 manage.py loadinitialdata
else
    echo "Skipping loadinitialdata (VINCE_NAMESPACE == vincepub)"
fi
