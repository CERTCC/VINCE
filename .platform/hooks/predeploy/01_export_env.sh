#!/bin/bash
set -e

# Load all EB environment variables into the runtime exported environment
if [ -f /opt/elasticbeanstalk/deployment/env ]; then
    echo "Exporting EB environment variables"
    export $(cat /opt/elasticbeanstalk/deployment/env | xargs)
fi

