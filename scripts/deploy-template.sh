#!/bin/bash

ZIP_NAME=bigvince.zip
DEPLOY_BUCKET=:update:

if [ "X${AWS_SECRET_ACCESS_KEY}" = "X" ]; then
    echo "Environment must be configured for AWS access (access key, etc.)"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd ../
git archive -v -o "$ZIP_NAME" --format=zip HEAD
aws s3 cp bigvince.zip s3://"$DEPLOY_BUCKET" --profile "$PROFILE"
rm $ZIP_NAME

cd "$DIR"
