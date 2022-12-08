#!/bin/bash
until $(curl --output /dev/null --silent --head --fail http://localstack:4566); do
    echo "waiting on localstack..."
    sleep 5
done
sleep 5
export LOCALSTACK_HOST=localstack
pool_id=$(awslocal cognito-idp create-user-pool --pool-name $POOL_NAME | jq -rc ".UserPool.Id")
client_id=$(awslocal cognito-idp create-user-pool-client --user-pool-id $pool_id --client-name $CLIENT_NAME | jq -rc ".UserPoolClient.ClientId")
awslocal cognito-idp sign-up --client-id $client_id --username $ADMIN_EMAIL --password $ADMIN_PASSWORD --user-attributes Name=email,Value=$ADMIN_EMAIL Name=email_verified,Value=true
awslocal cognito-idp admin-confirm-sign-up --user-pool-id $pool_id --username $ADMIN_EMAIL
awslocal s3api create-bucket --bucket $BUCKET_NAME
awslocal iam create-user --user-name $ADMIN_EMAIL
ACCESSDATA=$(awslocal iam create-access-key --user-name $ADMIN_EMAIL)
echo $ACCESSDATA
awslocal cognito-idp create-group --user-pool-id $pool_id --group-name vince
awslocal cognito-idp create-group --user-pool-id $pool_id --group-name ADMIN
awslocal cognito-idp admin-add-user-to-group --user-pool-id $pool_id --group-name ADMIN --username $ADMIN_EMAIL
awslocal cognito-idp admin-add-user-to-group --user-pool-id $pool_id --group-name vince --username $ADMIN_EMAIL

AWS_COGNITO_USER_POOL_ID=$pool_id
AWS_COGNITO_APP_ID=$client_id
AWS_ACCESS_KEY_ID=$(echo $ACCESSDATA | jq -rc ".AccessKey.AccessKeyId")
AWS_SECRET_ACCESS_KEY=$(echo $ACCESSDATA | jq -rc ".AccessKey.SecretAccessKey")
BUCKET_URL=http://$BUCKET_NAME.s3.$REGION.localstack:4566
AWS_S3_ENDPOINT_URL=http://$POOL_NAME.$REGION.localstack:4566
BOTO_URL=http://$POOL_NAME.localstack:4566
VINCE_PUB_DOMAIN=$DOMAIN
VINCE_TRACK_DOMAIN=$DOMAIN
VINCE_COMM_DOMAIN=$DOMAIN
AWS_STORAGE_BUCKET_NAME=$BUCKET_NAME
SUPERUSER=$ADMIN_USERNAME

to_replace="AWS_COGNITO_USER_POOL_ID AWS_COGNITO_APP_ID AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY BUCKET_URL AWS_S3_ENDPOINT_URL BOTO_URL VINCE_PUB_DOMAIN VINCE_TRACK_DOMAIN VINCE_COMM_DOMAIN AWS_STORAGE_BUCKET_NAME SUPERUSER"

filename="/opt/vince/bigvince/.env"
for i in $to_replace;
do
    export b=$(echo ${!i} | sed "s/\//\\\\\//g")
    echo "s/$i.*$/$i=\"$b\"/g"
    sed -i s/$i.*$/$i=\"$b\"/g $filename
done
export PGPASSWORD=$POSTGRESQL_PASS
createdb -h $POSTGRES_HOST -U postgres vince
createdb -h $POSTGRES_HOST -U postgres vincecomm
createdb -h $POSTGRES_HOST -U postgres vincepub 
python3 manage.py migrate
python3 manage.py migrate --database=vincecomm
python3 manage.py migrate --database=vincepub
DJANGO_SUPERUSER_PASSWORD=$ADMIN_PASSWORD python3 manage.py createsuperuser --noinput --username=$ADMIN_USERNAME --email=$ADMIN_EMAIL
python3 manage.py loadinitialdata
