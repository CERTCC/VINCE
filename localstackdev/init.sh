#!/bin/bash
#If this is the first time application is run, run initial_install
if [ ! -f /firsttime ]; then
    chmod +x /opt/vince/localstackdev/initial_install.sh
    /opt/vince/localstackdev/initial_install.sh
    touch /firsttime
fi
until $(curl --output /dev/null --silent --head --fail http://localstack:4566); do
    echo "waiting on localstack..."
    sleep 5
done
sleep 5
#More Django Commands
python3 manage.py collectstatic --noinput
python3 manage.py runserver 0.0.0.0:80