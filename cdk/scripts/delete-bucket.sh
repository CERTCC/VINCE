#!/bin/bash


function usage
{
echo delete-bucket.sh pattern

echo Remove buckets matching pattern

exit 1 
}

if [[ $# -eq 0 ]] ; 
then
usage 
fi

for x in `aws s3 ls | grep  "$1" | cut -f3 -d' '`
do
while true; do
    read -p "Delete $x ? " yn
    case $yn in
        y|Y ) aws s3 rb s3://$x --force; break;;
        n|N ) break;;
        * ) echo "Please answer y or n.";;
    esac
done


done
