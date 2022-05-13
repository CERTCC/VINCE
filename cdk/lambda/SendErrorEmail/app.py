import boto3
from botocore.exceptions import ClientError
import logging
import json
import os

# stuff that shouldn't change often, if at all
# :update: for public release: Your chosen default region might be different. Update accordingly.
aws_region = 'us-east-1'
charset = "UTF-8"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def handler(event, context):
    logger.debug(f"Got event:")
    logger.debug(json.dumps(event))

    note = event['Records'][0]['Sns']
    #logger.info("Got message event:")
    #logger.info(f"Subject: {note['Subject']}")
    #logger.info(f"Message: {note['Message']}")

    email_from = os.environ['EMAIL_FROM']
    email_to = os.environ['EMAIL_TO'].split(",")
    subj_prefix = os.getenv('SUBJ_PREFIX', '')
    if len(subj_prefix) > 0:
        subj_prefix += " "
    subject = f"{subj_prefix}{note['Subject']}"

    client = boto3.client('ses', region_name=aws_region)
    try:
        res = client.send_email(
            Destination={
                'ToAddresses': email_to,
            },
            Message={
                'Body': {
                    'Text': {
                        'Charset': charset,
                        'Data': note['Message'],
                    },
                },
                'Subject': {
                    'Charset': charset,
                    'Data': subject,
                },
            },
            Source=email_from,
        )
    except ClientError as e:
        logger.error(e.response['Error']['Message'])
        return False
    else:
        logger.info(f"Message sent: {res['MessageId']}")
        return True

