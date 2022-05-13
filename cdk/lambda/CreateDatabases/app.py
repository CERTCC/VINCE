import json
import logging
#import requests
import boto3
import psycopg2
from crhelper import CfnResource

logger = logging.getLogger(__name__)

helper = CfnResource(
    json_logging=False,
    log_level='DEBUG',
    boto_level='CRITICAL'
)



def create_db(event):
    dburl = event["ResourceProperties"]["Dburl"]
    dbport = event["ResourceProperties"]["Dbport"]
    logger.debug(f"Dburl: {dburl}")
    logger.debug(f"Dbport: {dbport}")
    master = json.loads(get_secret(event["ResourceProperties"]["Master"]))
    keys = [json.loads(get_secret(x['value'])) for x in event["ResourceProperties"]["Keys"]]

    con = psycopg2.connect(dbname='postgres', user=master['username'], host=dburl, port=dbport, password=master['password'])
    con.autocommit = True

    for key in keys:
        cur = con.cursor()
        username = key['username']
        password = key['password']

        logger.info(f"Creating user {username}...")
        try:
            cur.execute(f"CREATE USER {username} WITH ENCRYPTED PASSWORD '{password}';")
            logger.info(f"User {username} created.")
        except psycopg2.ProgrammingError as e:
            if not 'already exists' in str(e):
                raise e
            else:
                logger.info(str(e))

        logger.info(f"Creating database {username}..")
        try:
            cur.execute(f"CREATE DATABASE {username};")
            logger.info(f"Database {username} created.")

            new_con = psycopg2.connect(dbname=username, user=master['username'], host=dburl, port=dbport,
                                       password=master['password'])
            new_con.autocommit = True
            logger.info(f"Connecting to {username}.")
            new_con.cursor().execute('CREATE EXTENSION BTREE_GIN;')
            logger.info(f"Added BTREE_GIN extension to {username}.")

        except psycopg2.ProgrammingError as e:
            if not 'already exists' in str(e):
                raise e
            else:
                logger.info(str(e))
        else:
            logger.info(f"Altering database {username}'s owner to {username}")
            cur.execute(f"ALTER DATABASE {username} owner to {username};")
            logger.info(f"Ownership updated.")



def handler(event, context):
    # if event['RequestType'] == 'Delete':
    #     responseStatus = 'SUCCESS'
    #     responseData = {}
    #     sendResponse(event, context, responseStatus, responseData)
    # else:
    #     helper(event, context)

    helper(event, context)

@helper.create
def create(event, context):
    logger.info("Got Create")
    logger.info("Event:")
    logger.info(json.dumps(event))

    create_db(event)
    return event["ResourceProperties"]["Dburl"]

    # Items stored in helper.Data will be saved
    # as outputs in your resource in CloudFormation
    # helper.Data.update({"test": "testdata"})


@helper.update
def update(event, context):
    logger.info("Got Update")
    logger.info("Event:")
    logger.info(json.dumps(event))

    create_db(event)
    return event["ResourceProperties"]["dburl"]

@helper.delete
def delete(event, context):
    # Delete never returns anything.  Should not fail if the underlying resources are already deleted.  Desired State.
    logger.info("Got Delete.  Doing some high speed deletion stuff. Not returning anything. Nope. Meow.")
    logger.info("Event:")
    logger.info(json.dumps(event))


def get_secret(secret_arn):
    logger.debug(f"Getting secret {secret_arn}")
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager')
    secrets = client.get_secret_value(SecretId=secret_arn)
    return secrets['SecretString']


# def sendResponse(event, context, responseStatus, responseData):
#     responseBody = {'Status': responseStatus,
#                     'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
#                     'PhysicalResourceId': event['PhysicalResourceId'],
#                     'StackId': event['StackId'],
#                     'RequestId': event['RequestId'],
#                     'LogicalResourceId': event['LogicalResourceId'],
#                     'Data': responseData}
#     logger.info('RESPONSE BODY:n' + json.dumps(responseBody))
#     try:
#         req = requests.put(event['ResponseURL'], data=json.dumps(responseBody))
#         if req.status_code != 200:
#             logger.error(req.text)
#             raise Exception('Recieved non 200 response while sending response to CFN.')
#         return
#     except requests.exceptions.RequestException as e:
#         logger.error(e)
#         raise

