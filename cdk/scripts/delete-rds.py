import boto3
import argparse
import json
import sys



def yes_no(question):
    while True:
        reply = str(input(f"{question} (y/n): ").lower().strip())
        if reply[0] == 'y':
            return True
        if reply[0] == 'n':
            return False


def get_rds_arn_with_tag(key: str, value: str, region: str) -> list:
    """
    Return a list of ARN for RDS instances with matching key,value tags

    :param key:
    :param region: Region to search
    :return: List of Arns
    """
    client = boto3.client('rds', region_name=region)
    results = client.describe_db_instances()

    arns = []
    for x in results['DBInstances']:
        arn = x['DBInstanceArn']
        tags = client.list_tags_for_resource(ResourceName=arn)
        for tag in tags['TagList']:
            if tag['Key'] == key and tag['Value'] == value:
                arns.append(arn)
                continue

    return arns


def get_db_identifier_from_arn(arn: str, region: str) -> str:
    """
    Return the the RDS db identifier based on the RDS arn
    :param arn: RDS Arn
    :param region: AWS region
    :return: RDS db identifier or None
    """
    client = boto3.client('rds', region_name=region)
    results = client.describe_db_instances()
    for x in results['DBInstances']:
        if x['DBInstanceArn'] == arn:
            return x['DBInstanceIdentifier']



def delete_rds(arn, region, skip_final_snaphost: bool=True, final_db_snapshot_identifier: str='',  delete_automated_backups: bool=True):
    client = boto3.client('rds', region_name=region)
    identifier = get_db_identifier_from_arn(arn, region)
    tags = client.list_tags_for_resource(ResourceName=arn)


    yn = yes_no(f"Delete RDS {identifier} - {arn} ?\nTags:\n{json.dumps(tags['TagList'], indent=4, sort_keys=True)}\n")

    if yn:
        print(f"Deleting RDS {identifier} - {arn}...")
        client.modify_db_instance(DBInstanceIdentifier=identifier, DeletionProtection=False)
        response = client.delete_db_instance(
            DBInstanceIdentifier=identifier,
            SkipFinalSnapshot=skip_final_snaphost,
            FinalDBSnapshotIdentifier=final_db_snapshot_identifier,
            DeleteAutomatedBackups=delete_automated_backups
        )
        print(response)
    else:
        print(f"Skipping delete.")
        sys.exit(1)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('stack_name', help='Stack name of RDS instance to delete')
    parser.add_argument('-r', '--region_name', help='Region to search', default='us-east-2')
    args = parser.parse_args()

    key = 'aws:cloudformation:stack-name'


    arns = get_rds_arn_with_tag(key, args.stack_name, args.region_name)
    try:
        delete_rds(arns[0], args.region_name)
    except IndexError:
        print(f"No RDS instances for stack {args.stack_name}")



