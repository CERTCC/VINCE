import boto3
import argparse
import json
import sys
from datetime import datetime


def yes_no(question):
    while True:
        reply = str(input(f"{question} (y/n): ").lower().strip())
        if reply[0] == 'y':
            return True
        if reply[0] == 'n':
            return False


def get_log_groups_by_prefix(value: str, region: str) -> list:
    """
    Return a list of ARN for log groups matching the specified prefix

    :param key:
    :param region: Region to search
    :return: List of Arns
    """
    client = boto3.client('logs', region_name=region)
    results = client.describe_log_groups()
    groups = []
    while(len(results['logGroups']) > 0):
        for x in results['logGroups']:
            name = x['logGroupName']
            if value in name:
                groups.append(name)

        if 'nextToken' in results and len(results['nextToken']) > 0:
            results = client.describe_log_groups(nextToken=results['nextToken'])
        else:
            break

    return groups



def delete_log_group(name, region):
    client = boto3.client('logs', region_name=region)
    groups = client.describe_log_groups(logGroupNamePrefix=name)
    if len(groups['logGroups']) > 1:
        print("Error: We got more than one group when asking for a specific prefix.\nLog groups must be deleted in console!")
        sys.exit(1)
    timestamp = datetime.fromtimestamp(groups['logGroups'][0]['creationTime']/1000)

    yn = yes_no(f"Delete log group {name} ? \n\tCreated: {timestamp}\n")

    if yn:
        print(f"Deleting log group {name}...\n")
        client.delete_log_group(logGroupName=name)
    else:
        print(f"Skipping delete.")



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('stack_name', help='Stack name prefix to delete')
    parser.add_argument('-r', '--region_name', help='Region to search', default='us-east-2')
    args = parser.parse_args()

    #key = 'aws:cloudformation:stack-name'


    names = get_log_groups_by_prefix(args.stack_name, args.region_name)
    for name in names:
        delete_log_group(name, args.region_name)



