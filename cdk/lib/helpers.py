from aws_cdk import core
import boto3
import yaml
import json


def get_lambda_arn(region: str, first_part: str, second_part: str=None) -> str:
    """
    This function searches a given region and returns the lambda function that contains name
    :param region: Region to search for cert provider arn
    :param name: Function name to look for
    :return: Matching function's ARN
    """
    client = boto3.client('lambda', region_name=region)
    response = client.list_functions()
    for x in response['Functions']:
        if second_part:
            if first_part in x['FunctionArn'] and second_part in x['FunctionArn']:
                return x['FunctionArn']
        else:
            if first_part in x['FunctionArn']:
                return x['FunctionArn']

    if second_part:
        raise ValueError(f"Cannot find function '{first_part}-*-{second_part}' in region {region}")
    else:
        raise ValueError(f"Cannot find function '{first_part}' in region {region}")


def get_hosted_id(domain_name):
    client = boto3.client('route53')
    response = client.list_hosted_zones()
    for x in response['HostedZones']:
        if x['Name'][:-1] in domain_name:
            return x['Id'].split('/')[2]


def get_hosted_zone_name(domain_name):
    client = boto3.client('route53')
    response = client.list_hosted_zones()
    for x in response['HostedZones']:
        if x['Name'][:-1] in domain_name:
            return x['Name']


def get_cert_arn(region: str, domain: str) -> str:
    """
    This function searches a given region and returns the arn for the certificate with the given domain
    :param region: Region to search
    :param domain: Domain name to look for
    :return: ARN of the matching certificate
    """
    client = boto3.client('acm', region_name=region)

    # as of 12/2021, we now need to tell boto3's ACM client to list other cyphers so that we see our new certs [jdw]
    includes = {
        'keyTypes': ['RSA_2048', 'EC_prime256v1', 'EC_secp384r1']
    }
    response = client.list_certificates(Includes=includes)
    for x in response['CertificateSummaryList']:
        if domain in x['DomainName']:
            return x['CertificateArn']

    raise ValueError(f"Cannot find ACM certificate for domain '{domain}' in region {region}")


def tag(app: core.App, resource: core.Construct):
    for key, value in app.node.try_get_context("tags").items():
        core.Tags.of(resource).add(key, value)
    core.Tags.of(resource).add('env', app.node.try_get_context('env'))


def create_context_from_yaml(cdkjson: str) -> dict:
    with open(cdkjson, 'r') as inf:
        context_yaml = json.loads(inf.read().encode('utf-8'))['context']['yaml_context']

    with open(context_yaml, 'r') as inf:
        context = {}
        for key, value in yaml.safe_load(inf)['context'].items():
            context[key] = value

    return context


def create_context_from_yaml_app(app: core.App):
    with open(app.node.try_get_context('yaml_context'), 'r') as inf:
        [app.node.set_context(key, value) for key, value in yaml.safe_load(inf)['context'].items()]


def get_lambda_latest_version_num(fn_arn: str, region: str) -> int:
    """
    Return the latest version number for a given function arn
    :param fn_arn: ARN of the function to check
    :return: fn_arn's latest version
    """

    client = boto3.client('lambda', region_name=region)
    response = client.list_versions_by_function(FunctionName=fn_arn)

    for v in response['Versions']:
        if v['Version'] == '$LATEST':
            latest_hash = v['CodeSha256']
            break

    for v in response['Versions']:
        if v['Version'] != '$LATEST' and v['CodeSha256'] == latest_hash:
            return v['Version']


def get_eb_app_latest_version(eb_app_name: str, region: str):
    """
    Return the latest version name for a given EB app. If app does not exist, return None
    :param eb_app_name:
    :param region:
    :return: latest app version name, or None
    """

    client = boto3.client('elasticbeanstalk', region_name=region)
    try:
        res = client.describe_application_versions(ApplicationName=eb_app_name)
        versions = res['ApplicationVersions']
        versions = sorted(versions, key=lambda v: v['DateUpdated'], reverse=True)

        latest_version = versions[0]['VersionLabel']
        return latest_version
    except Exception:
        pass
    return None


class ConfigStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        create_context_from_yaml_app(self)
