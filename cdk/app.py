#!/usr/bin/env python3

import yaml
from aws_cdk import core

from stacks import CertificateStack, CertificateStackNoVA
from stacks import CloudfrontStack
from stacks import LambdaEdgeStack
from stacks import LambdaStack
# from stacks.test import TestStack
from stacks import SecretsStack
from stacks import VpcStack
from stacks import BucketsStack
from stacks import LoggingStack
from stacks.kb import KbEbStack
from stacks.vince import VinceEbStack, VinceRdsStack
from stacks.vincecomm import VinceCommEbStack
from lib.helpers import tag
from lib.helpers import create_context_from_yaml_app

app = core.App(tree_metadata=False)
create_context_from_yaml_app(app)

base_stack_name = app.node.try_get_context("stack_name")
vince_stack_suffix = app.node.try_get_context("vince_stack_suffix")
kb_stack_suffix = app.node.try_get_context("kb_stack_suffix")
vincecomm_stack_suffix = app.node.try_get_context("vincecomm_stack_suffix")

env = {'region': 'us-east-1',
       'account': str(app.node.try_get_context('aws_account_id'))}

# These stacks need to be deployed first in Nova
# CloudFront certificates need to be in NoVa (us-east-1) (east coast best coast)
cf_certs_stack = CertificateStackNoVA(app, f"{base_stack_name}-cf-certs", env=env)
tag(app, cf_certs_stack)

# LambdaEdge functions need to be in NoVa (us-east-1) (east coast best coast)
lambda_edge_stack = LambdaEdgeStack(app, f"{base_stack_name}-lambdaedge", env=env)
tag(app, lambda_edge_stack)

env = {'region': app.node.try_get_context('aws_region'),
       'account': str(app.node.try_get_context('aws_account_id'))}

# These stacks are deployed in dependency order.

# Secrets Stack
secrets_stack = SecretsStack(app, f"{base_stack_name}-secrets", env=env)
tag(app, secrets_stack)

# VPC Stack
vpc_stack = VpcStack(app, f"{base_stack_name}-vpc", env=env)
tag(app, vpc_stack)

# Cert Stacks
certs_stack = CertificateStack(app, f"{base_stack_name}-certs", env=env)
tag(app, certs_stack)

# # Lambda Stack
lambda_stack = LambdaStack(app, f"{base_stack_name}-lambdas", vpc=vpc_stack.vpc, env=env)
tag(app, lambda_stack)
if app.node.try_get_context('vince_rds_initialize_db') or app.node.try_get_context('kb_rds_initialize_db'):
    lambda_stack.gen_create_db_lambda()
    create_db_lambda = lambda_stack.create_db_lambda
else:
    create_db_lambda = None
if app.node.try_get_context('vince_error_email_recipients'):
    lambda_stack.gen_send_error_email_func()

cloudfront_stack = CloudfrontStack(app, f"{base_stack_name}-cloudfront", env=env)
if app.node.try_get_context("kb_cloudfront_create_dist"):
    cloudfront_stack.create_kb_dist()
if app.node.try_get_context("vince_cloudfront_create_dist"):
    cloudfront_stack.create_vince_dist()
tag(app, cloudfront_stack)

# Shared buckets stack
buckets_stack = BucketsStack(app, f"{base_stack_name}-buckets", env=env)

# Monitoring stack
logging_stack = LoggingStack(app, f"{base_stack_name}-logging", env=env)

# Vince Database Stack
vince_rds_stack = VinceRdsStack(app, f"{base_stack_name}-{vince_stack_suffix}-rds", vpc=vpc_stack.vpc,
                                bastion=vpc_stack.bastion,
                                secrets=secrets_stack, create_db_lambda=create_db_lambda, env=env)
tag(app, vince_rds_stack)

# Vince EB Stack
vince_eb_stack = VinceEbStack(app, f"{base_stack_name}-{vince_stack_suffix}-eb", vpc=vpc_stack.vpc, rds=vince_rds_stack,
                              secrets=secrets_stack, cert=certs_stack.vince_cert, buckets=buckets_stack,
                              logging=logging_stack, bastion=vpc_stack.bastion,
                              cf_canonical_user_id=cloudfront_stack.cf_canonical_user_id,
                              cf_domain_name=cloudfront_stack.vince_dist_domain_name,
                              send_error_email_lambda=lambda_stack.send_error_email_lambda,
                              env=env)

tag(app, vince_eb_stack)

# VinceComm EB Stack
vincecomm_eb_stack = VinceCommEbStack(app, f"{base_stack_name}-{vincecomm_stack_suffix}-eb", vpc=vpc_stack.vpc,
                                      rds=vince_rds_stack,
                                      secrets=secrets_stack, cert=certs_stack.vincecomm_cert, buckets=buckets_stack,
                                      logging=logging_stack, bastion=vpc_stack.bastion,
                                      cf_canonical_user_id=cloudfront_stack.cf_canonical_user_id,
                                      cf_domain_name=cloudfront_stack.kb_dist_domain_name,
                                      env=env)
tag(app, vincecomm_eb_stack)

# Kb EB Stack
kb_eb_stack = KbEbStack(app, f"{base_stack_name}-{kb_stack_suffix}-eb", vpc=vpc_stack.vpc, rds=vince_rds_stack,
                        secrets=secrets_stack, cert=certs_stack.kb_cert, buckets=buckets_stack, logging=logging_stack,
                        bastion=vpc_stack.bastion,
                        cf_canonical_user_id=cloudfront_stack.cf_canonical_user_id,
                        cf_domain_name=cloudfront_stack.kb_dist_domain_name,
                        env=env)
tag(app, kb_eb_stack)

app.synth()
