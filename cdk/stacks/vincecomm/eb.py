from aws_cdk import core
from aws_cdk.aws_ec2 import Vpc, SecurityGroup, Port, Protocol, Peer
from aws_cdk.aws_elasticbeanstalk import CfnApplication, CfnApplicationVersion, CfnEnvironment, CfnConfigurationTemplate
from aws_cdk.aws_iam import Policy, Effect, PolicyStatement
from aws_cdk.aws_iam import Role, ServicePrincipal, ManagedPolicy, CfnInstanceProfile
from aws_cdk.aws_route53 import CfnRecordSet, AliasRecordTargetConfig, ARecord, RecordTarget, HostedZone
from aws_cdk.aws_route53_targets import LoadBalancerTarget
from aws_cdk.aws_s3 import Bucket
from aws_cdk.aws_sns import Topic
from aws_cdk.aws_sns_subscriptions import SqsSubscription
from aws_cdk.aws_sqs import Queue

from lib.bastion import Bastion
from lib.certificate import CertificateGenerator
from lib.helpers import get_hosted_id, get_eb_app_latest_version
from lib.public_bucket import LimitedPublicBucket
from stacks.secrets import SecretsStack
from stacks.buckets import BucketsStack
from stacks.logging import LoggingStack
from stacks.vince import VinceRdsStack


class VinceCommEbStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, vpc: Vpc, rds: VinceRdsStack, secrets: SecretsStack,
                 cert: CertificateGenerator, buckets: BucketsStack, logging: LoggingStack,
                 cf_canonical_user_id: str = None,
                 cf_domain_name: str = None, bastion: Bastion = None, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        source_bundle = self.create_bundle()
        name = f"{self.stack_name}-{self.node.try_get_context('env')}"
        self.vpc = vpc
        self.rds = rds
        self.secrets = secrets
        self.domain_name = self.node.try_get_context('vincecomm_elb_domain_name')
        self.cf_domain_name = cf_domain_name

        # Generate Certificates
        self.cert = cert

        # Shared buckets
        self.buckets = buckets

        # Logging
        self.logging = logging

        # Roles and Polices
        self.eb_srole = Role(self, 'eb-srole',
                             assumed_by=ServicePrincipal('elasticbeanstalk.amazonaws.com'),
                             managed_policies=[ManagedPolicy.from_aws_managed_policy_name(
                                 'service-role/AWSElasticBeanstalkEnhancedHealth'),
                                 ManagedPolicy.from_aws_managed_policy_name(
                                     'service-role/AWSElasticBeanstalkService')
                             ]
                             )

        self.eb_irole = Role(self, 'eb-irole',
                             assumed_by=ServicePrincipal('ec2.amazonaws.com'),
                             managed_policies=[ManagedPolicy.from_aws_managed_policy_name(
                                 'AWSElasticBeanstalkWebTier')
                             ]
                             )

        self.eb_irole_worker = Role(self, 'eb-irole-worker',
                                    assumed_by=ServicePrincipal('ec2.amazonaws.com'),
                                    managed_policies=[ManagedPolicy.from_aws_managed_policy_name(
                                        'AWSElasticBeanstalkWorkerTier')
                                    ]
                                    )

        # Grant read access to the database passwords
        self.secrets.RDS_COMM.grant_read(self.eb_irole)
        self.secrets.RDS_COMM.grant_read(self.eb_irole_worker)
        # self.secrets.RDS_TRACK.grant_read(self.eb_irole)
        self.secrets.RDS_PUB.grant_read(self.eb_irole)
        self.secrets.RDS_PUB.grant_read(self.eb_irole_worker)
        self.secrets.VINCE_SUPERUSER.grant_read(self.eb_irole)
        self.secrets.VINCE_SUPERUSER.grant_read(self.eb_irole_worker)

        # SES
        ses_pstatment = PolicyStatement(
            actions=["ses:SendEmail", "ses:SendRawEmail", "ses:GetSendQuota"],
            effect=Effect.ALLOW,
            resources=['*']
        )

        Policy(self, 'ses-policy', roles=[self.eb_irole, self.eb_irole_worker], statements=[ses_pstatment])

        # Cognito
        cognito_pstatement_list = PolicyStatement(
            actions=['cognito-idp:DescribeUserPoolDomain', 'cognito-idp:ListUserPools'],
            effect=Effect.ALLOW, resources=['*'])

        cognito_pstatement_use = PolicyStatement(actions=['cognito-idp:*'],
                                                 effect=Effect.ALLOW,
                                                 resources=[self.node.try_get_context('cognito_user_pool_arn')])

        Policy(self, 'cognito-policy', roles=[self.eb_irole],
               statements=[cognito_pstatement_list, cognito_pstatement_use])

        # Logging
        self.logging.cloudwatch_log_group.grant_write(self.eb_irole)
        self.logging.cloudwatch_log_group.grant_write(self.eb_irole_worker)
        self.logging.cloudwatch_log_group.grant(self.eb_irole, 'logs:CreateLogGroup')
        self.logging.cloudwatch_log_group.grant(self.eb_irole, 'logs:DescribeLogGroups')
        self.logging.cloudwatch_log_group.grant(self.eb_irole_worker, 'logs:CreateLogGroup')
        self.logging.cloudwatch_log_group.grant(self.eb_irole_worker, 'logs:DescribeLogGroups')

        # Profiles
        self.eb_iprofile = CfnInstanceProfile(self, 'eb-iprofile',
                                              roles=[self.eb_irole.role_name]
                                              )

        self.eb_iprofile_worker = CfnInstanceProfile(self, 'eb-iprofile-worker',
                                                     roles=[self.eb_irole_worker.role_name]
                                                     )

        # Security Groups
        self.eb_sg = SecurityGroup(self, 'eb-sg', vpc=self.vpc)
        for src_cidr in self.node.try_get_context("allowed_cidr"):
            self.eb_sg.add_ingress_rule(Peer.ipv4(cidr_ip=src_cidr),
                                        Port(protocol=Protocol.TCP, from_port=443, to_port=443,
                                             string_representation='https'))

        rds_sg = SecurityGroup.from_security_group_id(self, 'rds_sg', security_group_id=self.rds.db_security_group_id)
        rds_sg.connections.allow_from(self.eb_sg, Port(protocol=Protocol.TCP,
                                                       from_port=5432,
                                                       to_port=5432,
                                                       string_representation='5432'))

        # Allow bastion if we are using one
        if bastion:
            self.eb_sg.connections.allow_from(bastion.security_group, Port(protocol=Protocol.TCP,
                                                                           from_port=22,
                                                                           to_port=22,
                                                                           string_representation='ssh'))

        # Create cloudfront security groups
        # Note: Currently we need two because there are more prefixes than will fit in one (50 max)
        # This tag allows CloudFront Ipaddress to access this security group on http/https
        # This security group will be updated when new CloudFront IPs are added
        # See: https://aws.amazon.com/blogs/security/how-to-automatically-update-your-security-groups-for-amazon-cloudfront-and-aws-waf-by-using-aws-lambda/
        self.eb_sg_cf_even = SecurityGroup(self, 'eb-sg-cf-even', vpc=self.vpc)
        core.Tags.of(self.eb_sg_cf_even).add(key='Name', value='cloudfront_g')
        core.Tags.of(self.eb_sg_cf_even).add(key='AutoUpdate', value='true')
        core.Tags.of(self.eb_sg_cf_even).add(key='Protocol', value='https')
        core.Tags.of(self.eb_sg_cf_even).add(key='Even', value='true')

        self.eb_sg_cf_odd = SecurityGroup(self, 'eb-sg-cf-odd', vpc=self.vpc)
        core.Tags.of(self.eb_sg_cf_odd).add(key='Name', value='cloudfront_g')
        core.Tags.of(self.eb_sg_cf_odd).add(key='AutoUpdate', value='true')
        core.Tags.of(self.eb_sg_cf_odd).add(key='Protocol', value='https')
        core.Tags.of(self.eb_sg_cf_odd).add(key='Odd', value='true')

        # create list of security group names
        self.eb_sg_names = ','.join([
            self.eb_sg.security_group_name,
            self.eb_sg_cf_even.security_group_name,
            self.eb_sg_cf_odd.security_group_name
        ])

        # Incoming reports bucket
        self.buckets.incoming_reports.grant_write(self.eb_irole)

        # Shared vince bucket for uploads
        self.buckets.vincecomm_shared.grant_read_write(self.eb_irole)
        self.buckets.vincecomm_shared.grant_read_write(self.eb_irole_worker)

        # Static Files Bucket
        bname = f"static-bucket-{self.stack_name}"
        b = LimitedPublicBucket(self, bname, bucket_name=bname,
                                cf_canonical_user_id=cf_canonical_user_id)
        self.static_bucket = b.bucket
        self.static_bucket.grant_read_write(self.eb_irole)
        self.static_bucket.grant_read_write(self.eb_irole_worker)

        # publish and error SNS topics
        self.vince_publish_topic = Topic.from_topic_arn(self, 'vince-publish',
                                                        self.node.try_get_context('vince_pub_sns_arn'))
        self.vince_errors_topic = Topic.from_topic_arn(self, 'vince-publish-errors',
                                                       self.node.try_get_context('vince_pub_errors_sns_arn'))
        self.vince_email_topic = Topic.from_topic_arn(self, 'vince-email',
                                                      self.node.try_get_context('vince_email_sns_arn'))

        self.vince_errors_topic.grant_publish(self.eb_irole)
        self.vince_errors_topic.grant_publish(self.eb_irole_worker)
        self.vince_publish_topic.grant_publish(self.eb_irole)

        # internal SNS for app-to-worker traffic
        self.vince_comm_sns_topic = Topic(self, 'vince-comm-sns')
        self.vince_comm_sns_topic.grant_publish(self.eb_irole)

        # SQS queue for worker
        self.sqs = Queue(self, 'sqs')
        self.vince_comm_sns_topic.add_subscription(SqsSubscription(self.sqs))

        # SQS perms
        self.sqs.grant_consume_messages(self.eb_irole_worker)
        self.sqs.grant_send_messages(self.eb_irole)

        # Application
        self.eb_app = CfnApplication(self, 'eb-app', application_name=name)

        # See if we have a version already out there
        self.eb_app_version_label = get_eb_app_latest_version(self.eb_app.application_name,
                                                              self.node.try_get_context('aws_region'))
        if not self.eb_app_version_label:
            self.eb_app_version = CfnApplicationVersion(self, 'eb-app-version',
                                                        application_name=self.eb_app.application_name,
                                                        source_bundle={'s3Bucket': source_bundle['bucket'],
                                                                       's3Key': source_bundle['key']}
                                                        )
            self.eb_app_version.add_depends_on(self.eb_app)
            self.eb_app_version_label = self.eb_app_version.ref

        self.eb_config_template = CfnConfigurationTemplate(self, 'eb-config-temp',
                                                           application_name=self.eb_app.application_name,
                                                           solution_stack_name=self.node.try_get_context(
                                                               'solution_stack'),
                                                           option_settings=self.eb_app_config + self.eb_env_config
                                                           )

        self.eb_env = CfnEnvironment(self, 'eb-env',
                                     environment_name=name,
                                     application_name=self.eb_app.application_name,
                                     template_name=self.eb_config_template.ref,
                                     version_label=self.eb_app_version_label
                                     )

        # Beanstalk worker
        self.eb_config_template_worker = CfnConfigurationTemplate(self, 'eb-config-temp-worker',
                                                                  application_name=self.eb_app.application_name,
                                                                  solution_stack_name=self.node.try_get_context(
                                                                      'solution_stack'),
                                                                  option_settings=self.eb_app_config_worker + self.eb_env_config
                                                                  )

        self.eb_env_worker = CfnEnvironment(self, 'eb-env-worker',
                                            environment_name=f"{name}-wrk",
                                            application_name=self.eb_app.application_name,
                                            template_name=self.eb_config_template_worker.ref,
                                            version_label=self.eb_app_version_label,
                                            tier={
                                                'type': 'SQS/HTTP',
                                                'name': 'Worker',
                                            }
                                            )

        # DNS Record for the application
        record_set = CfnRecordSet(self, 'record-set',
                                  name=self.domain_name,
                                  type='A',
                                  hosted_zone_id=get_hosted_id(self.domain_name),
                                  alias_target={
                                      'dnsName': self.eb_env.attr_endpoint_url,
                                      'hostedZoneId': self.node.try_get_context('elb_hosted_zone_id')
                                  }
                                  )

    @property
    def eb_env_config(self):
        return [
            {'namespace': 'aws:elbv2:listener:default', 'optionName': 'ListenerEnabled', 'value': 'false'},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_REGION",
             "value": core.Aws.REGION},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_DEFAULT_REGION",
             "value": core.Aws.REGION},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_DEPLOYED",
             "value": "true", },
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_STORAGE_BUCKET_NAME",
             "value": f"{self.static_bucket.bucket_name}"},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_SECRET_MANAGER",
             "value": "true"},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_SUPERUSER_AUTH",
             "value": self.secrets.VINCE_SUPERUSER.secret_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_TRACK_DB_HOST",
             "value": self.rds.endpoint_address},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_TRACK_DB_PORT",
             "value": self.rds.endpoint_port},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_TRACK_AUTH",
             "value": self.secrets.RDS_TRACK.secret_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_PUB_DB_HOST",
             "value": self.rds.endpoint_address},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_PUB_DB_PORT",
             "value": self.rds.endpoint_port},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_PUB_AUTH",
             "value": self.secrets.RDS_PUB.secret_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_COMM_DOMAIN",
             "value": self.node.try_get_context('kb_cloudfront_domain_name')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_PUB_DOMAIN",
             "value": self.node.try_get_context('kb_cloudfront_domain_name')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_TRACK_DOMAIN",
             "value": self.node.try_get_context('vince_cloudfront_domain_name')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_COMM_DB_HOST",
             "value": self.rds.endpoint_address},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_COMM_DB_PORT",
             "value": self.rds.endpoint_port},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_COMM_AUTH",
             "value": self.secrets.RDS_COMM.secret_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_ERROR_SNS_ARN",
             "value": self.vince_errors_topic.topic_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_TRACK_SNS_ARN",
             "value": self.vince_publish_topic.topic_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_COMM_SNS_ARN",
             "value": self.vince_comm_sns_topic.topic_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_LOG_GROUP_NAME",
             "value": self.logging.cloudwatch_log_group.log_group_name},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "NO_REPLY_EMAIL",
             "value": self.node.try_get_context('vince_no_reply_email_sender')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "REPLY_EMAIL",
             "value": self.node.try_get_context('vince_reply_email_sender')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_NAMESPACE",
             "value": self.node.try_get_context('vince_comm_namespace')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_DEV_SYSTEM",
             "value": str(self.node.try_get_context('vince_dev_banner'))},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "GOOGLE_RECAPTCHA_SECRET_KEY",
             "value": self.node.try_get_context('google_recaptcha_secret_key')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "GOOGLE_SITE_KEY",
             "value": self.node.try_get_context('google_site_key')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_COGNITO_USER_POOL_ID",
             "value": self.node.try_get_context('cognito_user_pool_id')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_COGNITO_APP_ID",
             "value": self.node.try_get_context('cognito_app_id')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_COGNITO_USER_POOL_ARN",
             "value": self.node.try_get_context('cognito_user_pool_arn')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_COGNITO_REGION",
             "value": self.node.try_get_context('congito_region')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_COGNITO_ADMIN_GROUP",
             "value": self.node.try_get_context('cognito_admin_group')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "SERVER_NAME",
             "value": f"https://{self.node.try_get_context('kb_cloudfront_domain_name')}"},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "LOGLEVEL",
             "value": self.node.try_get_context('loglevel')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_S3_CUSTOM_DOMAIN",
             "value": f"{self.node.try_get_context('kb_cloudfront_domain_name')}"},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_LOCATION",
             "value": f"vince/static-{self.stack_name}/vince"},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_UPDATE_QUEUE",
             "value": self.sqs.queue_url},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "PRIVATE_BUCKET_NAME",
             "value": self.buckets.vincecomm_shared.bucket_name},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "S3_INCOMING_REPORTS",
             "value": self.buckets.incoming_reports.bucket_name},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "SECRET_KEY",
             "value": self.node.try_get_context('django_secret_key')}

        ]

    @property
    def eb_app_config_worker(self):
        private_subnets = ','.join([x.subnet_id for x in self.vpc.private_subnets])

        return [
            {'namespace': 'aws:elasticbeanstalk:sqsd', 'optionName': 'WorkerQueueURL', 'value': self.sqs.queue_url},
            {'namespace': 'aws:elasticbeanstalk:sqsd', 'optionName': 'HttpPath',
             'value': '/vcworker/ingest/'},
            {'namespace': 'aws:elasticbeanstalk:sqsd', 'optionName': 'InactivityTimeout', 'value': '599'},
            {'namespace': 'aws:elasticbeanstalk:sqsd', 'optionName': 'VisibilityTimeout', 'value': '600'},
            {'namespace': 'aws:elasticbeanstalk:environment', 'optionName': 'EnvironmentType',
             'value': 'SingleInstance'},
            {'namespace': 'aws:elasticbeanstalk:environment', 'optionName': 'ServiceRole',
             'value': self.eb_srole.role_name},
            {'namespace': 'aws:elasticbeanstalk:healthreporting:system', 'optionName': 'SystemType',
             'value': 'enhanced'},
            {'namespace': 'aws:elasticbeanstalk:cloudwatch:logs', 'optionName': 'StreamLogs', 'value': 'true'},
            {'namespace': 'aws:elasticbeanstalk:cloudwatch:logs:health', 'optionName': 'HealthStreamingEnabled',
             'value': 'true'},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'EC2KeyName',
             'value': self.node.try_get_context('ssh_key_name')},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'IamInstanceProfile',
             'value': self.eb_iprofile_worker.ref},
            # Todo: paramterize these
            {'namespace': 'aws:autoscaling:asg', 'optionName': 'MinSize', 'value': '1'},
            {'namespace': 'aws:autoscaling:asg', 'optionName': 'MaxSize', 'value': '3'},
            #
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'MeasureName', 'value': 'CPUUtilization'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'Unit', 'value': 'Percent'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'UpperThreshold', 'value': '80'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'LowerThreshold', 'value': '40'},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'SecurityGroups',
             'value': self.eb_sg_names},
            {'namespace': 'aws:elasticbeanstalk:command', 'optionName': 'DeploymentPolicy', 'value': "Rolling"},
            {'namespace': 'aws:ec2:vpc', 'optionName': 'VPCId', 'value': self.vpc.vpc_id},
            {'namespace': 'aws:ec2:vpc', 'optionName': 'Subnets', 'value': private_subnets},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "IS_ELASTICBEANSTALK_WORKER",
             "value": "true"},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "IS_VCWORKER",
             "value": "true"}

        ]

    @property
    def eb_app_config(self):
        private_subnets = ','.join([x.subnet_id for x in self.vpc.private_subnets])
        public_subnets = ','.join([x.subnet_id for x in self.vpc.public_subnets])

        return [
            {'namespace': 'aws:elasticbeanstalk:environment', 'optionName': 'EnvironmentType', 'value': 'LoadBalanced'},
            {'namespace': 'aws:elasticbeanstalk:environment', 'optionName': 'LoadBalancerType', 'value': 'application'},
            {'namespace': 'aws:elasticbeanstalk:environment', 'optionName': 'ServiceRole',
             'value': self.eb_srole.role_name},
            {'namespace': 'aws:elasticbeanstalk:healthreporting:system', 'optionName': 'SystemType',
             'value': 'enhanced'},
            {'namespace': 'aws:elasticbeanstalk:cloudwatch:logs', 'optionName': 'StreamLogs', 'value': 'true'},
            {'namespace': 'aws:elasticbeanstalk:cloudwatch:logs:health', 'optionName': 'HealthStreamingEnabled',
             'value': 'true'},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'EC2KeyName',
             'value': self.node.try_get_context('ssh_key_name')},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'IamInstanceProfile',
             'value': self.eb_iprofile.ref},
            # Todo: paramterize these
            {'namespace': 'aws:autoscaling:asg', 'optionName': 'MinSize',
             'value': str(self.node.try_get_context('vince_eb_asg_min_size')) or '1'},
            {'namespace': 'aws:autoscaling:asg', 'optionName': 'MaxSize',
             'value': str(self.node.try_get_context('vince_eb_asg_max_size')) or '3'},
            #
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'MeasureName', 'value': 'CPUUtilization'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'Unit', 'value': 'Percent'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'UpperThreshold', 'value': '80'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'LowerThreshold', 'value': '40'},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'SecurityGroups',
             'value': self.eb_sg_names},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'InstanceType',
             'value': self.node.try_get_context('vincecomm_eb_app_instance_type')},
            {'namespace': 'aws:autoscaling:updatepolicy:rollingupdate', 'optionName': 'RollingUpdateEnabled',
             'value': "true"},
            {'namespace': 'aws:autoscaling:updatepolicy:rollingupdate', 'optionName': 'RollingUpdateType',
             'value': "Health"},
            {'namespace': 'aws:autoscaling:updatepolicy:rollingupdate', 'optionName': 'MinInstancesInService',
             'value': str(self.node.try_get_context('vince_eb_asg_min_size')) or '1'},
            {'namespace': 'aws:autoscaling:updatepolicy:rollingupdate', 'optionName': 'MaxBatchSize',
             'value': str(self.node.try_get_context('vince_eb_asg_min_size')) or '1'},
            {'namespace': 'aws:elasticbeanstalk:command', 'optionName': 'DeploymentPolicy', 'value': "Rolling"},
            {'namespace': 'aws:ec2:vpc', 'optionName': 'VPCId', 'value': self.vpc.vpc_id},
            {'namespace': 'aws:ec2:vpc', 'optionName': 'Subnets', 'value': private_subnets},
            {'namespace': 'aws:ec2:vpc', 'optionName': 'ELBSubnets', 'value': public_subnets},
            {'namespace': 'aws:elasticbeanstalk:application', 'optionName': 'Application Healthcheck URL',
             'value': '/vince/'},
            {'namespace': 'aws:elasticbeanstalk:environment:process:default', 'optionName': 'HealthCheckPath',
             'value': '/vince/'},
            {'namespace': 'aws:elbv2:listener:443', 'optionName': 'Protocol', 'value': 'HTTPS', },
            {'namespace': 'aws:elbv2:listener:443', 'optionName': 'SSLCertificateArns',
             'value': self.cert.certificate_arn}
        ]

    def create_bundle(self) -> dict:
        return {'bucket': self.node.try_get_context('vince_deployment_bucket'),
                'key': self.node.try_get_context('vince_deployment_key')}
