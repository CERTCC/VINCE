from aws_cdk import core
from aws_cdk.aws_ec2 import Vpc, SecurityGroup, Port, Protocol, Peer
from aws_cdk.aws_elasticbeanstalk import CfnApplication, CfnApplicationVersion, CfnEnvironment, CfnConfigurationTemplate
from aws_cdk.aws_iam import Role, ServicePrincipal, ManagedPolicy, CfnInstanceProfile, PolicyStatement, Policy, Effect
from aws_cdk.aws_route53 import CfnRecordSet, AliasRecordTargetConfig
from aws_cdk.aws_sns import Topic
from aws_cdk.aws_sqs import Queue
from aws_cdk.aws_sns_subscriptions import SqsSubscription

from lib.bastion import Bastion
from lib.certificate import CertificateGenerator
from lib.helpers import get_hosted_id, get_eb_app_latest_version
from lib.public_bucket import LimitedPublicBucket
from stacks.vince import VinceRdsStack
from stacks.secrets import SecretsStack
from stacks.buckets import BucketsStack
from stacks.logging import LoggingStack


class KbEbStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, vpc: Vpc, rds: VinceRdsStack, secrets: SecretsStack,
                 cert: CertificateGenerator, buckets: BucketsStack, logging: LoggingStack,
                 cf_canonical_user_id: str = None,
                 cf_domain_name: str = None, bastion: Bastion = None, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        name = f"{self.stack_name}-{self.node.try_get_context('env')}"
        self.vpc = vpc
        self.rds = rds
        self.secrets = secrets
        self.domain_name = self.node.try_get_context('kb_elb_domain_name')
        self.cf_domain_name = cf_domain_name

        # Certificates
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
                                 'AWSElasticBeanstalkWebTier')]
                             )

        self.eb_irole_worker = Role(self, 'eb-irole-worker',
                                    assumed_by=ServicePrincipal('ec2.amazonaws.com'),
                                    managed_policies=[ManagedPolicy.from_aws_managed_policy_name(
                                        'AWSElasticBeanstalkWorkerTier')
                                    ]
                                    )

        # SES
        ses_pstatment = PolicyStatement(
            actions=["ses:SendEmail", "ses:SendRawEmail", "ses:GetSendQuota"],
            effect=Effect.ALLOW,
            resources=['*']
        )

        Policy(self, 'ses-policy', roles=[self.eb_irole], statements=[ses_pstatment])

        # Grant read access to the database passwords
        self.secrets.RDS_PUB.grant_read(self.eb_irole)
        self.secrets.RDS_PUB.grant_read(self.eb_irole_worker)
        self.secrets.KB_SUPERUSER.grant_read(self.eb_irole)
        self.secrets.VINCE_SUPERUSER.grant_read(self.eb_irole)
        self.secrets.VINCE_SUPERUSER.grant_read(self.eb_irole_worker)

        # Logging
        self.logging.cloudwatch_log_group.grant_write(self.eb_irole)
        self.logging.cloudwatch_log_group.grant_write(self.eb_irole_worker)
        self.logging.cloudwatch_log_group.grant(self.eb_irole, 'logs:CreateLogGroup')
        self.logging.cloudwatch_log_group.grant(self.eb_irole, 'logs:DescribeLogGroups')
        self.logging.cloudwatch_log_group.grant(self.eb_irole_worker, 'logs:CreateLogGroup')
        self.logging.cloudwatch_log_group.grant(self.eb_irole_worker, 'logs:DescribeLogGroups')

        # Instance Profiles
        self.eb_iprofile = CfnInstanceProfile(self, 'eb-iprofile',
                                              roles=[self.eb_irole.role_name]
                                              )

        self.eb_iprofile_worker = CfnInstanceProfile(self, 'eb-iprofile-worker',
                                                     roles=[self.eb_irole_worker.role_name]
                                                     )

        # Create buckets
        self.create_buckets(cf_canonical_user_id)

        # NOTE: Queues are manually created and referenced through the deploy context. [jdw, ecoff]
        # Create topics
        # self.create_sns_topics()

        # Create Security groups
        self.create_sg(bastion)


        # publish and error SNS topics
        self.vince_publish_topic = Topic.from_topic_arn(self, 'vince-publish',
                                                        self.node.try_get_context('vince_pub_sns_arn'))

        self.vince_errors_topic = Topic.from_topic_arn(self, 'vince-publish-errors',
                                                       self.node.try_get_context('vince_pub_errors_sns_arn'))

        self.vince_publish_topic.grant_publish(self.eb_irole)
        self.vince_errors_topic.grant_publish(self.eb_irole)
        self.vince_errors_topic.grant_publish(self.eb_irole_worker)

        # SQS queue for Worker
        self.sqs = Queue(self, 'sqs')
        self.buckets.vince_updates_created_notifications.add_subscription(SqsSubscription(self.sqs))
        #self.buckets.vince_updates.add_event_notification(EventType.OBJECT_CREATED, SqsDestination(self.sqs))

        # SQS perms
        self.sqs.grant_consume_messages(self.eb_irole_worker)
        self.sqs.grant_send_messages(self.eb_irole)


        # Web Application
        source_bundle = self.create_bundle()
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



        # Beanstalk Worker
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

        # DNS
        self.update_dns(self.eb_env)

    @property
    def eb_env_config(self) -> list:

        return [
            {'namespace': 'aws:elbv2:listener:default', 'optionName': 'ListenerEnabled', 'value': 'false'},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_REGION",
             "value": core.Aws.REGION},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_DEFAULT_REGION",
             "value": core.Aws.REGION},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_DEPLOYED",
             "value": "true", },
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_SECRET_MANAGER",
             "value": "true"},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "KB_SUPERUSER_AUTH",
             "value": self.secrets.KB_SUPERUSER.secret_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_SUPERUSER_AUTH",
             "value": self.secrets.VINCE_SUPERUSER.secret_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_PUB_DB_HOST",
             "value": self.rds.endpoint_address},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_PUB_DB_PORT",
             "value": self.rds.endpoint_port},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_PUB_AUTH",
             "value": self.secrets.RDS_PUB.secret_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "RDS_HOSTNAME",
             "value": self.rds.endpoint_address},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "RDS_PORT",
             "value": self.rds.endpoint_port},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "KB_PUB_AUTH",
             "value": self.secrets.RDS_PUB.secret_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "LOGLEVEL",
             "value": self.node.try_get_context('loglevel')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_S3_CUSTOM_DOMAIN",
             "value": self.node.try_get_context('kb_cloudfront_domain_name')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_COMM_DOMAIN",
             "value": self.node.try_get_context('kb_cloudfront_domain_name')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_PUB_DOMAIN",
             "value": self.node.try_get_context('kb_cloudfront_domain_name')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_TRACK_DOMAIN",
             "value": self.node.try_get_context('vince_cloudfront_domain_name')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_LOG_GROUP_NAME",
             "value": self.logging.cloudwatch_log_group.log_group_name},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_NAMESPACE",
             "value": self.node.try_get_context('vince_kb_namespace')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_DEV_SYSTEM",
             "value": str(self.node.try_get_context('vince_dev_banner'))},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_LOCATION",
             "value": f"static-{self.stack_name}"},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "GOOGLE_RECAPTCHA_SECRET_KEY",
             "value": self.node.try_get_context('google_recaptcha_secret_key')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "GOOGLE_SITE_KEY",
             "value": self.node.try_get_context('google_site_key')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_ERROR_SNS_ARN",
             "value": self.vince_errors_topic.topic_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "VINCE_TRACK_SNS_ARN",
             "value": self.vince_publish_topic.topic_arn},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "NO_REPLY_EMAIL",
             "value": self.node.try_get_context('vince_no_reply_email_sender')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "REPLY_EMAIL",
             "value": self.node.try_get_context('vince_reply_email_sender')},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "S3_UPDATE_BUCKET_NAME",
             "value": self.buckets.vince_updates.bucket_name},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "S3_KB_SHARED_BUCKET_NAME",
             "value": self.buckets.kb_shared.bucket_name},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "AWS_STORAGE_BUCKET_NAME",
             "value": self.static_bucket.bucket_name},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "S3_INCOMING_REPORTS",
             "value": self.buckets.incoming_reports.bucket_name},
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "SECRET_KEY",
             "value": self.node.try_get_context('django_secret_key')}
        ]

    @property
    def eb_app_config(self) -> list:
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
             'value': str(self.node.try_get_context('kb_eb_asg_min_size')) or '1'},
            {'namespace': 'aws:autoscaling:asg', 'optionName': 'MaxSize',
             'value': str(self.node.try_get_context('kb_eb_asg_max_size')) or '3'},
            #
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'MeasureName', 'value': 'CPUUtilization'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'Unit', 'value': 'Percent'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'UpperThreshold', 'value': '80'},
            {'namespace': 'aws:autoscaling:trigger', 'optionName': 'LowerThreshold', 'value': '40'},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'SecurityGroups',
             'value': self.eb_sg_names},
            {'namespace': 'aws:autoscaling:launchconfiguration', 'optionName': 'InstanceType',
             'value': self.node.try_get_context('kb_eb_app_instance_type')},
            {'namespace': 'aws:autoscaling:updatepolicy:rollingupdate', 'optionName': 'RollingUpdateEnabled',
             'value': "true"},
            {'namespace': 'aws:autoscaling:updatepolicy:rollingupdate', 'optionName': 'RollingUpdateType',
             'value': "Health"},
            {'namespace': 'aws:autoscaling:updatepolicy:rollingupdate', 'optionName': 'MinInstancesInService',
             'value': str(self.node.try_get_context('kb_eb_asg_min_size')) or '1'},
            {'namespace': 'aws:autoscaling:updatepolicy:rollingupdate', 'optionName': 'MaxBatchSize',
             'value': str(self.node.try_get_context('kb_eb_asg_min_size')) or '1'},
            {'namespace': 'aws:elasticbeanstalk:command', 'optionName': 'DeploymentPolicy', 'value': "Rolling"},
            {'namespace': 'aws:ec2:vpc', 'optionName': 'VPCId', 'value': self.vpc.vpc_id},
            {'namespace': 'aws:ec2:vpc', 'optionName': 'Subnets', 'value': private_subnets},
            {'namespace': 'aws:ec2:vpc', 'optionName': 'ELBSubnets', 'value': public_subnets},
            {'namespace': 'aws:elasticbeanstalk:application', 'optionName': 'Application Healthcheck URL',
             'value': '/vuls/'},
            {'namespace': 'aws:elasticbeanstalk:environment:process:default', 'optionName': 'HealthCheckPath',
             'value': '/vuls/'},
            {'namespace': 'aws:elbv2:listener:443', 'optionName': 'Protocol', 'value': 'HTTPS', },
            {'namespace': 'aws:elbv2:listener:443', 'optionName': 'SSLCertificateArns',
             'value': self.cert.certificate_arn}
        ]

    @property
    def eb_app_config_worker(self) -> list:
        private_subnets = ','.join([x.subnet_id for x in self.vpc.private_subnets])

        return [
            {'namespace': 'aws:elasticbeanstalk:sqsd', 'optionName': 'WorkerQueueURL', 'value': self.sqs.queue_url},
            {'namespace': 'aws:elasticbeanstalk:sqsd', 'optionName': 'HttpPath',
             'value': '/kbworker/check-for-updates/'},
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
            {"namespace": "aws:elasticbeanstalk:application:environment", "optionName": "IS_KBWORKER",
             "value": "true"}

        ]

    def create_bundle(self) -> dict:
        return {'bucket': self.node.try_get_context('kb_deployment_bucket'),
                'key': self.node.try_get_context('kb_deployment_key')}

    def create_buckets(self, cf_canonical_user_id):

        # Static Files Bucket
        bname = f"static-bucket-{self.stack_name}"
        b = LimitedPublicBucket(self, bname, bucket_name=bname, cf_canonical_user_id=cf_canonical_user_id,
                                website_index_document='index.html',
                                website_error_document='404.html')
        self.static_bucket = b.bucket
        self.static_bucket.grant_read_write(self.eb_irole)
        self.static_bucket.grant_read_write(self.eb_irole_worker)

        # Update bucket for vince-updater
        #self.updates_bucket = Bucket(self, 'update-bucket', removal_policy=core.RemovalPolicy.DESTROY)
        self.buckets.vince_updates.grant_read_write(self.eb_irole)
        self.buckets.vince_updates.grant_read(self.eb_irole_worker)


        # incoming reports bucket
        #self.incoming_reports_bucket = Bucket.from_bucket_arn(self, 'incoming-reports-bucket',
        #                                                      self.node.try_get_context('incoming_reports_bucket_arn'))
        self.buckets.incoming_reports.grant_read_write(self.eb_irole)
        self.buckets.incoming_reports.grant_read_write(self.eb_irole_worker)

        # kb shared bucket for artifacts for published reports
        self.buckets.kb_shared.grant_read_write(self.eb_irole_worker)

    def create_sns_topics(self):
        # NOTE: None of these are used, so we're not going to create them here. The
        #       queues that are used are manually created and referenced by arn
        #       in the deployment context. [jdw, ecoff]

        # VINCE_ERROR_SNS_ARN - Error queue for application
        # self.error_topic = Topic(self, 'error_topic')
        # self.error_topic.grant_publish(self.eb_irole)

        # VINCE_TRACK_SNS_ARN - used for sending new VDF submission notifications to vince_track
        # self.vince_track_vrf_notification = Topic(self, 'track-vrf-notification')
        # self.vince_track_vrf_notification.grant_publish(self.eb_irole)

        # VINCE_DHSVDP_SNS_ARN
        # self.dhs_vrf_notification = Topic(self, 'dhs-vrf-notification')
        # self.dhs_vrf_notification.grant_publish(self.eb_irole)

        pass

    def update_dns(self, env: CfnEnvironment):
        # DNS Record for the application
        a_target = AliasRecordTargetConfig(dns_name=env.attr_endpoint_url,
                                           hosted_zone_id=self.node.try_get_context('elb_hosted_zone_id'))
        CfnRecordSet(self, 'elb-rs',
                     name=self.domain_name,
                     type='A',
                     hosted_zone_id=get_hosted_id(self.domain_name),
                     alias_target={
                         'dnsName': env.attr_endpoint_url,
                         'hostedZoneId': self.node.try_get_context('elb_hosted_zone_id')
                     }
                     )

        if self.cf_domain_name and self.node.try_get_context('kb_add_dns_rr'):
            # Hosted Zone Id for Cloudfront is hardcoded
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html#cfn-route53-aliastarget-hostedzoneid

            kb_cf_domain_name = self.node.try_get_context('kb_cloudfront_domain_name')
            CfnRecordSet(self, 'cf-rs',
                         name=kb_cf_domain_name,
                         type='A',
                         hosted_zone_id=get_hosted_id(self.domain_name),
                         alias_target={
                             'dnsName': self.cf_domain_name,
                             'hostedZoneId': 'Z2FDTNDATAQYW2'

                         }
                         )

    def create_environment(self, name: str, config_template_options: list, ) -> CfnEnvironment:
        eb_config_template = CfnConfigurationTemplate(self, f"{name}",
                                                      application_name=self.eb_app.application_name,
                                                      solution_stack_name=self.node.try_get_context(
                                                          'solution_stack'),
                                                      option_settings=config_template_options
                                                      )

        return CfnEnvironment(self, f"{name}-ct",
                              environment_name=name,
                              application_name=self.eb_app.application_name,
                              template_name=eb_config_template.ref,
                              version_label=self.eb_app_version_label
                              )

    def create_sg(self, bastion):
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
