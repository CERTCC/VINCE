from aws_cdk import core
from aws_cdk.aws_s3 import Bucket
from aws_cdk.aws_sns import Topic
from aws_cdk.aws_s3 import EventType
from aws_cdk.aws_s3_notifications import SnsDestination
from aws_cdk.aws_iam import Policy, Effect, PolicyStatement, AnyPrincipal
from aws_cdk.aws_iam import Role, ServicePrincipal, ManagedPolicy, CfnInstanceProfile
from lib.public_bucket import LimitedPublicBucket


class BucketsStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.incoming_reports_bucket = Bucket(self, 'incoming-reports', removal_policy=core.RemovalPolicy.RETAIN)
        self.vince_updates_bucket = Bucket(self, 'vince-updates', removal_policy=core.RemovalPolicy.RETAIN)
        self.vincecomm_shared_bucket = Bucket(self, 'vincecomm-shared', removal_policy=core.RemovalPolicy.RETAIN)
        self.kb_shared_bucket = Bucket(self, 'kb-shared', removal_policy=core.RemovalPolicy.RETAIN)

        # SNS topics for bucket events
        self.vince_updates_topic = Topic(self, 's3_vince_updates_created_topic')

        # set up events
        self.vince_updates_bucket.add_event_notification(EventType.OBJECT_CREATED,
                                                         SnsDestination(self.vince_updates_topic))

        # Policy magic so we can actually publish to the SNS topic:
        sns_pstatement = PolicyStatement(
            actions=["sns:Publish"],
            effect=Effect.ALLOW,
            resources=[self.vince_updates_topic.topic_arn],
            conditions={'ArnLike': {'aws:SourceArn': self.vince_updates_bucket.bucket_arn}},
            principals=[AnyPrincipal()]
        )
        self.vince_updates_topic.add_to_resource_policy(sns_pstatement)

        # Policy(self, 's3-events-policy', statements=[sns_pstatment])

    @property
    def incoming_reports(self):
        try:
            return self.incoming_reports_bucket
        except AttributeError:
            return None

    @property
    def vince_updates(self):
        try:
            return self.vince_updates_bucket
        except AttributeError:
            return None

    @property
    def vincecomm_shared(self):
        try:
            return self.vincecomm_shared_bucket
        except AttributeError:
            return None

    @property
    def kb_shared(self):
        try:
            return self.kb_shared_bucket
        except AttributeError:
            return None

    @property
    def vince_updates_created_notifications(self):
        try:
            return self.vince_updates_topic
        except AttributeError:
            return None

