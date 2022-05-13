from aws_cdk import core
from aws_cdk.aws_iam import CanonicalUserPrincipal, PolicyDocument, PolicyStatement, Effect, AnyPrincipal
from aws_cdk.aws_s3 import HttpMethods, CorsRule, Bucket, CfnBucketPolicy


class LimitedPublicBucket(core.Construct):
    def __init__(self, scope: core.Construct, id: str, bucket_name: str,
                 website_index_document: str = None,
                 website_error_document: str = None,
                 cf_canonical_user_id: str = None,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        corsrule = CorsRule(allowed_headers=["Authorization"], allowed_methods=[HttpMethods.GET], allowed_origins=["*"],
                            max_age=3000)
        self.static_bucket = Bucket(self, bucket_name, cors=[corsrule], bucket_name=bucket_name,
                                    website_index_document=website_index_document,
                                    website_error_document=website_error_document,
                                    removal_policy=core.RemovalPolicy.DESTROY)

        ps2 = PolicyStatement(
            actions=["s3:GetObject"],
            effect=Effect.ALLOW,
            principals=[AnyPrincipal()],
            resources=[f"arn:aws:s3:::{self.static_bucket.bucket_name}/*"],
            conditions={"IpAddress": {"aws:SourceIp": self.node.try_get_context('allowed_cidr')}}
        )

        if cf_canonical_user_id:
            # print(f"cf_canonical_user_id: {cf_canonical_user_id} - {bucket_name}")
            ps1 = PolicyStatement(
                actions=["s3:GetObject"],
                effect=Effect.ALLOW,
                principals=[
                    CanonicalUserPrincipal(canonical_user_id=cf_canonical_user_id)],
                resources=[f"arn:aws:s3:::{self.static_bucket.bucket_name}/*"]
            )
            policy_statements = [ps2, ps1]
        else:
            policy_statements = [ps2]

        pd = PolicyDocument(statements=policy_statements)

        CfnBucketPolicy(self, f"{bucket_name}-policy", bucket=self.static_bucket.bucket_name, policy_document=pd)

    @property
    def bucket(self):
        return self.static_bucket
