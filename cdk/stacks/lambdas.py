from aws_cdk import core
from aws_cdk.aws_ec2 import Vpc
from aws_cdk.aws_lambda import Function, AssetCode, Runtime, Version
from aws_cdk.aws_iam import PolicyStatement, Effect, ServicePrincipal, Role


class LambdaStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, vpc: Vpc, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        self.vpc = vpc
        self.create_db_func = None
        self.send_error_email_func = None

    def gen_send_error_email_func(self):
        # lambda function to send error email
        # environment so we an programmatically set some values from cdk app conf
        environment = {
            'EMAIL_FROM': self.node.try_get_context('vince_error_email_sender'),
            'EMAIL_TO': ','.join(self.node.try_get_context('vince_error_email_recipients')),
        }
        if self.node.try_get_context('env') != 'prod':
            environment['SUBJ_PREFIX'] = f"[VINCE-{self.node.try_get_context('env')}]"

        self.send_error_email_func = Function(self, 'send-error-email-lambda',
                                              code=AssetCode('lambda/SendErrorEmail/'),
                                              handler='app.handler',
                                              runtime=Runtime.PYTHON_3_8,
                                              timeout=core.Duration.seconds(10),
                                              environment=environment
                                              )

        # policy so this function can send email
        p = PolicyStatement(
            actions=["ses:SendEmail", "ses:SendRawEmail", "ses:GetSendQuota"],
            effect=Effect.ALLOW,
            resources=['*']
        )
        self.send_error_email_func.add_to_role_policy(p)

    def gen_create_db_lambda(self):
        # Lambda function that will initialize the database
        self.create_db_func = Function(self, 'create-db-lambda',
                                       code=AssetCode('lambda/CreateDatabases/'),
                                       handler='app.handler',
                                       runtime=Runtime.PYTHON_3_6,
                                       timeout=core.Duration.seconds(60),
                                       vpc=self.vpc,
                                       vpc_subnets=self.vpc.private_subnets[0]
                                       )

    @property
    def send_error_email_lambda(self) -> Function:
        return self.send_error_email_func

    @property
    def send_error_email_lambda_arn(self) -> str:
        return self.send_error_email_func.function_arn

    @property
    def create_db_lambda(self) -> Function:
        return self.create_db_func

    @property
    def create_db_lambda_arn(self) -> str:
        return self.create_db_func.function_arn


class LambdaEdgeStack(core.Stack):
    """
    LambdaEdge functions have to be in the us-east-1 region.  Because of this, they get their own stack.
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        p = PolicyStatement(
            principals=[ServicePrincipal('edgelambda.amazonaws.com'), ServicePrincipal('lambda.amazonaws.com')],
            actions=['sts:AssumeRole'],
            effect=Effect.ALLOW)

        self.redirect_func = Function(self, 'cfs3-redirect-lambda',
                                      code=AssetCode('lambda/CfS3RedirectToIndex/'),
                                      handler='app.handler',
                                      runtime=Runtime.PYTHON_3_7,
                                      )

        self.redirect_func.role.assume_role_policy.add_statements(p)
        self.redirect_func_ver = Version(self, 'cfs3-redirect-lambda-version', lambda_=self.redirect_func)

        self.security_header_func = Function(self, 'security-header-lambda',
                                             code=AssetCode('lambda/AddSecurityHeaders/'),
                                             handler='app.handler',
                                             runtime=Runtime.PYTHON_3_7,
                                             )

        self.security_header_func.role.assume_role_policy.add_statements(p)
        self.security_header_func_ver = Version(self, 'security-header-lambda-version',
                                                lambda_=self.security_header_func)

    # @property
    # def redirect_cfs3_lambda(self) -> Function:
    #     return self.redirect_func
    #
    # @property
    # def redirect_cfs3_lambda_arn(self) -> str:
    #     return self.redirect_func.function_arn
    #
    # @property
    # def redirect_cf_s3_lambda_version_arn(self) -> str:
    #     return self.redirect_func_ver.function_arn
