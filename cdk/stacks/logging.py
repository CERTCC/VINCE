from aws_cdk import core
from aws_cdk.aws_logs import LogGroup


# from aws_cdk.aws_iam import Policy, Effect, PolicyStatement, AnyPrincipal
# from aws_cdk.aws_iam import Role, ServicePrincipal, ManagedPolicy, CfnInstanceProfile

class FooStack():
    def __init__(self):
        self.foo = "foo"


class LoggingStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.cloudwatch_log_group = LogGroup(self, 'vince-loggroup', log_group_name=self.stack_name)

    @property
    def log_group(self):
        try:
            return self.cloudwatch_log_group
        except AttributeError:
            return None
