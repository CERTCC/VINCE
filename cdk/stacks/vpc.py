from aws_cdk import core
from aws_cdk.aws_ec2 import Vpc

from lib.bastion import Bastion


class VpcStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        self.vpc_construct = Vpc(self, 'vpc', cidr='172.16.0.0/16')

        if self.node.try_get_context('use_bastion'):
            # bastion_image_id = self.node.try_get_context('bastion_image_id')
            #
            # WHY WHY WHY WHY WHY was this ^^^ here? It wasn't used and confuses the world.
            # ALSO, the bastion list image doesn't take region into account so it
            # breaks because it picks AMIs from regions where the VPC might not be. [JDW]

            self.bastion_construct = Bastion(self, 'bastion', vpc=self.vpc_construct,
                                             key_name=self.node.try_get_context('ssh_key_name'),
                                             user_data=self.node.try_get_context('user_data'))

            core.Tags.of(self.bastion_construct).add('Name', f"{self.stack_name}-bastion")

        else:
            self.bastion_construct = None

    @property
    def vpc(self):
        return self.vpc_construct

    @property
    def bastion(self):
        return self.bastion_construct
