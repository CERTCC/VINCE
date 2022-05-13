import base64
from operator import itemgetter

import boto3
from aws_cdk import core
from aws_cdk.aws_ec2 import CfnInstance, Vpc, SecurityGroup, Port, Protocol, Peer


class Bastion(core.Construct):
    def __init__(self, scope: core.Construct, id: str, vpc: Vpc, key_name: str, image_id: str = None,
                 instance_type: str = 't2.micro',
                 user_data: str = None, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # This should give us the image id for the newest amazon ami
        # NOTE: needs region or will use user's default region, which might not be correct
        if not image_id:
            image_id = list_amis(self.node.try_get_context('aws_region'))[0]['ImageId']

        self.sg = SecurityGroup(self, 'bastion-sg', vpc=vpc)
        for src_cidr in self.node.try_get_context('allowed_cidr'):
            self.sg.add_ingress_rule(Peer.ipv4(cidr_ip=src_cidr),
                                     Port(protocol=Protocol.TCP, from_port=22, to_port=22, string_representation='ssh'))
            # self.sg.add_egress_rule(Peer.ipv4(cidr_ip='128.0.0.0/8'),
            # Port(protocol=Protocol.ALL, from_port=0, to_port=65535, string_representation='ALL'))

        if user_data:
            with open(user_data, 'r') as f:
                user_data = base64.b64encode(bytes(f.read(), 'utf-8')).decode('utf-8')

        self.bastion = CfnInstance(self, 'bastion',
                                   security_group_ids=[self.sg.security_group_id],
                                   subnet_id=vpc.public_subnets[0].subnet_id,
                                   image_id=image_id,
                                   instance_type=instance_type,
                                   key_name=key_name,
                                   user_data=user_data
                                   )

    @property
    def security_group(self) -> SecurityGroup:
        return self.sg

    @property
    def cfn_instance(self) -> CfnInstance:
        return self.bastion


def list_amis(region):
    client = boto3.client('ec2', region_name=region)
    response = client.describe_images(
        Filters=[
            {
                'Name': 'description',
                'Values': [
                    'Amazon Linux 2*AMI*x86_64 HVM gp2',
                ]
            },
        ],
        Owners=[
            'amazon'
        ]
    )
    # Sort on Creation date Desc
    return sorted(response['Images'], key=itemgetter('CreationDate'), reverse=True)
