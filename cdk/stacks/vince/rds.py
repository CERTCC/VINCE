from aws_cdk import core
from aws_cdk.aws_cloudformation import CustomResource, CustomResourceProvider
from aws_cdk.aws_ec2 import Vpc, InstanceType, InstanceClass, InstanceSize, Port, Protocol, SecurityGroup
from aws_cdk.aws_lambda import Function
from aws_cdk.aws_rds import DatabaseInstance, DatabaseInstanceEngine, DatabaseInstanceFromSnapshot, Credentials

from lib.bastion import Bastion
from stacks.secrets import SecretsStack


class VinceRdsStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, vpc: Vpc, secrets: SecretsStack,
                 create_db_lambda: Function = None,
                 bastion: Bastion = None, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.secrets = secrets
        self.master_secret = self.secrets.vince_master_secret
        multiaz = self.node.try_get_context('vince_rds_multi_az')

        self.db_sg = SecurityGroup(self, 'vince-sg', vpc=vpc)

        master_credentials = Credentials.from_password(
            username='postgres',
            password=self.master_secret.secret_value_from_json('password')
        )
        # RDS Database
        if self.node.try_get_context("vince_rds_from_snapshot"):
            self.rds = DatabaseInstanceFromSnapshot(self, 'postgres-rds',
                                                    engine=DatabaseInstanceEngine.POSTGRES,
                                                    instance_class=InstanceType.of(InstanceClass.BURSTABLE4_GRAVITON,
                                                                                   InstanceSize.MICRO),
                                                    credentials=master_credentials,
                                                    vpc=vpc,
                                                    deletion_protection=True,
                                                    delete_automated_backups=False,
                                                    multi_az=multiaz,
                                                    snapshot_identifier=self.node.try_get_context(
                                                        "vince_rds_snapshot_identifier"),
                                                    security_groups=[self.db_sg]
                                                    )

        else:
            self.rds = DatabaseInstance(self, 'postgres-rds',
                                        engine=DatabaseInstanceEngine.POSTGRES,
                                        instance_type=InstanceType.of(InstanceClass.BURSTABLE4_GRAVITON, InstanceSize.MICRO),
                                        credentials=master_credentials,
                                        vpc=vpc,
                                        deletion_protection=True,
                                        delete_automated_backups=False,
                                        multi_az=multiaz,
                                        security_groups=[self.db_sg]
                                        )

        if create_db_lambda:
            self.create_db(create_db_lambda)

        if bastion:
            self.rds.connections.allow_from(bastion.security_group, Port(protocol=Protocol.TCP,
                                                                         from_port=5432,
                                                                         to_port=5432,
                                                                         string_representation='5432'))

    def create_db(self, fn: Function):
        """
        This function creates a custom resource that will call a lambda function which will initialize the
        vince database
        :param fn: lambda which will initialize the databse
        :return: None
        """

        # It will use these passwords to setup the required databases
        self.master_secret.grant_read(fn.role)
        self.secrets.RDS_COMM.grant_read(fn.role)
        self.secrets.RDS_TRACK.grant_read(fn.role)
        self.secrets.RDS_PUB.grant_read(fn.role)
        self.secrets.VINCE_SUPERUSER.grant_read(fn.role)
        self.secrets.KB_SUPERUSER.grant_read(fn.role)

        # Give lambda function access to RDS
        self.rds.connections.allow_from(fn, Port(protocol=Protocol.TCP, from_port=5432, to_port=5432,
                                                 string_representation='5432'))

        # Create the custom resource
        properties = {
            # 'ServiceToken': fn.function_arn,
            'dburl': self.rds.db_instance_endpoint_address,
            'dbport': self.rds.db_instance_endpoint_port,
            'Master': self.master_secret.secret_arn,
            'Keys': [
                {'name': 'rds_comm', 'value': self.secrets.RDS_COMM.secret_arn},
                {'name': 'rds_track', 'value': self.secrets.RDS_TRACK.secret_arn},
                {'name': 'rds_pub', 'value': self.secrets.RDS_PUB.secret_arn},
            ]
        }
        cr = CustomResource(self, 'create-db-cr', provider=CustomResourceProvider.lambda_(fn), properties=properties)

    @property
    def RDS(self):
        return self.rds

    @property
    def endpoint_address(self):
        return self.rds.db_instance_endpoint_address

    @property
    def endpoint_port(self):
        return self.rds.db_instance_endpoint_port

    @property
    def MASTER_SECRET(self):
        return self.master_secret
   
    @property 
    def db_security_group_id(self):
        return self.db_sg.security_group_id
    
    @property
    def db_security_group(self):
        return self.db_sg        
