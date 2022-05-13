from aws_cdk import core

from aws_cdk.aws_secretsmanager import Secret, SecretStringGenerator

class SecretsStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Todo: Parameterize this
        password_length = 30

        superuser_username = self.node.try_get_context('superuser_username')

        self.rds_pub = Secret(self, 'rds_pub', generate_secret_string=SecretStringGenerator(exclude_punctuation=True,
                                                                                            password_length=password_length,
                                                                                            generate_string_key='password',
                                                                                            secret_string_template='{"username": "vincepub"}'))

        self.rds_comm = Secret(self, 'rds_comm', generate_secret_string=SecretStringGenerator(exclude_punctuation=True,
                                                                                              generate_string_key='password',
                                                                                              password_length=password_length,
                                                                                              secret_string_template='{"username": "vincecord"}'))

        self.rds_track = Secret(self, 'rds_track',
                                generate_secret_string=SecretStringGenerator(exclude_punctuation=True,
                                                                             password_length=password_length,
                                                                             generate_string_key='password',
                                                                             secret_string_template='{"username": "vincetrack"}'))

        self.vince_superuser = Secret(self, 'vince_superuser',
                                      generate_secret_string=SecretStringGenerator(exclude_punctuation=True,
                                                                                   password_length=password_length,
                                                                                   generate_string_key='password',
                                                                                   secret_string_template='{"username": "' + superuser_username + '"}'))

        self.kb_superuser = Secret(self, 'kb_superuser',
                                   generate_secret_string=SecretStringGenerator(exclude_punctuation=True,
                                                                                password_length=password_length,
                                                                                generate_string_key='password',
                                                                                secret_string_template='{"username": "' + superuser_username + '"}'))

        # Master passwords
        self.vince_master_secret = Secret(self, 'vince_rds_master',
                                          generate_secret_string=SecretStringGenerator(exclude_punctuation=True,
                                                                                       password_length=30,
                                                                                       generate_string_key='password',
                                                                                       secret_string_template='{"username": "postgres"}'))

        self.kb_master_secret = Secret(self, 'kb_rds_master',
                                       generate_secret_string=SecretStringGenerator(exclude_punctuation=True,
                                                                                    password_length=30,
                                                                                    generate_string_key='password',
                                                                                    secret_string_template='{"username": "postgres"}'))

    @property
    def RDS_PUB(self):
        return self.rds_pub

    @property
    def RDS_COMM(self):
        return self.rds_comm

    @property
    def RDS_TRACK(self):
        return self.rds_track

    @property
    def VINCE_SUPERUSER(self):
        return self.vince_superuser

    @property
    def KB_SUPERUSER(self):
        return self.kb_superuser

    @property
    def VINCE_MASTER_DB(self):
        return self.vince_master_secret

    @property
    def KB_MASTER_SECRET(self):
        return self.kb_master_secret
