from aws_cdk import core

from lib.certificate import CertificateGenerator
from lib.helpers import create_context_from_yaml_app


class CertificateStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.vince_cert_construct = CertificateGenerator(self, 'vince-cert',
                                                         domain_name=self.node.try_get_context('vince_elb_domain_name'),
                                                         region=self.region)

        self.vincecomm_cert_construct = CertificateGenerator(self, 'vincecomm-cert',
                                                         domain_name=self.node.try_get_context('vincecomm_elb_domain_name'),
                                                         region=self.region)

        self.kb_cert_construct = CertificateGenerator(self, 'kb-cert',
                                                      domain_name=self.node.try_get_context('kb_elb_domain_name'),
                                                      region=self.region)

    @property
    def vince_cert(self) -> CertificateGenerator:
        return self.vince_cert_construct

    @property
    def vincecomm_cert(self) -> CertificateGenerator:
        return self.vincecomm_cert_construct

    @property
    def kb_cert(self) -> CertificateGenerator:
        return self.kb_cert_construct


class CertificateStackNoVA(core.Stack):
    """
    These certificates are used by CloudFront. They have to be in the us-east-1 region.
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        san = self.node.try_get_context('kb_cloudfront_alt_domains')
        self.kb_cfcert = CertificateGenerator(self, 'kb-cf-cert',
                                              self.node.try_get_context('kb_cloudfront_domain_name'),
                                              region=self.region,
                                              subject_alternative_names=san,
                                              )

        san = self.node.try_get_context('vince_cloudfront_alt_domains')
        self.vince_cfcert = CertificateGenerator(self, 'vince-cf-cert',
                                              self.node.try_get_context('vince_cloudfront_domain_name'),
                                              region=self.region,
                                              subject_alternative_names=san)

    @property
    def kb_cf_cert(self):
        return self.kb_cfcert

    @property
    def vince_cf_cert(self):
        return self.vince_cfcert
