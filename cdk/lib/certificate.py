from aws_cdk import core
from aws_cdk.aws_cloudformation import CustomResourceProvider, CustomResource
from aws_cdk.aws_certificatemanager import Certificate, CertificateProps, CertificateValidation
from aws_cdk.aws_lambda import Function
from aws_cdk.aws_route53 import CfnRecordSet, HostedZone

from lib.helpers import get_lambda_arn, get_hosted_id


class CertificateGenerator(core.Construct):
    """
    This construct uses binxio-cfn-certificate-provider to generate certificates

    https://github.com/binxio/cfn-certificate-provider
    """

    def __init__(self, scope: core.Construct, id: str, domain_name: str, region: str,
                 subject_alternative_names: list = [], **kwargs) -> None:
        """
        :param scope: This construct's scope
        :param id: This construct's id
        :param domain_name: Domain name for the certificate
        :param cert_provider_lambda_arn: ARN of the bixio-cfn-certificate-provider lambda function
        :param hosted_zone_id: Hosted zone id for the certificate: https://docs.aws.amazon.com/general/latest/gr/rande.html#elb_region
        :param kwargs:
        """
        super().__init__(scope, id, **kwargs)

        self.certs_use_binxio = self.node.try_get_context('certs_use_binxio')
        self.hosted_zone_id = get_hosted_id(domain_name)

        # if we are using binxio, do a whole bunch of stuff to make it work
        if self.certs_use_binxio:
            cert_provider_lambda_arn = get_lambda_arn(region, 'binxio-cfn-certificate-provider')
            self.fn = Function.from_function_arn(self, 'cert-provider-lambda', function_arn=cert_provider_lambda_arn)

            properties = {
                'DomainName': domain_name,
                'ValidationMethod': 'DNS'
            }
            if subject_alternative_names:
                properties['SubjectAlternativeNames'] = subject_alternative_names

            # this condition is redundant.
            if self.certs_use_binxio:
                self.cr = CustomResource(self, 'certificate', provider=CustomResourceProvider.lambda_(self.fn),
                                         properties=properties,
                                         resource_type="Custom::Certificate")

                properties = {'CertificateArn': self.cr.ref}
                self.cr_issue_cert = CustomResource(self, 'issue-cert', provider=CustomResourceProvider.lambda_(self.fn),
                                                    properties=properties, resource_type="Custom::IssuedCertificate")

                # Create DNS validation records for the certificate
                self.create_dns_validation_record(domain_name, self.cr.ref)
                for domain in subject_alternative_names:
                    self.create_dns_validation_record(domain, self.cr.ref)
        else:
            # not using binxio, so use the AWS stack method (https://aws.amazon.com/blogs/security/how-to-use-aws-certificate-manager-with-aws-cloudformation/)
            # LOOK HOW MUCH EASIER THIS IS!!!!!!  [jdw]
            # Note: this needs the actual HostedZone object to pass to from_dns, so get it using the id we have
            hosted_zone = HostedZone.from_hosted_zone_id(self, 'hosted_zone', self.hosted_zone_id)
            self.cr = Certificate(self, 'certificate',
                                  domain_name=domain_name,
                                  subject_alternative_names=subject_alternative_names,
                                  validation=CertificateValidation.from_dns(hosted_zone))

    @property
    def certificate(self):
        return self.cr

    @property
    def certificate_arn(self):
        if self.certs_use_binxio:
            return self.cr.ref
        return self.cr.certificate_arn

    # not sure what this is used for.. I do not see any current usages. It
    # will only be valid for certificates created with the binxio lambda
    # stack, so return None if we didn't use binxio, and I guess hope for
    # the best? [jdw]
    @property
    def issued_certificate(self):
        if self.certs_use_binxio:
            return self.cr_issue_cert
        return None

    def create_dns_validation_record(self, domain_name, cert_arn):
        properties = {
            'CertificateArn': cert_arn,
            'DomainName': domain_name
        }

        cr_cert_dns_record = CustomResource(self, f"cert-dns-rec-{domain_name}",
                                            provider=CustomResourceProvider.lambda_(self.fn),
                                            properties=properties, resource_type="Custom::CertificateDNSRecord")

        CfnRecordSet(self, f"record-set-{domain_name}",
                     name=core.Token.as_string(cr_cert_dns_record.get_att('Name')),
                     type=core.Token.as_string(cr_cert_dns_record.get_att('Type')),
                     ttl="60",
                     weight=1,
                     set_identifier=self.cr.ref,
                     resource_records=[core.Token.as_string(cr_cert_dns_record.get_att('Value'))],
                     hosted_zone_id=self.hosted_zone_id
                     )
