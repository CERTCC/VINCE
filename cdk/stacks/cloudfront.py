from aws_cdk import core
from aws_cdk.aws_cloudfront import CustomOriginConfig, CloudFrontWebDistribution, AliasConfiguration, \
    OriginProtocolPolicy, SourceConfiguration, Behavior, CloudFrontAllowedMethods, S3OriginConfig, LambdaEdgeEventType, \
    LambdaFunctionAssociation, CfnDistribution, OriginAccessIdentity
from aws_cdk.aws_lambda import Version
from aws_cdk.aws_s3 import Bucket
from lib.helpers import get_cert_arn, get_lambda_arn, get_lambda_latest_version_num


class CloudfrontStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, create_kb_dist: bool = False, create_vince_dist: bool = False,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        self.s3_origin_access_identity = OriginAccessIdentity.from_origin_access_identity_name(self, id,
                                                                                               self.node.try_get_context(
                                                                                                   'cloudfront_origin_access'))

    @property
    def kb_dist_id(self) -> str:
        try:
            return self.kb_dist.distribution_id
        except AttributeError:
            return None

    @property
    def kb_dist_domain_name(self) -> str:
        try:
            return self.kb_dist.domain_name
        except AttributeError:
            return None

    @property
    def vince_dist_id(self) -> str:
        try:
            return self.vince_dist.distribution_id
        except AttributeError:
            return None

    @property
    def vince_dist_domain_name(self) -> str:
        try:
            return self.vince_dist.domain_name
        except AttributeError:
            return None

    @property
    def cf_canonical_user_id(self) -> str:
        return self.node.try_get_context('cloudfront_canonical_user_id')

    @property
    def cf_origin_access_id(self) -> str:
        return self.node.try_get_context('cloudfront_origin_access_id')

    def create_kb_dist(self):
        cf_domain = self.node.try_get_context('kb_cloudfront_domain_name')
        san = self.node.try_get_context('kb_cloudfront_alt_domains')
        base_stack_name = self.node.try_get_context('stack_name')
        if isinstance(san, list):
            all_domains = san.copy()
            all_domains.append(cf_domain)
        else:
            all_domains = [cf_domain]

        try:
            self.kb_cfcert_arn = get_cert_arn('us-east-1', cf_domain)
        except ValueError:
            print(f"Skipping CloudFront distribution for {cf_domain}.  No certificate in us-east-1.")
            return None

        try:
            self.sec_lambda_arn = get_lambda_arn('us-east-1', f"{base_stack_name}", "securityheaderlambda")
        except ValueError:
            print(f"Skipping CloudFront distribution for {cf_domain}.  No security header lambda in us-east-1.")
            return None

        try:
            self.cfs3_lambda_arn = get_lambda_arn('us-east-1', f"{base_stack_name}", "cfs3redirectlambda")
        except ValueError:
            print(f"Skipping CloudFront distribution for {cf_domain}.  No security header lambda in us-east-1.")
            return None

        cfs3_func_ver = get_lambda_latest_version_num(self.cfs3_lambda_arn, 'us-east-1')
        cfs3_func = Version.from_version_arn(self, 'cfs3-func',
                                             f"{self.cfs3_lambda_arn}:{cfs3_func_ver}")
        cfs3_fassoc = LambdaFunctionAssociation(event_type=LambdaEdgeEventType.VIEWER_REQUEST,
                                                lambda_function=cfs3_func)

        sec_func_ver = get_lambda_latest_version_num(self.sec_lambda_arn, 'us-east-1')
        sec_func = Version.from_version_arn(self, 'sec-func-kb',
                                            f"{self.sec_lambda_arn}:{sec_func_ver}")
        sec_fassoc = LambdaFunctionAssociation(event_type=LambdaEdgeEventType.VIEWER_RESPONSE,
                                               lambda_function=sec_func)

        # Default - App
        alias_config = AliasConfiguration(acm_cert_ref=self.kb_cfcert_arn,
                                          names=all_domains)

        cust_origin_config = CustomOriginConfig(domain_name=self.node.try_get_context('kb_elb_domain_name'),
                                                origin_protocol_policy=OriginProtocolPolicy.HTTPS_ONLY, )

        cookies = {
            'forward': 'whitelist',
            'whitelistedNames': ['close_announcement', 'csrftoken']
        }
        forward_headers = [
            'Referer',
        ]
        
        fvalues = CfnDistribution.ForwardedValuesProperty(cookies=cookies, headers=forward_headers, query_string=True)

        b1 = Behavior(allowed_methods=CloudFrontAllowedMethods.ALL,
                      default_ttl=core.Duration.seconds(60),
                      max_ttl=core.Duration.seconds(86400),
                      min_ttl=core.Duration.seconds(0),
                      forwarded_values=fvalues,
                      is_default_behavior=True,
                      lambda_function_associations=[sec_fassoc],
                      )
        cookies = {
            'forward': 'whitelist',
            'whitelistedNames': ['csrftoken']
        }

        # fvalues = {
        #    'cookies': cookies,
        #    'queryString': True,
        # }
        fvalues = CfnDistribution.ForwardedValuesProperty(cookies=cookies, query_string=True)

        b2 = Behavior(allowed_methods=CloudFrontAllowedMethods.ALL,
                      is_default_behavior=False,
                      default_ttl=core.Duration.seconds(60),
                      min_ttl=core.Duration.seconds(0),
                      max_ttl=core.Duration.seconds(86400),
                      forwarded_values=fvalues,
                      path_pattern='/vuls/id/*-*',
                      lambda_function_associations=[sec_fassoc]
                      )

        # for the feed, only forward the query string
        fvalues = CfnDistribution.ForwardedValuesProperty(query_string=True)

        b_vulfeed = Behavior(allowed_methods=CloudFrontAllowedMethods.ALL,
                             is_default_behavior=False,
                             default_ttl=core.Duration.seconds(300),
                             min_ttl=core.Duration.seconds(300),
                             max_ttl=core.Duration.seconds(86400),
                             forwarded_values=fvalues,
                             path_pattern='/vulfeed*',
                             lambda_function_associations=[sec_fassoc]
                             )

        b_vuls_atomfeed = Behavior(allowed_methods=CloudFrontAllowedMethods.ALL,
                                   is_default_behavior=False,
                                   default_ttl=core.Duration.seconds(300),
                                   min_ttl=core.Duration.seconds(300),
                                   max_ttl=core.Duration.seconds(86400),
                                   forwarded_values=fvalues,
                                   path_pattern='/vuls/atomfeed*',
                                   lambda_function_associations=[sec_fassoc]
                                   )

        default_source_config = SourceConfiguration(behaviors=[b1, b2, b_vulfeed, b_vuls_atomfeed],
                                                    custom_origin_source=cust_origin_config)

        kb_stack_name = f"{base_stack_name}-{self.node.try_get_context('kb_stack_suffix')}-eb"

        # Static Files
        b_security_txt = Behavior(allowed_methods=CloudFrontAllowedMethods.GET_HEAD,
                                  is_default_behavior=False,
                                  path_pattern='/.well-known/security.txt',
                                  default_ttl=core.Duration.seconds(60),
                                  min_ttl=core.Duration.seconds(0),
                                  max_ttl=core.Duration.seconds(86400),
                                  lambda_function_associations=[sec_fassoc]
                                  )

        b3 = Behavior(allowed_methods=CloudFrontAllowedMethods.GET_HEAD,
                      is_default_behavior=False,
                      path_pattern='/vuls/id/???*',
                      default_ttl=core.Duration.seconds(60),
                      min_ttl=core.Duration.seconds(0),
                      max_ttl=core.Duration.seconds(86400),
                      lambda_function_associations=[sec_fassoc, cfs3_fassoc]
                      )

        forward_cookies = {
            'forward': 'none'
        }
        forward_headers = [
            'Access-Control-Request-Headers',
            'Access-Control-Request-Method',
            'Origin',
        ]
        fvalues = CfnDistribution.ForwardedValuesProperty(headers=forward_headers, query_string=False,
                                                          cookies=forward_cookies)
        b4 = Behavior(allowed_methods=CloudFrontAllowedMethods.GET_HEAD,
                      is_default_behavior=False,
                      path_pattern='/static-*',
                      default_ttl=core.Duration.seconds(60),
                      min_ttl=core.Duration.seconds(0),
                      max_ttl=core.Duration.seconds(86400),
                      forwarded_values=fvalues,
                      lambda_function_associations=[sec_fassoc]
                      )

        static_bucket = Bucket.from_bucket_name(self, f"static-bucket-{kb_stack_name}",
                                                f"static-bucket-{kb_stack_name}")
        s3_origin_config = S3OriginConfig(s3_bucket_source=static_bucket,
                                          origin_access_identity=self.s3_origin_access_identity)
        s3_source_config = SourceConfiguration(behaviors=[b_security_txt, b3, b4], s3_origin_source=s3_origin_config)


        # vincecomm distribution behaviors live here because they live under kb
        vincecomm_stack_name = f"{base_stack_name}-{self.node.try_get_context('vincecomm_stack_suffix')}-eb"

        all_cookies = {
            'forward': 'all',
        }
        forward_headers = [
            'Authorization',
            'Referer',
        ]
        fvalues = CfnDistribution.ForwardedValuesProperty(cookies=all_cookies, headers=forward_headers,
                                                          query_string=True)
        b5 = Behavior(allowed_methods=CloudFrontAllowedMethods.ALL,
                      is_default_behavior=False,
                      path_pattern='/vince/*',
                      default_ttl=core.Duration.seconds(0),
                      min_ttl=core.Duration.seconds(0),
                      max_ttl=core.Duration.seconds(86400),
                      forwarded_values=fvalues,
                      lambda_function_associations=[sec_fassoc]
                      )

        vince_origin_config = CustomOriginConfig(domain_name=self.node.try_get_context('vincecomm_elb_domain_name'),
                                                 origin_protocol_policy=OriginProtocolPolicy.HTTPS_ONLY, )

        vince_source_config = SourceConfiguration(behaviors=[b5], custom_origin_source=vince_origin_config)

        forward_cookies = {
            'forward': 'none'
        }
        forward_headers = [
            'Access-Control-Request-Headers',
            'Access-Control-Request-Method',
            'Origin',
        ]
        fvalues = CfnDistribution.ForwardedValuesProperty(headers=forward_headers, query_string=False,
                                                          cookies=forward_cookies)
        b6 = Behavior(allowed_methods=CloudFrontAllowedMethods.GET_HEAD,
                      is_default_behavior=False,
                      path_pattern='/vince/static-*',
                      default_ttl=core.Duration.seconds(300),
                      min_ttl=core.Duration.seconds(0),
                      max_ttl=core.Duration.seconds(86400),
                      forwarded_values=fvalues,
                      lambda_function_associations=[sec_fassoc]
                      )

        vince_static_origin_config = S3OriginConfig(
            s3_bucket_source=Bucket.from_bucket_name(self, f"static-bucket-{vincecomm_stack_name}",
                                                     f"static-bucket-{vincecomm_stack_name}"),
            origin_access_identity=self.s3_origin_access_identity)

        vince_static_source_config = SourceConfiguration(behaviors=[b6], s3_origin_source=vince_static_origin_config)

        # set up origin configs. Ordering is important.
        origin_configs = [default_source_config, s3_source_config, vince_static_source_config, vince_source_config]

        # if we have an artifacts bucket defined, add its config and origin
        # note: This is custom to CERT, but others may have a similar use case.
        #       This provides a path to a bucket of static files that will get
        #       served through cloudfront.
        if self.node.try_get_context('kb_artifacts_s3_arn') and self.node.try_get_context('kb_artifacts_s3_region'):
            forward_cookies = {
                'forward': 'none'
            }
            forward_headers = [
                'Access-Control-Request-Headers',
                'Access-Control-Request-Method',
                'Origin',
            ]
            fvalues = CfnDistribution.ForwardedValuesProperty(headers=forward_headers, query_string=False,
                                                              cookies=forward_cookies)
            b7 = Behavior(allowed_methods=CloudFrontAllowedMethods.GET_HEAD,
                          is_default_behavior=False,
                          path_pattern='/artifacts/*',
                          default_ttl=core.Duration.seconds(300),
                          min_ttl=core.Duration.seconds(0),
                          max_ttl=core.Duration.seconds(86400),
                          forwarded_values=fvalues,
                          lambda_function_associations=[sec_fassoc]
                          )

            # artifacts bucket needs to specify region, since it is a cross-region shared resource.
            #
            # Note that this only necessary here because the bucket is being used as a cloudfront
            # origin, which appends a domain name to the bucket arn to define the origin. The domain
            # name defaults to the current region, which breaks when the bucket is in a different
            # region.
            artifacts_bucket = Bucket.from_bucket_attributes(self, f"{kb_stack_name}-artifacts-bucket",
                bucket_arn=self.node.try_get_context('kb_artifacts_s3_arn'),
                region=self.node.try_get_context('kb_artifacts_s3_region')
            )
            kb_artifacts_origin_config = S3OriginConfig(
                s3_bucket_source=artifacts_bucket,
                origin_access_identity=self.s3_origin_access_identity)

            kb_artifacts_source_config = SourceConfiguration(behaviors=[b7], s3_origin_source=kb_artifacts_origin_config)
            origin_configs.append(kb_artifacts_source_config)

        # set up custom responses to handle errors, especially 403 errors from bucket access attempts on non-existent files
        custom_403_response = CfnDistribution.CustomErrorResponseProperty(error_code=403, response_code=404,
                                                                          response_page_path='/404.html')
        custom_404_response = CfnDistribution.CustomErrorResponseProperty(error_code=404, response_code=404,
                                                                          response_page_path='/404.html')

        # create the distribution
        self.kb_dist = CloudFrontWebDistribution(self, 'kb-distribution',
                                                 origin_configs=origin_configs,
                                                 alias_configuration=alias_config,
                                                 error_configurations=[custom_403_response, custom_404_response],
                                                 comment=f"Distribution for: {self.node.try_get_context('kb_elb_domain_name')}",
                                                 default_root_object='')

    def create_vince_dist(self):

        cf_domain = self.node.try_get_context('vince_cloudfront_domain_name')
        # Subject alternative names for this distributions certificate
        san = self.node.try_get_context('vince_cloudfront_alt_domains')
        base_stack_name = self.node.try_get_context('stack_name')
        if isinstance(san, list):
            all_domains = san.copy()
            all_domains.append(cf_domain)
        else:
            all_domains = [cf_domain]

        try:
            self.vince_cfcert_arn = get_cert_arn('us-east-1', cf_domain)
        except ValueError:
            print(f"Skippping CloudFront distribution for {cf_domain}.  No certificate in us-east-1.")
            return None

        try:
            self.sec_lambda_arn = get_lambda_arn('us-east-1', f"{base_stack_name}", "securityheaderlambda")
        except ValueError:
            print(f"Skippping CloudFront distribution for {cf_domain}.  No security header lambda in us-east-1.")
            return None

        # sec_func = Function.from_function_arn(self, 'cfs3-redirect-lambda', self.cfs3_lambda_arn)
        sec_func_ver = get_lambda_latest_version_num(self.sec_lambda_arn, 'us-east-1')
        sec_func = Version.from_version_arn(self, 'sec-func-vince',
                                              f"{self.sec_lambda_arn}:{sec_func_ver}")
        sec_fassoc = LambdaFunctionAssociation(event_type=LambdaEdgeEventType.VIEWER_RESPONSE,
                                               lambda_function=sec_func)

        # Default - App
        alias_config = AliasConfiguration(acm_cert_ref=self.vince_cfcert_arn,
                                          names=all_domains)

        cust_origin_config = CustomOriginConfig(domain_name=self.node.try_get_context('vince_elb_domain_name'),
                                                origin_protocol_policy=OriginProtocolPolicy.HTTPS_ONLY, )

        all_cookies = {
            'forward': 'all',
        }
        forward_headers = [
            'Referer',
        ]

        fvalues = CfnDistribution.ForwardedValuesProperty(headers=forward_headers, query_string=True,
                                                          cookies=all_cookies)

        b1 = Behavior(allowed_methods=CloudFrontAllowedMethods.ALL,
                      default_ttl=core.Duration.seconds(0),
                      max_ttl=core.Duration.seconds(0),
                      min_ttl=core.Duration.seconds(0),
                      forwarded_values=fvalues,
                      is_default_behavior=True,
                      lambda_function_associations=[sec_fassoc]
                      )

        default_source_config = SourceConfiguration(behaviors=[b1], custom_origin_source=cust_origin_config)

        vince_stack_name = f"{base_stack_name}-{self.node.try_get_context('vince_stack_suffix')}-eb"

        forward_cookies = {
            'forward': 'none'
        }
        forward_headers = [
            'Access-Control-Request-Headers',
            'Access-Control-Request-Method',
            'Origin',
        ]
        fvalues = CfnDistribution.ForwardedValuesProperty(headers=forward_headers, query_string=False,
                                                          cookies=forward_cookies)
        b2 = Behavior(allowed_methods=CloudFrontAllowedMethods.GET_HEAD,
                      is_default_behavior=False,
                      path_pattern='/static-*',
                      default_ttl=core.Duration.seconds(300),
                      min_ttl=core.Duration.seconds(0),
                      max_ttl=core.Duration.seconds(86400),
                      forwarded_values=fvalues,
                      lambda_function_associations=[sec_fassoc]
                      )

        s3_origin_config = S3OriginConfig(
            s3_bucket_source=Bucket.from_bucket_name(self, f"static-bucket-{vince_stack_name}",
                                                     f"static-bucket-{vince_stack_name}"),
            origin_access_identity=self.s3_origin_access_identity)

        s3_source_config = SourceConfiguration(behaviors=[b2], s3_origin_source=s3_origin_config)

        vince_web_acl_id = self.node.try_get_context('vince_web_acl_id')
        self.vince_dist = CloudFrontWebDistribution(self, 'vince-distribution',
                                                    origin_configs=[default_source_config, s3_source_config],
                                                    alias_configuration=alias_config,
                                                    comment=f"Distribution for: {self.node.try_get_context('vince_elb_domain_name')}",
                                                    web_acl_id=vince_web_acl_id,
                                                    default_root_object="")
