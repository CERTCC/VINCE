#########################################################################
# VINCE
#
# Copyright 2022 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for non-US
# Government use and distribution.
#
# Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
# U.S. Patent and Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM21-1126
########################################################################
from django.conf import settings
from storages.backends.s3boto3 import S3Boto3Storage


class PrivateMediaStorage(S3Boto3Storage):
    location = settings.AWS_PRIVATE_MEDIA_LOCATION
#    location = 'static'
    file_overwrite = False
    default_acl = 'private'
    region_name=settings.AWS_REGION
    #region_name = "us-east-1"
    custom_domain=False
    acl='private'
    bucket_name = getattr(settings, 'PRIVATE_BUCKET_NAME')
    
    def __init__(self, *args, **kwargs):
        if not settings.LOCALSTACK:
            kwargs['bucket'] = getattr(settings, 'PRIVATE_BUCKET_NAME')
            kwargs['default_acl']='private'
            kwargs['acl'] = 'private'
        #if hasattr(settings, 'ATTACHMENT_URL'):
        #    kwargs['custom_domain'] = settings.ATTACHMENT_URL
        #else:
        #    kwargs['custom_domain'] = False
        super(PrivateMediaStorage, self).__init__(*args, **kwargs)


class SharedMediaStorage(S3Boto3Storage):
    location = settings.AWS_PRIVATE_MEDIA_LOCATION
    file_overwrite = False
    default_acl = 'private'
    region_name = settings.AWS_REGION
    #region_name = "us-east-1"
    acl = 'private'
    custom_domain = False
    bucket_name = getattr(settings, 'VINCE_SHARED_BUCKET')

    def __init__(self, *args, **kwargs):
        if not settings.LOCALSTACK:
            kwargs['bucket'] = getattr(settings, 'VINCE_SHARED_BUCKET')
            kwargs['default_acl']='private'
            kwargs['acl'] = 'private'
        #if hasattr(settings, 'VC_ATTACHMENT_URL'):
        #    kwargs['custom_domain'] = settings.VC_ATTACHMENT_URL
        #else:
        #    kwargs['custom_domain'] = False
        super(SharedMediaStorage, self).__init__(*args, **kwargs)
        
class VRFReportsStorage(S3Boto3Storage):
    location = settings.VRF_PRIVATE_MEDIA_LOCATION
    file_overwrite = False
    default_acl = 'private'
    custom_domain=False
    region_name = settings.AWS_REGION
    acl = 'private'
    bucket_name = getattr(settings, 'S3_INCOMING_REPORTS')

    def __init__(self, *args, **kwargs):
        if not settings.LOCALSTACK:
            kwargs['bucket'] = getattr(settings, 'S3_INCOMING_REPORTS')
            kwargs['default_acl']='private'
            kwargs['acl'] = 'private'
        super(VRFReportsStorage, self).__init__(*args, **kwargs)
