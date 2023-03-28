#########################################################################
# VINCE
#
# Copyright 2023 Carnegie Mellon University.
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
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.http import HttpResponseRedirect
from django.urls import resolve
import logging
import pytz
import traceback

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class MultipleDomainMiddleware(MiddlewareMixin):

    def process_request(self, request):
        if settings.LOCALSTACK:
            return
        url_config = getattr(settings, 'MULTIURL_CONFIG', None)
        if not url_config:
            return

        host = None
        server = None
        path = request.get_full_path()
        #if request.session.session_key:
        #logger.debug(f"Path is {path}")
        scheme = "http" if not request.is_secure() else "https"
        
        try:
            app_name = resolve(request.path_info).view_name.split(':')[0]
        except:
            return None

        my_domain = url_config[settings.VINCE_NAMESPACE]
        if app_name == settings.VINCE_NAMESPACE:
            # this is the same namespace
            return
        
        if app_name in url_config:
            #request.urlconf = url_config[host]
            domain = url_config[app_name]
            if domain == my_domain:
                # different namespace, but same domain, so don't redirect
                return
            logger.debug(f"Middleware redirect to {domain}")
            return HttpResponseRedirect("{0}://{1}{2}".format(
                scheme, domain, path))


class TimezoneMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.DEBUG:
            return self.get_response(request)
        
        default_tz = getattr(settings, 'DEFAULT_TIME_ZONE', 'UTC')
        tzname = request.session.get('timezone') or default_tz
        timezone.activate(pytz.timezone(tzname))
        return self.get_response(request)
    
