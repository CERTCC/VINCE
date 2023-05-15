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


def vince_version(request):
    # return the value you want as a dictionnary. you may add multiple values in there.

    return {'VERSION': settings.VERSION,
            'VINCE_DEV_SYSTEM': settings.VINCE_DEV_SYSTEM,
            'GOOGLE_SITE_KEY': settings.GOOGLE_SITE_KEY,
            'VINCEPUB_URL': settings.VINCEPUB_URL,
            'VINCETRACK_URL': settings.VINCETRACK_URL,
            'VINCECOMM_URL': settings.VINCECOMM_URL,
            'FAVICON': settings.FAVICON,
            'WEB_TITLE': settings.WEB_TITLE,
            'ORG_NAME': settings.ORG_NAME,
            'CONTACT_EMAIL': settings.CONTACT_EMAIL,
            'VINCEPUB_BASE_TEMPLATE': settings.VINCEPUB_BASE_TEMPLATE,
            'VINCETRACK_BASE_TEMPLATE': settings.VINCETRACK_BASE_TEMPLATE,
            'VINCECOMM_BASE_TEMPLATE': settings.VINCECOMM_BASE_TEMPLATE,
            'CASE_ID': settings.CASE_IDENTIFIER,
            'REPORT_ID': settings.REPORT_IDENTIFIER}

            

