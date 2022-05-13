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
from django import template
from itertools import chain
from django.db.models import Q

register = template.Library()

@register.filter
def undeleted(vuls):
    """
    Return all of the vulnerabilities/vendors associated with this case that haven't been deleted
    """
    return vuls.filter(deleted=False)


@register.filter
def last_published(actions):
    """
    Return action of last published vul note
    """
    return actions.filter(action_type=9).order_by('-date').first()


@register.filter
def vendor_vuls(vuls):
    """
    Return all the vulnerabilites that we asked vendors to provide status for
    """
    return vuls.filter(ask_vendor_status=True, deleted=False).order_by('case_increment')

@register.filter
def vendor_status(status, vul):
    s = status.filter(vul=vul).first()
    return s

@register.filter
def vendor_filter_status(vendors):
    from vince.models import VendorStatus
    affected = vendors.filter(vendorstatus__status=VendorStatus.AFFECTED_STATUS).distinct('vendor').order_by('vendor')
    a = list(affected.values_list('id', flat=True))
    print(a)
    notaffected = vendors.filter(vendorstatus__status=VendorStatus.UNAFFECTED_STATUS).distinct('vendor').order_by('vendor')
    if a:
        notaffected = notaffected.exclude(id__in=a)
    na = list(notaffected.values_list('id', flat=True))
    unknown =  vendors.filter(Q(vendorstatus__status=VendorStatus.UNKNOWN_STATUS)|Q(vendorstatus__isnull=True)).distinct('vendor').order_by('vendor')
    if a or na:
        alist = a + na
        unknown = unknown.exclude(id__in=alist)
    
    x = list(chain(affected, notaffected, unknown))[:100]
    return x
