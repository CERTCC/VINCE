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
"""
django-helpdesk - A Django powered ticket tracker for small enterprise.
(c) Copyright 2008 Jutda. All Rights Reserved. See LICENSE for details.
templatetags/ticket_to_link.py - Used in ticket comments to allow wiki-style
                                 linking to other tickets. Including text such
                                 as '#3180' in a comment automatically links
                                 that text to ticket number 3180, with styling
                                 to show the status of that ticket (eg a closed
                                 ticket would have a strikethrough).
"""

import re

from django import template
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.contrib.auth.models import User, Group
from django.utils.html import urlize as urlize_impl
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def num_to_link(text):
    try:
        from vince.models import Ticket
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load ticket model.")

    if text == '':
        return text

    matches = []
    for match in re.finditer(r"(?:[^&]|\b|^)#(\d+)\b", text):
        matches.append(match)

    for match in reversed(matches):
        number = match.groups()[0]
        url = reverse('vince:ticket', args=[number])
        try:
            ticket = Ticket.objects.get(id=number)
        except Ticket.DoesNotExist:
            ticket = None

        if ticket:
            style = ticket.get_status_display()
            text = "%s <a href='%s' class='ticket_link_status ticket_link_status_%s'>#%s</a>%s" % (
                text[:match.start() + 1], url, style, match.groups()[0], text[match.end():])
    return mark_safe(text)

register = template.Library()
register.filter(num_to_link)

@register.filter
def email_to_user(text):
    matches = []
    for match in re.finditer(r'[\w.+-]+@[\w-]+\.[\w.-]+', text):
        matches.append(match)
    for match in reversed(matches):
        email = match.group(0)
        vcuser = User.objects.using('vincecomm').filter(email=email).first()
        if vcuser:
            link = reverse("vince:vcuser", args=[vcuser.id])
            text = "%s <a href='%s'>%s</a>%s" % (text[:match.start()], link, match.group(0), text[match.end():])
    return mark_safe(text)
                          
    


@register.filter(is_safe=True, needs_autoescape=True)
def smarter_urlize(value, limit, autoescape=None):
    return mark_safe(urlize_impl(value, trim_url_limit=int(limit), nofollow=True, autoescape=autoescape).replace('<a', '<a title="" vince-tooltip'))

@register.filter
def vince_user(submitter_email):
    vincomm_user = User.objects.using('vincecomm').filter(email=submitter_email).first()
    if vincomm_user:
        return f"<a class=\"vcuser_link\" href=\"{reverse('vince:vcuser', args=[vincomm_user.id])}\">VINCE User: {vincomm_user.vinceprofile.vince_username} [{vincomm_user.email}]</a>"
    else:
        return submitter_email


@register.filter
def case_status_repr(status):
    try:
        from vince.models import VulnerabilityCase
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load ticket model.")

    status = int(status)
    if status == 1:
        return "ACTIVE"
    elif status == 2:
        return "INACTIVE"
    elif status == 3:
        return "PUBLISHED"
    elif status == 4:
        return "UNPUBLISHED"
        
@register.filter
def status_repr(status):
    try:
        from vince.models import Ticket
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load ticket model.")

    status_dict = dict(Ticket.STATUS_CHOICES)
    return status_dict[int(status)]

@register.filter
def owner_repr(status):
    try:
        u = User.objects.filter(id=int(status)).first()
        return u.usersettings.preferred_username
    except:
        return "Unassigned"

@register.filter
def queue_repr(status):
    try:
        from vince.models import TicketQueue
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load ticketqueue model.")
    q = TicketQueue.objects.filter(id=int(status)).first()
    return q.title
    

@register.filter
def team_repr(status):
    g = Group.objects.filter(id=int(status)).first()
    return g.name


@register.filter
def case_access(case, user):
    try:
        from vince.models import CasePermissions, CaseAssignment
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load ticketqueue model.")
    if user.is_superuser:
        return True
    #is user assigned?
    if isinstance(case, int):
        if CaseAssignment.objects.filter(case__id=case, assigned=user).exists():
            return True
    else:
        if CaseAssignment.objects.filter(case=case, assigned=user).exists():
            return True
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    if isinstance(case, int):
        return CasePermissions.objects.filter(case__id=case, group__in=user_groups, group_read=True).exists()
    return CasePermissions.objects.filter(case=case, group__in=user_groups, group_read=True).exists()
    
