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
Default settings for django-helpdesk.
"""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

DEFAULT_USER_SETTINGS = {
    'use_email_as_submitter': True,
    'email_on_ticket_assign': True,
    'email_on_ticket_change': True,
    'email_case_changes': 1,
    'email_new_posts': 1,
    'email_new_messages': 1,
    'email_new_status': 1,
    'email_tasks': 1,
    'login_view_ticketlist': True,
    'tickets_per_page': 25,
    'send_reminders': True,
    'reminder_days': 2,
    'email_preference': 1,
    'triage': False,
    'reminder_tickets': True,
    'reminder_publication': True,
    'reminder_vendor_status': True,
    'reminder_vendor_views': True,
    'reminder_cases': True,
    
}

# triage assign setting
# the default is to create tickets unassigned by default
# By changing this setting to True, the user assigned as Triage
# will be assigned to incoming tickets
VINCE_ASSIGN_TRIAGE = getattr(settings, 'VINCE_ASSIGN_TRIAGE', False)

#If set to True, VINCE will only create a ticket for PERMANENT bounces.
#Transient bounces will be recorded and can be viewed in the Bounce Manager, but a ticket will not be created.
VINCE_IGNORE_TRANSIENT_BOUNCES = getattr(settings, 'VINCE_IGNORE_TRANSIENT_BOUNCES', False)

##########################################
# generic options - visible on all pages #
##########################################

# allow the subject to have a configurable template.
VINCE_EMAIL_SUBJECT_TEMPLATE = getattr(
    settings, 'VINCE_EMAIL_SUBJECT_TEMPLATE',
    "%(subject)s {{ ticket.ticket }} {{ ticket.title|safe }}")
# since django-helpdesk may not work correctly without the ticket ID
# in the subject, let's do a check for it quick:
if VINCE_EMAIL_SUBJECT_TEMPLATE.find("ticket.ticket") < 0:
    raise ImproperlyConfigured

# default fallback locale when queue locale not found
VINCE_EMAIL_FALLBACK_LOCALE = getattr(settings, 'VINCE_EMAIL_FALLBACK_LOCALE', 'en')

VULNOTE_TEMPLATE = getattr(settings, 'VULNOTE_TEMPLATE',
                           "### Overview\r\n\r\n### Description\r\n\r\n"\
                           "### Impact\r\nThe complete impact of this vulnerability is not yet known.\r\n\r\n### Solution"\
                           "\r\nThe CERT/CC is currently unaware of a practical solution to this problem."\
                           "\r\n\r\n### Acknowledgements\r\nThanks to the reporter who wishes to remain anonymous.\r\n\r\n")
