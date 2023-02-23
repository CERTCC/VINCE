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
import logging
import mimetypes
import os
import pytz
from smtplib import SMTPException
from django.conf import settings
try:
    from django.utils import six
except:
    import six
from django.utils.safestring import mark_safe
from vince.models import Ticket, Contact, VulnerabilityCase, CaseAction, CaseAssignment, AdminPGPEmail, VTDailyNotification, TicketQueue, CalendarEvent, FollowUp, EmailTemplate, EmailContact
from vinny.models import Case, VTCaseRequest, VinceCommGroupAdmin, VinceCommContact, GroupContact, VinceCommEmail
from django.contrib.auth.models import User, Group
from django.shortcuts import get_object_or_404
from django.core.mail import EmailMultiAlternatives
from django.utils.translation import gettext, gettext_lazy as _
from django.template import engines
from datetime import datetime, date
import base64
import gnupg
import tempfile
import traceback
import boto3
from M2Crypto import BIO, Rand, SMIME, X509
from botocore.exceptions import ClientError
from email.mime.base import MIMEBase
from email.message import Message
import mimetypes
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from M2Crypto import BIO, Rand, SMIME, X509
from vince.permissions import get_user_gen_queue, get_team_queues, get_case_case_queue
from vince.settings import VINCE_EMAIL_SUBJECT_TEMPLATE, VINCE_EMAIL_FALLBACK_LOCALE

from_string = engines['django'].from_string

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def get_ticket_path(ticket_context):
    slug = ticket_context['queue']['slug']
    ticket_id = ticket_context['ticket']['ticket']
    ticket_id = ticket_id.replace('[', '')
    ticket_id = ticket_id.replace(']', '')
    ticket_id = ticket_id.replace(slug, '')
    ticket_id = int(ticket_id.replace('-', ''))
    ticket = get_object_or_404(Ticket, id=ticket_id)
    return f"{settings.SERVER_NAME}{ticket.get_absolute_url()}"


def get_vc_case_path(case_context):
    case = Case.objects.filter(vuid=case_context['case']['vuid']).first()
    if case:
        return f"{settings.KB_SERVER_NAME}{case.get_absolute_url()}"
    else:
        return None

def get_vt_case_path(case_context):
    case = get_object_or_404(VulnerabilityCase, vuid=case_context['case']['vuid'])
    return f"{settings.SERVER_NAME}{case.get_absolute_url()}"


def is_case_action(title):

    logger.debug(f"TITLE IS {title}")

    tkt_text = str(_("Email Bounce"))

    if tkt_text in title:
        logger.warning(f"Email is a bounce returning 0 {tkt_text}")
        return 0

    tkt_text = str(_("Vendor statement"))

    if tkt_text in title:
        #vendor status update
        return CaseAction.lookup('Status Change')

    tkt_text = str(_("New Message"))

    if tkt_text in title:
        # message
        return CaseAction.lookup('Message')

    tkt_text = str(_("Email"))

    if tkt_text in title:
        #new case task
        return CaseAction.lookup('Task Activity')

    return 0


def get_case_update_template(action):
    if action == 1:
        return "case_update", "Case Updated"
    elif action == 2:
        return "case_new_post", "New Post"
    elif action == 3:
        return "case_new_message", "New Message"
    elif action == 4:
        return "case_vendor_status", "Vendor Status Change"
    elif action == 8:
        return "case_new_ticket", "New Case Task"
    else:
        return "case_update", "Case Updated"


def get_html_preference(user):
    s = user.usersettings.settings.get('email_preference', 1)
    if int(s) == 1:
        html = True
    else:
        html = False

    return html

def check_user_availability(user):
    # is this user OOF?
    today = date.today()
    return CalendarEvent.objects.filter(event_id=CalendarEvent.OOF, date__range=(today,today), user=user).exists()

def create_oof_ticket(user, action, ticket=None, case=None):
    #does a ticket already exist for this user for this date?

    logger.debug("Creating OOF TICKET")
    
    prev = Ticket.objects.filter(title__startswith="OOF update for user",
                                 submitter_email=user.email,
                                 created__date=date.today()).first()
    if prev:
        if ticket:
            #just add on to this ticket
            fup = FollowUp(ticket=prev,
                           title=f"Update on ticket for OOF user {user.usersettings.preferred_username}",
                           comment=f"{action}\r\n\r\n{settings.SERVER_NAME}{ticket.get_absolute_url()}")
            fup.save()
        elif case:
            #just add on to this ticket
            fup = FollowUp(ticket=prev,
		           title=f"Update on case {case.vu_vuid} for OOF user {user.usersettings.preferred_username}",
                           comment=f"{action}\r\n\r\n{settings.SERVER_NAME}{case.get_absolute_url()}")
            fup.save()
        #reopen ticket if closed
        prev.status = Ticket.OPEN_STATUS
        prev.save()
    else:
        queue = get_user_gen_queue(user)
        if ticket:
            tkt = Ticket(title=f"OOF update for user {user.usersettings.preferred_username}",
                         description=f"{action}\r\n\r\n{settings.SERVER_NAME}{ticket.get_absolute_url()}",
                         submitter_email=user.email,
                         queue=queue)
        else:
            tkt = Ticket(title=f"OOF update for user {user.usersettings.preferred_username}",
                         description=f"CASE {case.vu_vuid} update: {action}\r\n\r\n{settings.SERVER_NAME}{case.get_absolute_url()}",
                         queue=queue,
                         submitter_email=user.email)
        tkt.save()
                     
                       
                                 

def send_updateticket_mail(followup, files=None, user=None):
    # Get the ticket and queue from the followup
    ticket = followup.get_related_ticket
    queue = ticket.queue
    template = "updated_cc"

    if user == None:
        if followup.user:
            user = followup.user

    if (not ticket.assigned_to) or (ticket.assigned_to == user):
        # this is not assigned to anyone or the person assigned made the change
        return

    attachment_text = str(_("Attachment to Email"))
    tkt_text = str(_("Ticket Opened"))
    tkt_text_assigned = str(_("Assigned"))
    bulk_change = str(_("Bulk"))
    pbounce = str(_("Permanent bounce"))
    tbounce= str(_("Transient bounce"))
    ignore_titles = [attachment_text, tkt_text, tkt_text_assigned, bulk_change, pbounce, tbounce]
    if any(substr in followup.title for substr in ignore_titles):
        # send new ticket mail will send the email notification about this
        # new assignments will get a special assignment email
        # Ignore email attachments
        return
    context = None
    #there are a few case update emails that come through here
    # find out which one it is
    if ticket.case:
        action = is_case_action(followup.title)
        if action:
            logger.debug("THIS IS A CASE ACTION")
            if (check_user_availability(ticket.assigned_to)):
                # this user is OOF - now what?
                create_oof_ticket(ticket.assigned_to, followup.title, ticket)
            #now does this user want to see this email?
            prefs = check_email_preferences(action, ticket.assigned_to)
            if not prefs:
                # this user doesn't want email
                return
            if 2 in prefs:
                # this user wants a daily summary of this
                vtdn = VTDailyNotification(user=ticket.assigned_to,
                                           action_type=action,
                                           followup=followup,
                                           case=ticket.case)
                vtdn.save()
            if 1 not in list(prefs):
                return
            template, title = get_case_update_template(action)
            context = safe_case_context(ticket.case, action)
            context['case']['case_url'] = get_vt_case_path(context)
            context['ticket'] = ticket_template_context(ticket)
            context['ticket']['staff_url'] = f"{settings.SERVER_NAME}{ticket.get_absolute_url()}"
            context['emailtitle'] = title

            
            send_templated_mail(
	    template,
	    context,
            recipients=ticket.assigned_to.email,
            sender=queue.from_address,
	    fail_silently=True,
            files=files,
            html=get_html_preference(ticket.assigned_to)
            )
            return
            
    # Fill in context
    if not context:
        context = safe_template_context(ticket)
        context['comment'] = followup.comment
        context['emailtitle'] = "Ticket Updated"
        
        if not ticket.assigned_to.usersettings.settings.get('email_on_ticket_change', False):
            return

    send_ticket_mail(
        template,
        context,
        recipients=ticket.assigned_to.email,
        sender=queue.from_address,
        fail_silently=True,
        files=files,
        html=get_html_preference(ticket.assigned_to)
    )

    #messages_sent_to.append(ticket.assigned_to.email)

    ##get ticketcc
    #all_ticketcc = ticket.ticketcc_set.all()
    #for cc in all_ticketcc:
    #    if cc.user and cc.user != user and \
        #       cc.user.email not in messages_sent_to:
    #        context['emailtitle'] = "Ticket Updated"
    #        send_ticket_mail(
    #            'updated_cc',
    #            context,
    #            recipients=cc.user.email,
    #            sender=queue.from_address,
    #            fail_silently=True,
    #            files=files,
    #            html=cc.user.usersettings.settings.get('email_preference', True)
    #        )
    #        messages_sent_to.append(cc.user.email)
    
    
# if queue.updated_ticket_cc and \
#    queue.updated_ticket_cc not in messages_sent_to:
#     context['emailtitle'] = "Ticket Updated"
#     send_ticket_mail(
#         'updated_cc',
#         context,
#         recipients=queue.updated_ticket_cc,
#         sender=queue.from_address,
#         fail_silently=True,
#         files=files,
#         html=False
#     )
#
        
def send_newticket_mail(followup, files, user=None):
    # Get the ticket and queue from the followup
    ticket = followup.get_related_ticket
    queue = ticket.queue

    # Fill in context
    context = safe_template_context(ticket)
    context['comment'] = followup.comment

    messages_sent_to = []

    # don't send to submitter
#    if ticket.submitter_email:
#        context['emailtitle'] = "Ticket has been submitted"
#        send_ticket_mail(
#            'newticket_submitter',
#            context,
#            recipients=ticket.submitter_email,
#            sender=queue.from_address,
#            fail_silently=True,
#            files=files,
#        )

    if ticket.submitter_email:
        # don't send email to submitter
        messages_sent_to.append(ticket.submitter_email)

    if ticket.case:
        # if this has a related case, send to anyone assigned to the case
        assigned_users = CaseAssignment.objects.filter(case=ticket.case)
        context.update(safe_case_context(ticket.case))
        for asuser in assigned_users:
            if asuser.assigned.email not in messages_sent_to and check_email_preferences(CaseAction.lookup("Task Activity"), asuser.assigned):
                context['emailtitle'] = "New Task in Case %s" % ticket.case.get_vuid()
                send_ticket_mail(
                    'case_new_ticket',
                    context,
                    recipients=asuser.assigned.email,
                    sender=queue.from_address,
                    fail_silently=True,
                    files=files,
                    html=get_html_preference(asuser.assigned)
                )
                messages_sent_to.append(asuser.assigned.email)
        
    if ticket.assigned_to and \
            ticket.assigned_to != user and \
            ticket.assigned_to.usersettings.settings.get('email_on_ticket_assign', False) and \
            ticket.assigned_to.email and \
            ticket.assigned_to.email not in messages_sent_to:
        context['emailtitle'] = "Ticket Reassigned"
        send_ticket_mail(
            'assigned_owner',
            context,
            recipients=ticket.assigned_to.email,
            sender=queue.from_address,
            fail_silently=True,
            files=files,
            html=get_html_preference(ticket.assigned_to)
        )
        messages_sent_to.append(ticket.assigned_to.email)

    if queue.new_ticket_cc and queue.new_ticket_cc not in messages_sent_to:
        context['emailtitle'] = "New Ticket"
        send_ticket_mail(
            'newticket_cc',
            context,
            recipients=queue.new_ticket_cc,
            sender=queue.from_address,
            fail_silently=True,
            files=files,
            html=False
        )
        messages_sent_to.append(queue.new_ticket_cc)

    #if queue.updated_ticket_cc and \
    #        queue.updated_ticket_cc != queue.new_ticket_cc and \
    #        queue.updated_ticket_cc not in messages_sent_to:
    #    context['emailtitle'] = "Ticket Updated"
    #    send_ticket_mail(
    #        'newticket_cc',
    #        context,
    #        recipients=queue.updated_ticket_cc,
    #        sender=queue.from_address,
    #        fail_silently=True,
    #        files=files,
    #        html=False
    #    )


def check_email_preferences(action_type, user):
    """ Check if email and user action require either an
    immediate email or a digest email on a daily basis """

    if not user.is_active:
        logger.warning("User {user.username} is inactive returning []")
        return []

    pref_type = CaseAction.USER_ACTION_MAP.get(action_type,None)

    if pref_type == None:
        #pref_type does not map to any user actions requiring
        #sending of an email
        return []
    #pref_type will be belong to user prefence such as
    #('email_case_changes', 'email_tasks')
    prefs = user.usersettings.settings.get(pref_type,[1])

    #pref can be True or a list of integers. If pref is True
    #turn this into array [1] send email but not in daily digest mode
    if type(prefs) is not list:
        if prefs:
            prefs = [1]
        else:
            prefs = []

    return prefs

def emailable_action(action):
    if action.action_type in CaseAction.EMAILABLE_ACTIONS:
        return False

    return True

def send_updatecase_mail(action, new_user=None):
    # Get the ticket and queue from the followup
    # new_user is the user recently assigned to the case
    case = action.get_related_case

    logger.debug(f"ACTION is {action.action_type}")
    
    if not(emailable_action(action)):
        return
    
    # Fill in context
    context = safe_case_context(case, action)

    context['case']['case_url'] = get_vt_case_path(context)

    messages_sent_to_txt = []
    messages_sent_to_html = []

    assigned_users = CaseAssignment.objects.filter(case=case)

    if new_user:
        if action.user == new_user:
            # action was done by new assignee
            return
        # this is an assignment update
        pref = check_email_preferences(action.action_type, new_user)
        if 1 in pref:
            context['case']['assignee'] = action.user
            send_case_mail(
                "case_assigned_to",
                context,
                recipients=[new_user.email],
                fail_silently=True,
                html=get_html_preference(new_user)
            )
            # if new_user is populated, then this was just an update to tell
            # the user they have been assigned to the case
        if 2 in list(pref):
            vtdn = VTDailyNotification(user=new_user,
                                       action_type=action.action_type,
                                       case=case,
                                       action=action)
            vtdn.save()
        return

    #Assume everyone is OOF unless we get at least one user 
    alloof = True
    for user in assigned_users:
        if user.assigned not in [action.user, new_user]:
            pref = check_email_preferences(action.action_type, user.assigned)
            if 1 in pref:
                if get_html_preference(user.assigned):
                    messages_sent_to_html.append(user.assigned.email)
                else:
                    messages_sent_to_txt.append(user.assigned.email)
            if 2 in pref:
                # this user wants a daily summary email
                vtdn = VTDailyNotification(user=user.assigned,
                                           action_type=action.action_type,
                                           case=case,
                                           action=action)
                vtdn.save()

        #if assigned users are OOF
        if not(check_user_availability(user.assigned)):
            logger.debug(f"User {user.assigned} is Out Of Office")
            alloof = False


    if (len(assigned_users) and alloof):
        logger.debug(f"All assigned users are Out of Office {assigned_users}")
        #all assigned users are oof, so cut a triage ticket to alert
        #someone that something happened
        create_oof_ticket(user.assigned, action.title, None, case)
        
    # if this case is unassigned and there are changes, cut a new ticket to
    # alert people that changes happened
    if not(assigned_users):
        queue = None
        # cut a new ticket to alert
        if case.team_owner:
            tq = get_team_queues(case.team_owner)
            queue = tq.filter(queue_type=2).first()
        else:
            queue = get_case_case_queue(case)

        if not(queue):
            queue = TicketQueue.objects.filter(title="General").first()
            
        new_ticket = Ticket(title=action.title,
                            created=action.date,
                            queue=queue,
                            case=case,
                            description="Ticket opened due to change in unassigned case. Please assign this case.")
        new_ticket.save()
        return

    
    template, context['emailtitle'] = get_case_update_template(action.action_type)
        
    if len(messages_sent_to_txt):
        send_case_mail(
            template,
            context,
            recipients=messages_sent_to_txt,
            fail_silently=True,
            html=False
        )
        
    if len(messages_sent_to_html):
        send_case_mail(
            template,
            context,
            recipients=messages_sent_to_html,
            fail_silently=True,
            html=True
        )

    return messages_sent_to_txt
        
        
def send_ticket_mail(template_name,
                     context,
                     recipients,
                     sender=None,
                     bcc=None,
                     fail_silently=False,
                     files=None,
                     html=True):
    """
        Wrapper for send_templated_mail which adds the ticket_fullurl to the context.
        ticket_fullurl is used to create links for ticket emails
    """
    context['ticket']['staff_url'] = get_ticket_path(context)
    context['ticket']['ticket_url'] = get_ticket_path(context)
    context['signup_url'] = f"{settings.KB_SERVER_NAME}/vince/comm/signup/"
    send_templated_mail(template_name, context, recipients,
                        sender=sender, bcc=bcc, fail_silently=fail_silently,
                        files=files, html=html)


def send_case_mail(template_name,
                   context,
                   recipients,
                   sender=None,
                   bcc=None,
                   fail_silently=False,
                   files=None,
                   html=True):
    context['case']['case_url'] = get_vc_case_path(context)
    context['case']['vt_case_url'] = get_vt_case_path(context)
    context['signup_url'] = f"{settings.KB_SERVER_NAME}/vince/comm/signup/"
    send_templated_mail(template_name, context, recipients, sender=sender, bcc=bcc,
                        fail_silently=fail_silently, files=files, html=html)
                        


#This function is simply to generate the email with context and return
# so it can be added to activity log

def get_mail_content(ticket, template_name):
    context = safe_template_context(ticket)
    
    if 'queue' in context:
        locale = context['queue'].get('locale') or VINCE_EMAIL_FALLBACK_LOCALE
    else:
        locale = VINCE_EMAIL_FALLBACK_LOCALE

    try:
        t = EmailTemplate.objects.get(template_name__iexact=template_name, locale=locale)
    except EmailTemplate.DoesNotExist:
        try:
            t = EmailTemplate.objects.get(template_name__iexact=template_name, locale__isnull=True)
        except EmailTemplate.DoesNotExist:
            logger.warning('template "%s" does not exist, no mail sent', template_name)
            return  # just ignore if template doesn't exist       
    
    content = from_string(
        "%s" % (t.plain_text)
    ).render(context)

    return content
    
    
def send_templated_mail(template_name,
                        context,
                        recipients,
                        sender=None,
                        bcc=None,
                        fail_silently=False,
                        files=None,
                        html=True,
                        replyto=True):
    """
    send_templated_mail() is a wrapper around Django's e-mail routines that
    allows us to easily send multipart (text/plain & text/html) e-mails using
    templates that are stored in the database. This lets the admin provide
    both a text and a HTML template for each message.

    template_name is the slug of the template to use for this message (see
        models.EmailTemplate)

    context is a dictionary to be used when rendering the template

    recipients can be either a string, eg 'a@b.com', or a list of strings.

    sender should contain a string, eg 'My Site <me@z.com>'. If you leave it
        blank, it'll use settings.DEFAULT_FROM_EMAIL as a fallback.

    bcc is an optional list of addresses that will receive this message as a
        blind carbon copy.

    fail_silently is passed to Django's mail routine. Set to 'True' to ignore
        any errors at send time.

    files can be a list of tuples. Each tuple should be a filename to attach,
        along with the File objects to be read. files can be blank.
    """

    if 'queue' in context:
        locale = context['queue'].get('locale') or VINCE_EMAIL_FALLBACK_LOCALE
    else:
        locale = VINCE_EMAIL_FALLBACK_LOCALE
 

    context['homepage'] = f"{settings.KB_SERVER_NAME}/vince/comm/dashboard/"
    
    try:
        t = EmailTemplate.objects.get(template_name__iexact=template_name, locale=locale)
    except EmailTemplate.DoesNotExist:
        try:
            t = EmailTemplate.objects.get(template_name__iexact=template_name, locale__isnull=True)
        except EmailTemplate.DoesNotExist:
            logger.warning('template "%s" does not exist, no mail sent', template_name)
            return  # just ignore if template doesn't exist

    subject_part = from_string(
        VINCE_EMAIL_SUBJECT_TEMPLATE % {
            "subject": t.subject
        }).render(context).replace('\n', '').replace('\r', '')

    footer_file = os.path.join('vince-email', locale, 'email_text_footer.txt')

    text_part = from_string(
        "%s{%% include '%s' %%}" % (t.plain_text, footer_file)
    ).render(context)

    email_html_base_file = os.path.join('vince-email', locale, 'email_html_inline.html')
    # keep new lines in html emails

    #this really only matters for the HTML notifications that are sent out, but
    # need to be there so we don't get key error
    if context.get('team'):
        context['team']['phone'] = context['team'].get('phone', settings.DEFAULT_PHONE_NUMBER)
        context['team']['email'] = context['team'].get('email', settings.DEFAULT_REPLY_EMAIL)
    else:
        context['team'] = {}
        context['team']['phone'] = settings.DEFAULT_PHONE_NUMBER
        context['team']['email'] = context['team'].get('email', settings.DEFAULT_REPLY_EMAIL)
        
    if 'comment' in context:
        if context['comment']:
            context['comment'] = mark_safe(context['comment'].replace('\r\n', '<br>'))


    html_part = from_string(
        "{%% extends '%s' %%}{%% block title %%}"
        "%s"
        "{%% endblock %%}{%% block content %%}%s{%% endblock %%}"
        "{%% block phone %%}%s{%% endblock %%}{%% block email %%}%s{%% endblock %%}" %
        (email_html_base_file, t.heading, t.html, context['team']['phone'], context['team']['email'])
    ).render(context)

    if isinstance(recipients, str):
        if recipients.find(','):
            recipients = recipients.split(',')
    elif type(recipients) != list:
        recipients = [recipients]

    if sender == None:
        sender = f"{settings.DEFAULT_VISIBLE_NAME} <{settings.DEFAULT_FROM_EMAIL}>"

    if replyto:
        #if replyto, add default reply-to-email and headers
        #this is usually an auto-notification
        msg = EmailMultiAlternatives(subject_part, text_part,
                                     sender or settings.DEFAULT_FROM_EMAIL,
                                     recipients, bcc=bcc,
                                     reply_to=[settings.DEFAULT_REPLY_TO_EMAIL],
                                     headers=settings.DEFAULT_EMAIL_HEADERS)
    else:
        msg = EmailMultiAlternatives(subject_part, text_part,
                                     sender or settings.DEFAULT_FROM_EMAIL,
                                     recipients, bcc=bcc)
    if html:
        msg.attach_alternative(html_part, "text/html")

    if files:
        for filename, filefield in files:
            mime = mimetypes.guess_type(filename)
            if mime[0] is not None and mime[0] == "text/plain":
                with open(filefield.path, 'r') as attachedfile:
                    content = attachedfile.read()
                    msg.attach(filename, content)
            else:
                if six.PY3:
                    msg.attach_file(filefield.path)
                else:
                    with open(filefield.path, 'rb') as attachedfile:
                        content = attachedfile.read()
                        msg.attach(filename, content)

    logger.debug('Sending email using template {} with subject "{}" to {!r}'.format(template_name, subject_part, recipients))

    try:
         return msg.send()

    except SMTPException as e:
        logger.exception('SMTPException raised while sending email to {}'.format(recipients))
        logger.debug('SMTPException raised while sending email to {}'.format(recipients))
        if not fail_silently:
            raise e
        return 0


def get_public_phone(contact):
    #lookup vincecomm contact
    vc_contact = VinceCommContact.objects.filter(uuid=contact.uuid).first()
    if vc_contact:
        phone = vc_contact.get_phone_number()
        if phone != "":
            return phone
    return settings.DEFAULT_PHONE_NUMBER


def get_public_email(contact):
    #lookup vincecomm contact
    vc_contact = VinceCommContact.objects.filter(uuid=contact.uuid).first()
    if vc_contact:
        email = vc_contact.get_list_email()
        if email != "":
            return email
    return settings.DEFAULT_REPLY_EMAIL
    
def team_template_context(team):
    #does this team have settings                                                                 
    context = {}
    try:
        if team.groupsettings.team_signature:
            context['team_signature'] = team.groupsettings.team_signature
        else:
            context['team_signature'] = settings.DEFAULT_EMAIL_SIGNATURE

        context['phone'] = get_public_phone(team.groupsettings.contact)
        context['email'] = get_public_email(team.groupsettings.contact)
    except:
        context['phone'] = context.get('phone', settings.DEFAULT_PHONE_NUMBER)
        context['email'] = context.get('email', settings.DEFAULT_REPLY_EMAIL)
        context['team_signature'] = context.get('team_signature', settings.DEFAULT_EMAIL_SIGNATURE)
    return context
    
def safe_template_context(ticket):
    """
    Return a dictionary that can be used as a template context to render
    comments and other details with ticket or queue parameters. Note that
    we don't just provide the Ticket & Queue objects to the template as
    they could reveal confidential information. Just imagine these two options:
        * {{ ticket.queue.email_box_password }}
        * {{ ticket.assigned_to.password }}
    Ouch!
    The downside to this is that if we make changes to the model, we will also
    have to update this code. Perhaps we can find a better way in the future.
    """

    context = {
        'queue': queue_template_context(ticket.queue),
        'ticket': ticket_template_context(ticket),
        'team': team_template_context(ticket.queue.team)
    }

    context['ticket']['queue'] = context['queue']

    return context


def safe_case_context(case, action=None):
    context = {
        'case': case_template_context(case),
        'team': team_template_context(case.team_owner)
    }
    
    if action:
        context.update({
        'action': caseaction_template_context(action)
        })

    return context

def queue_template_context(queue):
    context = {}

    for field in ('title', 'slug', 'email_address', 'from_address'):
        attr = getattr(queue, field, None)
        if callable(attr):
            context[field] = attr()
        else:
            context[field] = attr

    return context


def ticket_template_context(ticket):
    context = {}

    for field in ('title', 'created', 'modified', 'submitter_email',
                  'status', 'get_status_display', 'on_hold', 'description',
                  'resolution', 'priority', 'get_priority_display',
                  'last_escalation', 'ticket', 'ticket_for_url',
                  'get_status', 'ticket_url', 'staff_url', '_get_assigned_to',
                  'case'
                  ):
        attr = getattr(ticket, field, None)
        if callable(attr):
            context[field] = '%s' % attr()
        else:
            context[field] = attr
    context['assigned_to'] = context['_get_assigned_to']

    return context

def case_template_context(case):
    context = {}

    for field in ('vuid', 'created', 'modified', 'on_hold', 'status',
                  'summary', 'owner', 'case_request', 'product_name',
                  'product_version', 'title', 'due_date', 'template',
                  'case_for_url', 'get_status', 'vu_vuid', 'vutitle',
                  '_get_assigned_to'
                  ):
        attr = getattr(case, field, None)
        if callable(attr):
            context[field] = '%s' % attr()
        else:
            context[field] = attr

    context['assigned_to'] = context['_get_assigned_to']
    #logger.debug(context)
    return context

def caseaction_template_context(action):
    context = {}

    for field in ('vendor', 'notification', 'post', 'date', 'last_edit',
                  'title', 'comment', 'user', 'new_status', 'artifact'
                  ):
        attr = getattr(action, field, None)
        if callable(attr):
            context[field] = '%s' % attr()
        else:
            context[field] = attr
        
    return context
    

def send_approval_email(contact, case):
    context = safe_case_context(case, None)
    send_case_mail("vendor_approve_stmt", context, contact.get_official_emails())

def send_vendor_approval_emails(contacts, case):
    for contact in contacts:
        contact = Contact.objects.filter(id=contact).first()
        send_approval_email(contact, case)
    
def send_vendor_email_notification(contacts, case, subject, body):
    context = safe_case_context(case, None)

    context['body'] = mark_safe(body)
    context['subject'] = subject

    for contact in contacts:
        contact = Contact.objects.filter(id=contact).first()
        # don't send inactive contacts emails
        if contact.active:
            send_case_mail("vendor_notify_newcase", context, contact.get_official_emails())

def send_participant_email_notification(contacts, case, subject, body):
    context = safe_case_context(case, None)
    context['body'] = mark_safe(body)
    context['subject'] = subject

    send_case_mail("participant_notify_newcase", context, contacts)

def send_submitter_email_notification(contacts, ticket, subject, body, vtcr=None):
    context = safe_template_context(ticket)
    context['body'] = mark_safe(body)
    context['subject'] = subject
    context['signup_url'] = f"{settings.KB_SERVER_NAME}/vince/comm/signup/"

    if vtcr:
        context['vrf'] = vtcr.vrf_id
        context['caseurl'] = f"{settings.KB_SERVER_NAME}{vtcr.get_absolute_url()}"

    send_templated_mail("blank_body", context, contacts, html=False)


def send_reset_mfa_email(user, ticket, template):
    context = safe_template_context(ticket)

    send_templated_mail(template, context, [user.email], sender=settings.DEFAULT_REPLY_EMAIL, html=False, replyto=False)
    
def send_regular_email_notification(contacts, subject, body):
    context = {}
    context['body'] = mark_safe(body)
    context['subject'] = subject
    context['signup_url'] = f"{settings.KB_SERVER_NAME}/vince/comm/signup/"

    send_templated_mail("blank_body_no_sig", context, contacts, sender=settings.DEFAULT_REPLY_EMAIL, html=False, replyto=False)


def send_noreply_email_notification(contacts, subject, body):
    context = {}
    context['body'] = mark_safe(body)
    context['subject'] = subject
    context['signup_url'] = f"{settings.KB_SERVER_NAME}/vince/comm/signup/"

    send_templated_mail("blank_body_no_sig", context, contacts, sender=settings.DEFAULT_REPLY_TO_EMAIL, html=False, replyto=True)
    
def send_email_notification(contacts, context, subject, body):

#    for contact in contacts:
#        contact = Contact.objects.filter(id=contact).first()
#        logger.debug(contact.get_emails())
    send_templated_mail("vendor_notify_newcase", context, contacts)
    

def send_user_approve_notification(user):
    context = {}
    context['login_url'] = f"{settings.KB_SERVER_NAME}/vince/"
    context['team_signature'] = settings.DEFAULT_EMAIL_SIGNATURE
    send_templated_mail("approve_user", context, user)


def send_sns(error):
    subject = "Problem with sending pgp email"
    try:
        client = boto3.client('sns', settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_ERROR_SNS_ARN,
            Subject=subject,
            Message=error)
        logger.debug("Response:{}".format(response))

    except:
        logger.debug('Error publishing to SNS')


def encrypt_mail(contents, admin_email):
    #get pgp email
    tf = tempfile.TemporaryDirectory()
    gpg = gnupg.GPG(gnupghome=tf.name)
    try:
        import_result = gpg.import_keys(admin_email.pgp_key_data)
        pgp_fingerprint = import_result.fingerprints
        keys = gpg.list_keys()
        encrypted_data = gpg.encrypt(contents, pgp_fingerprint, always_trust=True)
        logger.debug(encrypted_data.ok)
        logger.debug(encrypted_data.status)
        logger.debug(encrypted_data.stderr)
    except Exception as e:
        logger.warning("PGP Encryption failed due to error "+str(e))
        send_sns(str(e))
        return None
    return encrypted_data

def get_base64_file(file_path):
    bfile = file_path.open()
    b_str = base64.b64encode(bfile.read())
    return b_str


def send_encrypted_mail(to_email, subject, contents, attachment=None):

    admin_email = to_email
    
    msg = Message()
    msg.add_header(_name="Content-Type", _value="multipart/mixed", protected_headers="v1")
    msg["From"] = settings.DEFAULT_REPLY_EMAIL
    msg["To"] = admin_email.email
    msg['Subject'] = subject
    
    msg_text = Message()
    msg_text.add_header(_name="Content-Type", _value="multipart/mixed")
    msg_text.add_header(_name="Content-Language", _value="en-US")

    msg_body = Message()
    msg_body.add_header(_name="Content-Type", _value="text/plain", charset="utf-8")
    msg_body.add_header(_name="Content-Transfer-Encoding", _value="quoted-printable")
    pay_load = contents + 2*"\n"
    msg_body.set_payload(pay_load.encode())

    msg_attachment = Message()
    if attachment:
        msg_attachment.add_header(_name="Content-Type", _value=attachment.mime_type, name=attachment.filename)
        msg_attachment.add_header(_name="Content-Transfer-Encoding", _value="base64")
        msg_attachment.add_header(_name="Content-Disposition", _value="attachment", filename=attachment.filename)
        msg_attachment.set_payload(get_base64_file(attachment.file))

    msg_text.attach(msg_body)

    if attachment:
        msg_text.attach(msg_attachment)

    msg.attach(msg_text)

    pgp_msg = MIMEBase(_maintype="multipart", _subtype="encrypted", protocol="application/pgp-encrypted")
    pgp_msg["From"] = settings.DEFAULT_REPLY_EMAIL
    pgp_msg["To"] = admin_email.email
    pgp_msg["Subject"] = subject
    
    pgp_msg_part1 = Message()
    pgp_msg_part1.add_header(_name="Content-Type", _value="application/pgp-encrypted")
    pgp_msg_part1.add_header(_name="Content-Description", _value="PGP/MIME version identification")
    pgp_msg_part1.set_payload("Version: 1" + "\n")

    pgp_msg_part2 = Message()
    pgp_msg_part2.add_header(_name="Content-Type", _value="application/octet-stream", name="encrypted.asc")
    pgp_msg_part2.add_header(_name="Content-Description", _value="OpenPGP encrypted message")
    pgp_msg_part2.add_header(_name="Content-Disposition", _value="inline", filename="encrypted.asc")
    try:
        payload = encrypt_mail(msg.as_string(), admin_email)
    except Exception as e:
        logger.warning("Encrypting PGP Email failed due to error "+str(e))
        return f"Error encrypting data. Check key for {admin_email.email}"

    if payload == None:
        return f"Error encrypting data. Check log email for problems"

    if payload.ok == False:
        return f"Error encrypting data: {payload.status} {payload.stderr}"
    else:
        payload = str(payload)
    
    pgp_msg_part2.set_payload(payload)

    pgp_msg.attach(pgp_msg_part1)
    pgp_msg.attach(pgp_msg_part2)
    
    sesclient = boto3.client('ses', 'us-east-1')
    try:
        response = sesclient.send_raw_email(
            Destinations = admin_email.email.split(","),
            RawMessage={
                'Data': pgp_msg.as_string()
            },
            Source= f'{settings.ORG_NAME} <{settings.CONTACT_EMAIL}>'
        )
    except ClientError as e:
        logger.debug("ERROR SENDING EMAIL")
        send_sns(e.response['Error']['Message'])
        return e.response['Error']['Message']
    except:
        logger.debug("ERROR SENDING EMAIL - Not a ClientError")
        send_sns(traceback.format_exc())
        return traceback.format_exc()
    else:
        logger.debug("Email Sent! Message ID: ")
        logger.debug(response['MessageId'])

    return None


def send_smime_encrypted_mail(cert, subject, contents, attachment=None):

    tf = tempfile.NamedTemporaryFile()
    with open(tf.name, 'wb+') as destination:
        for chunk in cert.certificate.file.chunks():
            destination.write(chunk)

    msg = MIMEText(contents)
    msg_str = msg.as_string()
            
    buf = BIO.MemoryBuffer(msg_str.encode())

    Rand.load_file('randpool.dat', -1)

    # Instantiate an SMIME object.
    s = SMIME.SMIME()
    
    x509 = X509.load_cert(tf.name)
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)
    
    # Set cipher: 3-key triple-DES in CBC mode.
    s.set_cipher(SMIME.Cipher('des_ede3_cbc'))
    
    # Encrypt the buffer.
    p7 = s.encrypt(buf)
        
    # Output p7 in mail-friendly format.
    out = BIO.MemoryBuffer()
    out.write(f'From: {settings.DEFAULT_REPLY_EMAIL}\n')
    out.write(f'To: {cert.email}\n')
    out.write(f'Subject: {subject}\n')
    out.write(' \n')
    s.write(out, p7)
    
    sesclient = boto3.client('ses', 'us-east-1')
    try:
        response = sesclient.send_raw_email(
            Destinations = [cert.email],
            RawMessage={
                'Data': out.read()
            },
            Source= f'{settings.ORG_NAME} <{settings.CONTACT_EMAIL}>'
        )
    except ClientError as e:
        logger.debug("ERROR SENDING EMAIL")
        send_sns(e.response['Error']['Message'])
        return e.response['Error']['Message']
    except:
        logger.debug("ERROR SENDING EMAIL - Not a ClientError")
        send_sns(traceback.format_exc())
        return traceback.format_exc()
    else:
        logger.debug("Email Sent! Message ID: ")
        logger.debug(response['MessageId'])

    return None

def send_daily_digest_mail(user, text):
    subject = f'VINCE Daily Activity'

    context = {
        'digest': text,
        'username': user.usersettings.preferred_username,
        'login_url': f"{settings.SERVER_NAME}"
    }

    html = get_html_preference(user)

    send_templated_mail(
        'vt_daily_digest',
        context,
        recipients=user.email,
        fail_silently=True,
        files=None,
        html=html
    )

def send_email_to_all(to_group, subject, content, from_user, ticket):
    if to_group == '1':
        # get all vendors = get all groups with contacts
        groups = Group.objects.using('vincecomm').all().exclude(groupcontact__contact__isnull=True)
        vendor_groups = groups.exclude(groupcontact__contact__vendor_type='Contact')
        to_list = User.objects.using('vincecomm').filter(is_active=True, groups__in=vendor_groups).distinct()
        to_list_str = 'all VINCE vendor users'
        gcs = GroupContact.objects.filter(group__in=vendor_groups).values_list('contact__id', flat=True)
        list_emails = VinceCommEmail.objects.filter(contact__id__in=gcs, email_list=True, status=True)
    elif to_group == '2':
        # get all admins                                                       
        group_emails = VinceCommGroupAdmin.objects.all().values_list('email__email', flat=True).distinct()
        to_list = User.objects.using('vincecomm').filter(is_active=True, email__in=group_emails)
        to_list_str = 'all group admins'
    elif to_group == '3':
        # get all users                                                       
        to_list = User.objects.using('vincecomm').filter(is_active=True)
        to_list_str = 'all users'
        logger.debug(to_list)
    elif to_group == '4':
        #staff
        to_list = User.objects.using('vincecomm').filter(is_active=True, is_staff=True)
        to_list_str = 'all staff'
        logger.debug(to_list)
    elif to_group == '5':
        #find vendors without users
        group_user = [group.groupcontact.contact.vendor_id for group in Group.objects.using('vincecomm').exclude(groupcontact__isnull=True) if len(group.user_set.all()) > 0]
        contact_without_users = Contact.objects.filter(active=True, vendor_type='Vendor').exclude(id__in=group_user).values_list('id', flat=True)
        to_list = EmailContact.objects.filter(status=True, contact__id__in=contact_without_users, email_function__in=['TO', 'CC'])
        to_list_str = "all vendors without users"
        logger.debug(to_list)


    #send all emails individually
    emails = []
    for u in to_list:
        try:
            send_noreply_email_notification([u.email], subject, content)
            emails.append(u.email)
        except:
            logger.warning(f"Error sending email to user {u.email}")
            logger.warning(traceback.format_exc())

    if to_group == '1':
        #also send to email lists
        for u in list_emails:
            if u.email not in emails:
                try:
                    send_noreply_email_notification([u.email], subject, content)
                    emails.append(u.email)
                except:
                    logger.warning(f"Error sending email to {u.email}")
                    logger.warning(traceback.format_exc())
                    
                
            
    ticket = Ticket.objects.filter(id=int(ticket)).first()

    if ticket:
        #now add followup that it is done
        followup = FollowUp(ticket=ticket,
                            title=f"Sent {len(emails)} emails to {to_list_str}",
                            user=from_user,
                            comment=", ".join(emails))
        followup.save()
