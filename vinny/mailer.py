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
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
try:
    from django.utils import six
except:
    import six
from django.utils.safestring import mark_safe
import mimetypes
import os
from smtplib import SMTPException
from django.template import engines
import traceback

from_string = engines['django'].from_string

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def thread_template_context(thread):
    context = {}

    for field in ('subject', 'case', 'from_group', 'to_group'):
        attr = getattr(thread, field, None)
        if callable(attr):
            context[field] = '%s' % attr
        else:
            context[field] = attr
    if context['case']:
        context['case'] = f"{context['case'].vu_vuid}"
    
    return context

def message_template_context(message):
    context = {}
    
    for field in ('created', 'content'):
        attr = getattr(message, field, None)
        if callable(attr):
            context[field] = '%s' % attr
        else:
            context[field] = attr

    if message.sender:
        context["sender"] = message.sender.vinceprofile.vince_username
        
    return context


def team_template_context(team):
    #does this team have settings
    context = {}
    try:
        if team.coordinatorsettings.team_signature:
            context['team_signature'] = team.coordinatorsettings.team_signature
        else:
            context['team_signature'] = settings.DEFAULT_EMAIL_SIGNATURE

        phone = team.groupcontact.contact.get_phone_number()
        if phone:
            context['phone'] = phone
        else:
            context['phone'] = settings.DEFAULT_PHONE_NUMBER

        email = team.groupcontact.contact.get_list_email()
        if email:
            context['email'] = email
        else:
            context['email'] = settings.DEFAULT_REPLY_EMAIL
    except:
        context['phone'] = context.get('phone', settings.DEFAULT_PHONE_NUMBER)
        context['email'] = context.get('email', settings.DEFAULT_REPLY_EMAIL)
        context['team_signature'] = context.get('team_signature', settings.DEFAULT_EMAIL_SIGNATURE)
    return context

def safe_template_context(message):

    context = {
        'thread': thread_template_context(message.thread),
        'message': message_template_context(message),
        
    }

    if message.thread.case:
        if message.thread.case.team_owner:
            context.update({
                'team': team_template_context(message.thread.case.team_owner)
                }
            )
        

    return context

  
def send_newmessage_mail(message, user, notrack=True):

    if notrack:

        if user.groups.filter(name='vincetrack').exists():
            # don't notify vincetrack users, they will be notified from vincetrack
            return

    context = safe_template_context(message)

    context['message']['message_url'] = f"{settings.SERVER_NAME}{message.get_absolute_url()}"

    if message.thread.num_messages == 1:
        template = "new_message"
    else:
        template = "message_reply"

    try:
        s = user.vinceprofile.settings.get('email_preference', 1)
    except:
        # this user probably isn't setup to receive email
        return
    
    if int(s) == 1:
        html = True
    else:
        html = False
        
    send_templated_mail(
        template,
        context,
        recipients=user.email,
        fail_silently=True,
        files=None,
        html=html
    )


def send_group_mention_notification(user, group, mentioned_by, post, tracking=None):
     """Send group mention notification to user.  
        """
         
     item_url = post.case.get_absolute_url()
     tmpl_context = {
         'mentioned_by': mentioned_by,
         'group': group,
         'post_link': f"{settings.SERVER_NAME}{item_url}",
         'vuid': post.case.vu_vuid,
         'tracking':tracking
     }

     if post.case.team_owner:
         tmpl_context.update({
             'team': team_template_context(post.case.team_owner)
             }
         )
             

     s = user.vinceprofile.settings.get('email_preference', 1)
     if int(s) == 1:
         html = True
     else:
         html = False
     
     send_templated_mail(
         "group_tagged",
         tmpl_context,
         recipients=user.email,
         fail_silently=True,
         files=None,
         html=html
     )


def send_user_mention_notification(user, mentioned_by, post):
    """Send user mention notification to user.
       """
    subject = '[%s] You were tagged in a post' % (
        post.case.vu_vuid)
    item_url = post.case.get_absolute_url()
    tmpl_context = {
        'mentioned_by': mentioned_by,
        'post_link': f"{settings.SERVER_NAME}{item_url}",
        'vuid': post.case.vu_vuid
    }

    if post.case.team_owner:
        tmpl_context.update({
            'team': team_template_context(post.case.team_owner)
        }
    )
    
    s = user.vinceprofile.settings.get('email_preference', 1)
    if int(s) == 1:
        html = True
    else:
        html = False

        #if user.vinceprofile.settings.get('email_tags'):
    send_templated_mail(
        "user_tagged",
        tmpl_context,
        recipients=user.email,
        fail_silently=True,
        files=None,
        html=html
    )


def send_daily_digest_mail(user, text):
    subject = f'VINCE Daily Activity'

    context = {
        'digest': text,
        'username': user.vinceprofile.preferred_username,
        'login_url': f"{settings.KB_SERVER_NAME}/vince/",
        'team_signature': settings.DEFAULT_EMAIL_SIGNATURE
        
    }

    s = user.vinceprofile.settings.get('email_preference', 1)
    if int(s) == 1:
        html = True
    else:
        html = False

    send_templated_mail(
        'daily_digest',
        context,
        recipients=user.email,
        fail_silently=True,
        files=None,
        html=html
    )
        
def send_post_notification(post, user, tracking=None, role=0):
    """ Send post notifications to all users in case discussion """
    #### NEED TO ADD TRACKING PER GROUP ####
    
    subject = f'[{post.case.vu_vuid}] New Post in Case Discussion'
    item_url = post.case.get_absolute_url()
    tmpl_context = {
        'post_link': f"{settings.KB_SERVER_NAME}{item_url}",
        'vuid': post.case.vu_vuid,
        'tracking':tracking
    }

    if post.case.team_owner:
        tmpl_context.update({
            'team': team_template_context(post.case.team_owner)
        }
    )
    
    s = user.vinceprofile.settings.get('email_preference', 1)
    if int(s) == 1:
        html = True
    else:
        html = False
        

    if role == 1:
        template = "pinned_post"
    else:
        template = "new_post"
        
    send_templated_mail(
        template,
        tmpl_context,
        recipients=user.email,
        fail_silently=True,
        files=None,
        html=html
    )

    
def send_templated_mail(template_name,
                        context,
                        recipients,
                        sender=None,
                        bcc=None,
                        fail_silently=False,
			files=None,
                        html=True):
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
    from vince.models import EmailTemplate
    from vince.settings import VINCE_EMAIL_FALLBACK_LOCALE

    locale = VINCE_EMAIL_FALLBACK_LOCALE

    try:
        t = EmailTemplate.objects.using('default').filter(template_name__iexact=template_name, locale=locale).first()
    except EmailTemplate.DoesNotExist:
        try:
            t = EmailTemplate.objects.using('default').filter(template_name__iexact=template_name, locale__isnull=True).first()
        except EmailTemplate.DoesNotExist:
            logger.warning('template "%s" does not exist, no mail sent', template_name)
            return  # just ignore if template doesn't exist
    if not hasattr(t,'subject'):
        logger.error('template "%s" returns invalid object, no mail sent', template_name)
        return  # just ignore if template doesn't exist
    subject_part = from_string(
        "VINCE %(subject)s" % {
            "subject": t.subject
        }).render(context).replace('\n', '').replace('\r', '')

    footer_file = os.path.join('vince-email', locale, 'email_text_footer.txt')

    text_part = from_string(
        "%s{%% include '%s' %%}" % (t.plain_text, footer_file)
    ).render(context)

    email_html_base_file = os.path.join('vince-email', locale, 'email_html_inline.html')
    # keep new lines in html emails                                                                                              
    if 'comment' in context:
        if context['comment']:
            context['comment'] = mark_safe(context['comment'].replace('\r\n', '<br>'))

    #this really only matters for the HTML notifications that are sent out, but
    # need to be there so we don't get key error
    if context.get('team'):
        context['team']['phone'] = context['team'].get('phone', settings.DEFAULT_PHONE_NUMBER)
        context['team']['email'] = context['team'].get('email', settings.DEFAULT_REPLY_EMAIL)
    else:
        context['team'] = {}
        context['team']['phone'] = settings.DEFAULT_PHONE_NUMBER
        context['team']['email'] = context['team'].get('email', settings.DEFAULT_REPLY_EMAIL)
            
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
        
    msg = EmailMultiAlternatives(subject_part, text_part,
                                 sender or settings.DEFAULT_FROM_EMAIL,
                                 recipients, bcc=bcc,
                                 reply_to=[settings.DEFAULT_REPLY_TO_EMAIL],
                                 headers=settings.DEFAULT_EMAIL_HEADERS)
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

    logger.debug('Sending email using template {} with subject "{}" to {!r} from {}'.format(template_name, subject_part, recipients, sender))

    try:
         return msg.send()

    except SMTPException as e:
        logger.exception('SMTPException raised while sending email to {}'.format(recipients))
        logger.debug('SMTPException raised while sending email to {}'.format(recipients))
        if not fail_silently:
            raise e
        return 0
    except:
        logger.debug("Error sending email")
        logger.debug(traceback.format_exc())
        return
    
