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
import re
from datetime import date
import logging

from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.translation import ugettext as _

from vince.lib import process_attachments, get_oof_users
from vince.mailer import safe_template_context, send_ticket_mail
from vince.models import Ticket, FollowUp, TicketChange, TicketCC, UserRole, UserAssignmentWeight, CalendarEvent, VinceReminder


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def unsubscribe_ticket(ticket, user):
    try:
        TicketCC.objects.get(user=user, ticket=ticket).delete()
    except TicketCC.DoesNotExist:
        logger.debug(f"User {user} is not subscribed to {ticket}")
        pass

def subscribe_ticket(ticket, user):
    if not TicketCC.objects.filter(user=user, ticket=ticket):
        tf = TicketCC(ticket=ticket, user=user)
        tf.save()
    else:
        logger.debug(f"User {user} already subscribe to ticket {ticket}")


#this algorithm is based on the smooth weighted round robin here:
#https://github.com/nginx/nginx/commit/52327e0627f49dbda1e8db695e63a4b0af4448b1
def get_next_assignment(data):
    if len(data) == 0:
        return None
    if len(data) == 1:
        return data[0].user

    total_weight = 0
    result = None
    
    for entry in data:
        entry.current_weight += entry.effective_weight
        total_weight += entry.effective_weight
        if entry.effective_weight < entry.weight:
            entry.effective_weight += 1
        if not result or result.current_weight < entry.current_weight:
            result = entry
        entry.save()
    if not result:  # this should be unreachable, but check anyway
        logger.warning("Auto Assignment error")
        return None
    
    result.current_weight -= total_weight
    result.save()
    return result.user

        
def auto_assignment(role, exclude=None):
    #get users for this role

    users = UserAssignmentWeight.objects.filter(role__id=role)

    #are any of these users OOF today?
    oof_users = get_oof_users()
    if oof_users:
        users = users.exclude(user__in=oof_users)

    if exclude:
        #these are users that should be excluded bc they are requesting it (ex. vulnote approval)
        users = users.exclude(user=exclude)
    
    if users:
        return get_next_assignment(users)

    return None

        
def update_ticket(request, ticket_id):


    ticket = get_object_or_404(Ticket, id=ticket_id)

    logger.debug(f"Updating ticket: {ticket.id}")
    logger.debug(f"Ticket update post: {request.POST}")

    date_re = re.compile(
        r'(?P<month>\d{1,2})/(?P<day>\d{1,2})/(?P<year>\d{4})$')

    comment = request.POST.get('comment', '')
    new_status = int(request.POST.get('new_status', ticket.status))
    title = request.POST.get('title', '')
    owner = int(request.POST.get('owner', -1))
    priority = int(request.POST.get('priority', ticket.priority))
    due_date_year = int(request.POST.get('due_date_year', 0))
    due_date_month = int(request.POST.get('due_date_month', 0))
    due_date_day = int(request.POST.get('due_date_day', 0))
    subscribe = bool(request.POST.get('subscribe', False))
    unsubscribe = bool(request.POST.get('unsubscribe', False))
    auto_assign = int(request.POST.get('auto', 0))
    ticket_status_changed=False
    # NOTE: jQuery's default for dates is mm/dd/yy
    # very US-centric but for now that's the only format supported
    # until we clean up code to internationalize a little more
    due_date = request.POST.get('due_date', None) or None

    if due_date is not None:
        # based on Django code to parse dates:
        # https://docs.djangoproject.com/en/2.0/_modules/django/utils/dateparse/
        match = date_re.match(due_date)
        if match:
            kw = {k: int(v) for k, v in match.groupdict().items()}
            due_date = date(**kw)
    else:
        # old way, probably deprecated?
        if not (due_date_year and due_date_month and due_date_day):
            due_date = ticket.due_date
        else:
            # NOTE: must be an easier way to create a new date than doing it this way?
            if ticket.due_date:
                due_date = ticket.due_date
            else:
                due_date = timezone.now()
            due_date = due_date.replace(due_date_year, due_date_month, due_date_day)


    no_changes = all([
        not request.FILES,
        not comment,
        new_status == ticket.status,
        title == ticket.title or title == '',
        priority == int(ticket.priority),
        due_date == ticket.due_date,
        (owner == -1) or (not owner and not ticket.assigned_to) or
        (owner and User.objects.get(id=owner) == ticket.assigned_to),
    ])

    # Only change to the ticket is toggling the watcher
    if subscribe:
        logger.debug(f"Subscribing user {request.user} to {ticket.id}.")
        subscribe_ticket(ticket, request.user)
        if no_changes:
            return return_to_ticket(request.user, ticket)
    elif unsubscribe:
        unsubscribe_ticket(ticket, request.user)
        logger.debug(f"Unsubscribing user {request.user} from {ticket.id}.")
        if no_changes:
            return return_to_ticket(request.user, ticket)
    # No changes to the ticket
    elif no_changes:
        logger.debug(f"No changes to ticket {ticket.id}. Returning")
        return return_to_ticket(request.user, ticket)



    # We need to allow the 'ticket' and 'queue' contexts to be applied to the
    # comment.
    context = safe_template_context(ticket)

    from django.template import engines
    template_func = engines['django'].from_string
    # this prevents system from trying to render any template tags
    # broken into two stages to prevent changes from first replace being themselves
    # changed by the second replace due to conflicting syntax
    comment = comment.replace('{%', 'X-HELPDESK-COMMENT-VERBATIM').replace('%}', 'X-HELPDESK-COMMENT-ENDVERBATIM')
    comment = comment.replace('X-HELPDESK-COMMENT-VERBATIM', '{% verbatim %}{%').replace('X-HELPDESK-COMMENT-ENDVERBATIM', '%}{% endverbatim %}')
    # render the neutralized template
    comment = template_func(comment).render(context)

    if owner == -1 and ticket.assigned_to:
        owner = ticket.assigned_to.id


    f = FollowUp(ticket=ticket, date=timezone.now(), comment=comment)
    f.user = request.user

    reassigned = False

    old_owner = ticket.assigned_to
    if owner != -1:
        if owner != 0 and ((ticket.assigned_to and owner != ticket.assigned_to.id) or not ticket.assigned_to):
            new_user = User.objects.get(id=owner)
            if auto_assign:
                f.title = _('Auto Assigned to %(username)s') % {
                    'username': new_user.get_username(),
                }
            else:
                f.title = _('Assigned to %(username)s') % {
                    'username': new_user.get_username(),
                }
            ticket.assigned_to = new_user
            reassigned = True
        # user changed owner to 'unassign'
        elif owner == 0 and ticket.assigned_to is not None:
            f.title = _('Unassigned')
            ticket.assigned_to = None
        elif owner == -2:
            #AUTO ASSIGN
            pass

    old_status_str = ticket.get_status_display()
    old_status = ticket.status
    if new_status != ticket.status:
        ticket.status = new_status
        ticket.save()
        f.new_status = new_status
        ticket_status_changed = True
        if f.title:
            f.title += ' and %s' % ticket.get_status_display()
        else:
            f.title = '%s' % ticket.get_status_display()

    if not f.title:
        if f.comment:
            f.title = _('Comment')
        else:
            f.title = _('Updated')

    # Todo update this
    f.save()

    # if reassignment, followup save will prevent sending emails to new
    # assignee even though the ticket.assigned_to hasn't been saved
    # the signal might take longer to process
    
    files = process_attachments(f, request.FILES.getlist('attachment'))

    if title and title != ticket.title:
        c = TicketChange(
            followup=f,
            field=_('Title'),
            old_value=ticket.title,
            new_value=title,
        )
        c.save()
        ticket.title = title

    if new_status != old_status:
        logger.debug("IN TICKET CHANGE STATUS")
        c = TicketChange(
            followup=f,
            field=_('Status'),
            old_value=old_status_str,
            new_value=ticket.get_status_display(),
        )
        c.save()

    if ticket.assigned_to != old_owner:
        c = TicketChange(
            followup=f,
            field=_('Owner'),
            old_value=old_owner,
            new_value=ticket.assigned_to,
        )
        c.save()

    if priority != ticket.priority:
        c = TicketChange(
            followup=f,
            field=_('Priority'),
            old_value=ticket.priority,
            new_value=priority,
        )
        c.save()
        ticket.priority = priority

    if due_date != ticket.due_date:
        c = TicketChange(
            followup=f,
            field=_('Due on'),
            old_value=ticket.due_date,
            new_value=due_date,
        )
        c.save()
        ticket.due_date = due_date

    if new_status in (Ticket.RESOLVED_STATUS, Ticket.CLOSED_STATUS):
        if new_status == Ticket.RESOLVED_STATUS or not ticket.resolution:
            ticket.resolution = comment

    messages_sent_to = []

    # ticket might have changed above, so we re-instantiate context with the
    # (possibly) updated ticket.
    context = safe_template_context(ticket)
    context.update(
        resolution=ticket.resolution,
        comment=f.comment,
    )

    # Send comment or new status emails to the submitter and the cc
    if (f.comment or (
            f.new_status in (Ticket.RESOLVED_STATUS,
                             Ticket.CLOSED_STATUS))):
        if f.new_status == Ticket.RESOLVED_STATUS:
            template = 'resolved_'
        elif f.new_status == Ticket.CLOSED_STATUS:
            template = 'closed_'
        else:
            template = 'updated_'

        template_suffix = 'submitter'


        if ticket.submitter_email != request.user.email:
            #Is this a vincetrack user?
            vt_user = User.objects.filter(username=ticket.submitter_email).first()
            if vt_user:
                send_ticket_mail(
                    template + template_suffix,
                    context,
                    recipients=ticket.submitter_email,
                    sender=ticket.queue.from_address,
                    fail_silently=True,
                    files=files,
                )
            messages_sent_to.append(ticket.submitter_email)

        template_suffix = 'cc'
        messages_sent_to = email_ticketcc(ticket, template + template_suffix, context, files, messages_sent_to)

    # Send email to ticket owner (assignee)
    if ticket.assigned_to and \
            request.user != ticket.assigned_to and \
            ticket.assigned_to.email and \
            ticket.assigned_to.email not in messages_sent_to:
        # We only send e-mails to staff members if the ticket is updated by
        # another user. The actual template varies, depending on what has been
        # changed.
        if reassigned:
            template_staff = 'assigned_owner'
        elif f.new_status == Ticket.RESOLVED_STATUS:
            template_staff = 'resolved_owner'
        elif f.new_status == Ticket.CLOSED_STATUS:
            template_staff = 'closed_owner'
        else:
            template_staff = 'updated_owner'

        if (not reassigned or
            (reassigned and
             ticket.assigned_to.usersettings.settings.get(
                 'email_on_ticket_assign', False))) or \
                (not reassigned and
                 ticket.assigned_to.usersettings.settings.get(
                     'email_on_ticket_change', False)):
            send_ticket_mail(
                template_staff,
                context,
                recipients=ticket.assigned_to.email,
                sender=ticket.queue.from_address,
                fail_silently=True,
                files=files,
            )
            messages_sent_to.append(ticket.assigned_to.email)

    logger.debug("saving ticket")

    if ticket_status_changed and ticket.assigned_to == None and new_status == Ticket.CLOSED_STATUS:
        ticket.assigned_to = request.user
        c = TicketChange(
            followup=f,
            field=_('Owner'),
            old_value=None,
            new_value=ticket.assigned_to,
        )
        c.save()
        #if ticket unassigned and ticket status changed
        # auto assign person closing ticket

    ticket.save()

    if f.new_status == Ticket.CLOSED_STATUS:
        #check to see if there are reminders about this ticket
        reminders = VinceReminder.objects.filter(ticket=ticket)
        for r in reminders:
            r.delete()
            

    return return_to_ticket(request.user, ticket)


def return_to_ticket(user, ticket):
    """Helper function for update_ticket"""
    return HttpResponseRedirect(ticket.get_absolute_url())

def email_ticketcc(ticket, template, context, files, messages_sent_to):
    # Send email to people that are cc'd on ticket (watch list)
    for cc in ticket.ticketcc_set.all():
        if cc.email_address not in messages_sent_to:
            send_ticket_mail(
                template,
                context,
                recipients=cc.email_address,
                sender=ticket.queue.from_address,
                fail_silently=True,
                files=files,
            )
            messages_sent_to.append(cc.email_address)

    return messages_sent_to

