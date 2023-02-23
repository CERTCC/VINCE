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
from django import template
from django.core.paginator import Paginator
from django.db.models import Q
register = template.Library()

@register.filter
def email_lists(emails):
    return emails.filter(email_list=True)


@register.filter
def unread(thread, user):
    """
    Check whether there are any unread messages for a particular thread for a user.
    """
    return bool(thread.userthread_set.filter(user=user, unread=True))


@register.filter
def unread_thread_count(user):
    """
    Return the number of Threads with unread messages for this user, useful for highlighting on an account bar for example.
    """
    try:
        from vinny.models import Thread
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load Thread model.")
    return Thread.unread(user).count()


@register.filter
def published(case, objects=None):
    try:
        from vinny.models import Case
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load Case model.")
    try:
        return case.filter(note__datefirstpublished__isnull=False)
    except AttributeError:
        #if objects:
        #return objects.filter(status=Case.OPEN_STATUS)
        return []

@register.filter
def open(case, objects=None):
    try:
        from vinny.models import Case
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load Case model.")
    try:
        return case.filter(status=Case.ACTIVE_STATUS).exclude(note__datefirstpublished__isnull=False)
    except AttributeError:
        if objects:
            return objects.filter(status=Case.ACTIVE_STATUS)
        return []

@register.filter
def not_last_users(thread):
    try:
        from vinny.models import Thread
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load Thread model.")
    if thread.to_group:
        if thread.from_group:
            if thread.to_group != thread.from_group:
                # this is a message from CERT/CC to another Group
                return thread.users.exclude(id=thread.latest_message.sender.id)[:3]
        #this is a message to CERT/CC
        #x = thread.users.exclude(Q(id=thread.latest_message.sender.id) | Q(groups__groupcontact__contact__vendor_name=thread.to_group))[:3]
        #return x
        #get all senders of messages
    senders = thread.messages.exclude(sender__id=thread.latest_message.sender.id).distinct('sender__id').order_by('sender__id').values_list('sender__id', flat=True)
    return thread.users.filter(id__in=senders).distinct()[:3]

@register.filter
def not_in_group(thread):
    try:
        from vinny.models import Thread
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load Thread model.")
    u_list = []
    vendors = []
    if thread.to_group:
        vendors = thread.to_group.split(", ")
    if thread.from_group:
        vendors.extend(thread.from_group.split(", "))

    if vendors:
        users = thread.users.exclude(Q(id=thread.latest_message.sender.id) | Q(groups__groupcontact__contact__vendor_name__in=vendors))
        for u in users:
            try:
                if u.vinceprofile.vince_username not in u_list:
                    u_list.append(u.vinceprofile.vince_username)
            except:
                u_list.append(u.email)
        return u_list
    else:
        u_list = []
        users = thread.users.exclude(Q(id=thread.latest_message.sender.id))
        for u in users:
            u_list.append(u.vinceprofile.vince_username)
        return u_list

    
@register.filter
def group_logo(group_name, imgclass):
    try:
        from vinny.models import GroupContact
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load GroupContact model.")
    gc = GroupContact.objects.filter(group__name=group_name).first()
    if gc:
        if gc.get_logo():
            return f"<img class=\"hide-for-small-only {imgclass}\" src=\"{gc.get_logo()}\" title=\"{gc.group.name}\">"
        else:
            return f"<div class=\"{imgclass} text-center\" title=\"{group_name}\" style=\"background-color:{gc.logocolor};\"><span class=\"logo-initial\">{group_name[0]}</span></div>"
    return f"<div class=\"{imgclass} text-center\" style=\"background-color:black;\" title=\"{group_name}\"><span class=\"logo-initial\">{group_name[0]}</span></div>"



