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
from .apps import VinceTrackConfig
from vince.models import Ticket, TicketQueue, QueuePermissions, CasePermissions, CaseAssignment
from django.conf import settings

def is_in_group_vincetrack(user):
    return user.groups.filter(name=VinceTrackConfig.name).exists() 

def has_queue_read_access(user, queue):
    if user.is_superuser:
        return True
    return QueuePermissions.objects.filter(queue=queue, group__in=user.groups.all(), group_read=True).exists()

def has_queue_write_access(user, queue):
    if user.is_superuser:
        return True
    return QueuePermissions.objects.filter(queue=queue, group__in=user.groups.all(), group_write=True).exists()

def has_case_read_access(user, case):
    if user.is_superuser:
        return True
    if case.owner == user:
        return True
    #if assigned?
    if CaseAssignment.objects.filter(case=case, assigned=user).exists():
        return True
    return CasePermissions.objects.filter(case=case, group__in=user.groups.all(), group_read=True).exists()

def has_case_write_access(user, case):
    if user.is_superuser:
        return True
    if case.owner == user:
        return True
    #if assigned
    if CaseAssignment.objects.filter(case=case, assigned=user).exists():
        return True
    
    return CasePermissions.objects.filter(case=case, group__in=user.groups.all(), group_write=True).exists()

def has_case_publish_access(user, case):
    if user.is_superuser:
        return True
    return CasePermissions.objects.filter(case=case, group__in=user.groups.all(), publish=True).exists()

def get_rw_queues(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    queues = QueuePermissions.objects.filter(group__in=user_groups, group_read=True, group_write=True).values_list('queue', flat=True)
    return queues

def get_r_queues(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    queues = QueuePermissions.objects.filter(group__in=user_groups, group_read=True).values_list('queue', flat=True)
    return queues

def get_case_case_queue(case, user=None):
    if user:
        groups = CasePermissions.objects.filter(case=case, group_write=True,group__in=user.groups.all()).exclude(group__groupsettings__contact__isnull=True).values_list('group', flat=True)
    else:
        groups = CasePermissions.objects.filter(case=case, group_write=True).exclude(group__groupsettings__contact__isnull=True).values_list('group', flat=True)
    if groups:
        qperm = QueuePermissions.objects.filter(group__in=groups, group_write=True, queue__queue_type=TicketQueue.CASE_TASK_QUEUE).first()
        if qperm:
            return qperm.queue
    return TicketQueue.objects.get(slug='case')

def get_user_case_queue(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    perms = QueuePermissions.objects.filter(group__in=user_groups, group_read=True, group_write=True, queue__queue_type=TicketQueue.CASE_TASK_QUEUE).first()
    if perms:
        return perms.queue
    return TicketQueue.objects.get(slug='case')

def get_user_gen_queue(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    perms = QueuePermissions.objects.filter(group__in=user_groups, group_read=True, group_write=True, queue__queue_type=TicketQueue.GENERAL_TICKET_QUEUE).first()
    if perms:
        return perms.queue
    return TicketQueue.objects.get(slug='gen')


def get_vendor_queue(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    #does this user have access to the Vendor queue?
    perms = QueuePermissions.objects.filter(group__in=user_groups, group_read=True, group_write=True, queue__title="Vendor").first()
    if perms:
        return perms.queue
    return get_user_gen_queue(user)
    

def get_user_cr_queue(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    perms = QueuePermissions.objects.filter(group__in=user_groups, group_read=True, group_write=True, queue__queue_type=TicketQueue.CASE_REQUEST_QUEUE).first()
    if perms:
        return perms.queue
    return TicketQueue.objects.get(slug='cr')

def get_all_cr_queue(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    perms = QueuePermissions.objects.filter(group__in=user_groups, group_read=True, group_write=True, queue__queue_type=TicketQueue.CASE_REQUEST_QUEUE).values_list('queue', flat=True)
    if perms:
        return TicketQueue.objects.filter(id__in=perms)
    return None
    

def get_contact_read_perms(user):
    user_groups = user.groups.filter(groupsettings__contacts_read=True).exclude(groupsettings__contact__isnull=True)
    if user_groups:
        return True
    if user.usersettings.contacts_read:
        # if this user has special permissions (outside the normal group perms), this will be set to True
        return True
    return False

def get_contact_write_perms(user):
    user_groups = user.groups.filter(groupsettings__contacts_write=True).exclude(groupsettings__contact__isnull=True)
    if user_groups:
        return True
    if user.usersettings.contacts_write:
        # if this user has special permissions (outside the normal group perms), this will be set to True
        return True
    return False
    
def get_team_queues(team):
    #team == group
    return TicketQueue.objects.filter(team=team)

def is_my_team(user, team):
    #team == group
    if user.is_superuser:
        return True
    return user.groups.filter(id=team).exists()

def get_my_team(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    if user_groups:
        return user_groups[0]
    else:
        return None

def get_team_sig(user):
    my_team = get_my_team(user)
    if my_team:
        try:
            if my_team.groupsettings.team_signature:
                return my_team.groupsettings.team_signature
            return settings.DEFAULT_EMAIL_SIGNATURE
        except:
            return settings.DEFAULT_EMAIL_SIGNATURE
    return settings.DEFAULT_EMAIL_SIGNATURE
