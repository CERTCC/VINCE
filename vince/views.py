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
import difflib
import json
import markdown
import random
import re
import requests
from django.urls import resolve
from django.db.models import CharField
from django.db.models.functions import TruncMonth, TruncDay
from datetime import datetime, timedelta
from random import randint
from django.core.management import call_command
from django.contrib import messages
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.core.files.base import ContentFile
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.urls import reverse, reverse_lazy
from cvelib import cve_api as cvelib
import pytz
import email
from django.template.loader import get_template
from vince.lib import process_attachments, push_s3_data, update_vinny_post, download_vrf, send_error_sns, publish_vul_note, update_srmail_file, update_vinny_case, get_triage_users, add_coordinator_case
from vince.lib import add_vendor_vinny_case, remove_vendor_vinny_case, remove_participant_vinny_case, get_casemember_from_vc, get_bounce_stats
from vince.mailer import safe_template_context, send_email_notification, send_updatecase_mail, send_participant_email_notification, send_user_approve_notification, send_submitter_email_notification, send_encrypted_mail, send_approval_email, send_vendor_approval_emails, send_regular_email_notification, send_smime_encrypted_mail, send_reset_mfa_email, get_public_phone, get_public_email, get_mail_content
from itertools import chain
from django.db.models import *
from django.db.models import Case as DBCase
from django.forms.models import model_to_dict
from django.forms.fields import DateField, DateTimeField
from django.forms.formsets import formset_factory
from django.forms.models import inlineformset_factory
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseServerError, Http404
from django.http.response import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.defaulttags import register
from django.urls import reverse
from django.forms.utils import ErrorList
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _
from django.views import generic
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.generic.edit import FormView, FormMixin
from vince.forms import *
from vince.ticket_update import update_ticket, auto_assignment
from vinny.models import VinceCommContact, VinceCommPostal, VinceCommPhone, VinceCommEmail, VinceCommWebsite, VinceCommPgP, Message, Thread, GroupContact, ContactInfoChange, VinceCommGroupAdmin, Case, VinceCommCaseAttachment, CaseMember, CaseVulnerability, CaseMemberStatus, VendorAction, Post, VCVUReport, VCVendor, VCNoteVulnerability, VCVulnerabilityNote, VCVendorVulStatus, VTCaseRequest, VinceProfile, CaseStatement, VinceAttachment, VendorStatusChange, CaseViewed, CaseVulExploit
from vinny.contact_update import extract_pgp_info
from vincepub.models import VulnerabilityNote, NoteVulnerability, Vendor, VendorVulStatus, VUReport, VendorRecord
from django.contrib.sessions.models import Session
from django.contrib.sessions.backends.db import SessionStore
from cogauth.views import GetUserMixin, TokenMixin
from django.contrib.auth import authenticate, logout, login as auth_login
from django.contrib.auth.decorators import login_required, user_passes_test
from cogauth.utils import token_verify, cognito_verify_email, cognito_check_track_permissions, disable_totp_mfa, disable_sms_mfa, get_user_details, send_courtesy_email, create_new_user, admin_change_user_details
from .permissions import *
from django.db.models import Q
from django.core import serializers
import shlex
from dictdiffer import diff
import traceback
import boto3
from botocore.exceptions import ClientError
from boto3.exceptions import Boto3Error
from bigvince.storage_backends import PrivateMediaStorage
from vince.settings import VULNOTE_TEMPLATE
from collections import OrderedDict
from django.utils.http import is_safe_url

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def object_to_json_response(obj, status=200):
    """
    Given an object, returns an HttpResponse object with a JSON serialized
    version of that object
    """
    return JsonResponse(
        data=obj, status=status, safe=False, json_dumps_params={'ensure_ascii': False},
    )

@register.filter(name='leading_zeros')
def leading_zeros(value, desired_digits):
    return str(value).zfill(desired_digits)

#@register.filter(name="get_affected")
#def get_affected(var, obj):
#    if var == "Affected" or var == "Vulnerable":
#        return "<i class=\"fas fa-exclamation-triangle\" aria-hidden=\"true\" style=\"color:red;\"></i>&nbsp; Affected"
#    elif var == "Unknown":
#        return "<i class=\"fas fa-question-circle\" aria-hidden=\"true\"></i>&nbsp;Unknown "
#    else:
#        return "<i class=\"fas fa-check-circle\" aria-hidden=\"true\" style=\"color:green;\"></i>&nbsp;Not Affected"
#
@register.filter(name='get_activity_icon')
def get_activity_icon(var, obj):
    if var in ['Ticket Opened', 'Added Vulnerability', 'Created vul note', 'New Status']:
        return "<i class=\"fas fa-plus-square\"></i>"
    elif var in ['Comment']:
        return "<i class=\"fas fa-comment\"></i>"
    elif var in ['Edited Case Details', 'Edited Vul Note', 'Edited artifact', 'Edited Vulnerability', 'Status Change']:
        return "<i class=\"fas fa-edit\"></i>"
    elif var in ['Added Vendor to Case', 'Added Participant to Case']:
        return "<i class=\"fas fa-plus\"></i>"
    elif var in ['Notified vendors']:
        return "<i class=\"fas fa-bell\"></i>"
    elif var in ['Vendor Statement', 'Created Notification Post']:
        return "<i class=\"fas fa-pen-square\"></i>"
    elif var in ['Published Post']:
        return "<i class=\"fas fa-paper-plane\"></i>"
    elif "viewed" in var:
        return "<i class=\"fas fa-eye\"></i>"
    else:
        return "<i class=\"fas fa-reply\"></i>"

@register.filter(name='vendorstatus')
def vendorstatus(qs, vul):
    status = qs.filter(vul=vul)
    if status:
        return status[0]
    else:
        return None

@register.filter(name='contact_to_name')
def contact_to_name(id, x):
    if id:
        return Contact.objects.get(id=id).vendor_name
    return ""

@register.filter(name='gettags')
def gettags(tags, x):
    rs = ''
    for tag in tags:
        rs = rs + "<span class=\"tag\">" + tag + "</span> "
    return rs

@register.filter(name='vendor_statement')
def vendor_statement(qs, vul):
    statement = qs.filter(vul=vul)
    if statement:
        if statement[0].statement or statement[0].references:
            return True
        else:
            return False
    return False

@register.filter(name="in_role")
def in_role(qs, role):
    return qs.filter(role=role)


@register.filter(name='notifystatus')
def notifystatus(case, x):
    #is post published
    posts = VendorNotificationContent.objects.filter(case=case).exclude(published_date__isnull=True)
    if not posts:
        return False

    # check for vuls
    vuls = Vulnerability.casevuls(case)
    if not vuls:
        return False

    return True

@register.filter(name='percentcalc')
def percentcalc(value, total):
    return int((value/total) * 100)

@register.simple_tag()
def vcuser(email):
    user = User.objects.using('vincecomm').filter(username=email).first()
    if user:
        return user.vinceprofile.vince_username
    else:
        return email

@register.filter(name='contact_access')
def contact_access(user):
    return get_contact_read_perms(user)

@register.simple_tag()
def vcid(email):
    user = User.objects.using('vincecomm').filter(username=email).first()
    if user:
        return user.id
    else:
        return None

@register.simple_tag()
def contactid(name):
    contact = Contact.objects.filter(vendor_name=name).first()
    if contact:
        return contact.id
    else:
        return None

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_team_cases(request, pk):
    #make sure this user is part of this team
    if not(request.user.groups.filter(id=pk).exists()):
        raise Http404
    # get all users in my group
    team = User.objects.filter(groups__id=pk)
    #assigned = CaseAssignment.objects.filter(assigned__in=team, case__status=1).values_list('case__id', flat=True)
    cases = VulnerabilityCase.objects.filter(owner__in=team, status=1)
    page = request.GET.get('page', 1)

    for key in request.GET:
        if 'field' in key:
            field = request.GET[key]
        elif 'value' in key:
            value = request.GET[key]
            # do query
            if field == 'vu':
                cases = cases.filter(vuid__icontains=value)
            elif field == 'title':
                cases = cases.filter(title__icontains=value)
            elif field == 'assigned_to':
                if (value in ["Unassigned", "unassigned"]):
                    #all assigne cases
                    assigned = CaseAssignment.objects.filter(case__in=cases).distinct().values_list('case__id', flat=True)
                    cases = cases.exclude(id__in=assigned)
                else:
                    assigned = CaseAssignment.objects.filter(assigned__in=team, case__status=1, assigned__usersettings__preferred_username__icontains=value).values_list('case__id', flat=True)
                    cases = cases.filter(id__in=assigned)
    
    tickets = cases.order_by('-modified')
    paginator = Paginator(tickets, 25)
    ticketsjs = [obj.as_dict() for obj in paginator.page(page)]
    data = json.dumps({'data':ticketsjs, 'last_page':paginator.num_pages})
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)


@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_team_tickets(request, pk):
    #make sure this user is part of this team
    if not(request.user.groups.filter(id=pk).exists()):
        raise Http404
    queues = TicketQueue.objects.filter(team=pk)
    tickets = Ticket.objects.filter(queue__in=queues)
    page = request.GET.get('page', 1)
    size = request.GET.get('size', 20)
    queue = request.GET.get('queue', None)
    query=False
    if queue:
        tickets = tickets.filter(status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS])
        threads = TicketThread.objects.filter(ticket__in=tickets).values_list('ticket', flat=True)
        tickets = tickets.filter(id__in=threads)
    for key in request.GET:
        if 'field' in key:
            field = request.GET[key]
        elif 'value' in key:
            value = request.GET[key]
            # do query
            if field == 'status':
                query=True
                if value in ['Open', 'open', 'Reopened', 'reopened']:
                    tickets = tickets.filter(status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS])
                elif value in ["Closed", 'closed', 'Resolved', 'resolved']:
                    tickets = tickets.filter(status__in=[Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS])
                else:
                    tickets = tickets.filter(status__in=[Ticket.IN_PROGRESS_STATUS])
            elif field == 'title':
                query=True
                tickets = tickets.filter(title__icontains=value)
            elif field == 'ticket':
                query=True
                tickets = tickets.filter(Q(queue__title__icontains=value)|Q(queue__slug__icontains=value))
            elif field == "assigned_to":
                query=True
                tickets = tickets.filter(assigned_to__usersettings__preferred_username__icontains=value)


    if query==False and queue == None:
        tickets = tickets.filter(status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS])
    
    tickets = tickets.order_by('-modified')
    paginator = Paginator(tickets, size)
    ticketsjs = [obj.as_dict() for obj in paginator.page(page)]
    data = json.dumps({'data':ticketsjs, 'last_page':paginator.num_pages})
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)


@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_casevuls(request, pk):
    case = get_object_or_404(VulnerabilityCase, id=pk)
    vuls = Vulnerability.casevuls(case)
    vulsjs = [obj.as_dict() for obj in vuls]
    mimetype = 'application/json'
    data = json.dumps(vulsjs)
    return HttpResponse(data, mimetype)


@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_pgp(request, key_id):
    pgp = ContactPgP.objects.filter(pgp_key_id=key_id).first()
    data = pgp.pgp_key_data
    data = json.dumps(data)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)


@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_contact(request, name):
    data = {"emails":[], "pgp":[], "pgp_key_data":"", "pgp_key_info":[]}
    contact = Contact.objects.filter(vendor_name__iexact=name).first()
    if contact:
        emails = contact.get_official_emails()
        emails = ",".join(emails)
        pgp_keys = list(ContactPgP.objects.filter(contact=contact, revoked=False).exclude(pgp_key_data__isnull=True).exclude(pgp_key_data__exact='').values_list('pgp_key_id', flat=True))
        pgp_key_info = list(ContactPgP.objects.filter(contact=contact, revoked=False).values_list('pgp_key_id', 'pgp_email', 'pgp_key_data','startdate', 'enddate'))
        logger.debug(pgp_key_info)
        pgp_key_data = ""
        if len(pgp_keys) == 1:
            pgp_key_data = ContactPgP.objects.filter(contact=contact, revoked=False).exclude(pgp_key_data__isnull=True).exclude(pgp_key_data__exact='').first()
            pgp_key_data = pgp_key_data.pgp_key_data
        data = {'emails': emails, 'pgp': pgp_keys, 'pgp_key_data': pgp_key_data, "pgp_key_info":pgp_key_info}
    data = json.dumps(data)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_cwe(request):
    if request.GET.get('term'):
        cwe = list(CWEDescriptions.objects.filter(cwe__icontains=request.GET.get('term')).values_list('cwe', flat=True))
    else:
        cwe = list(CWEDescriptions.objects.all().values_list('cwe', flat=True))
    data = json.dumps(cwe)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_vendor(request, groups=False):
    vendorlist = list(Contact.objects.filter(active=True).values_list('vendor_name', flat=True).distinct())
    if not(groups):
        grouplist = list(ContactGroup.objects.filter(status="Active").values_list('name', flat=True).distinct())
        grouplist = [ "Group: " +  x for x in grouplist ]
        velist = vendorlist.extend(grouplist)
    data = json.dumps(vendorlist)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def calendar_events(request):
    start = request.GET.get('start', None)
    end = request.GET.get('end', None)
    groups = request.user.groups.exclude(groupsettings__contact__isnull=True)
    users = User.objects.filter(groups__in=groups)
    events = CalendarEvent.objects.filter(Q(date__range=(start,end))|Q(end_date__range=(start,end))).filter(user__in=users)
    data= [obj.as_dict() for obj in events]

    data = json.dumps(data)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_casevendors(request, pk):
    case = get_object_or_404(VulnerabilityCase, id=pk)
    page = request.GET.get('page', 1)
    size = request.GET.get('size', 20)
    vendors = VulnerableVendor.casevendors(case).order_by('vendor')
    user_filter = False
    for key in request.GET:
        if 'field' in key:
            field = request.GET[key]
            continue
        elif 'value' in key:
            value = request.GET[key]
            # do query
        else:
            continue

        if field == "vendor":
            vendors = vendors.filter(contact__vendor_name__istartswith=value)
        elif field == "status":
            if value.startswith("A"):
                stat = 1
            elif value.startswith("Una"):
                stat = 2
            else:
                stat = 3
            status = VendorStatus.objects.filter(vendor__in=vendors, status=stat).values_list('vendor__id', flat=True)
            vendors = vendors.filter(id__in=status)
        elif field == "approved":
            vendors = vendors.filter(approved=True)
        elif field == "seen":
            vendors = vendors.filter(seen=True)
        elif field == "reqapproval":
            vendors = vendors.filter(approved=False, statement_date__isnull=False)
        elif field == "statement_date":
            vendors = vendors.filter(statement_date__isnull=False)
        elif field == "contact_date":
            vendors = vendors.filter(contact_date__isnull=True)
        elif field == "users":
            user_filter = True
        
    paginator = Paginator(vendors, size)

    vendorsjs = [obj.as_dict() for obj in paginator.page(page)]
    #vendorsjs = [obj.as_dict() for obj in vendors]

    alert_tags = list(TagManager.objects.filter(tag_type=2, alert_on_add=True).values_list('tag', flat=True))
    logger.debug(f"ALERT TAGS: {alert_tags}")
    for vjs in vendorsjs:
        cid = vjs['contact_id']
        vc_contact = VinceCommContact.objects.using('vincecomm').filter(vendor_id=cid).first()
        if vc_contact:
            groupcontact = GroupContact.objects.using('vincecomm').filter(contact=vc_contact).first()
            if groupcontact:
                count = User.objects.using('vincecomm').filter(groups=groupcontact.group).count()
                vjs.update({'users':count})
                #check alert tags
                if vjs['alert_tags'] and alert_tags:
                    vjs['alert_tags'] = list(set(vjs['alert_tags']) & set(alert_tags))
                continue
        vjs.update({'users': 0})
        #check alert tags
        if vjs['alert_tags'] and alert_tags:
            vjs['alert_tags'] = list(set(vjs['alert_tags']) & set(alert_tags))

    data = json.dumps({'data':vendorsjs, 'last_page': paginator.num_pages})
    #data = json.dumps(vendorsjs)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_caseparticipants(request, pk):
    case = get_object_or_404(VulnerabilityCase, id=pk)
    vendors = CaseParticipant.objects.filter(case=case).order_by('user_name')
    vendorsjs = [obj.as_dict() for obj in vendors]
    data = json.dumps(vendorsjs)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_casetasks(request, pk):
    case = get_object_or_404(VulnerabilityCase, id=pk)
    page = request.GET.get('page', 1)
    tickets = Ticket.objects.filter(case=case).annotate(custom_order=DBCase(When(status = Ticket.OPEN_STATUS, then=Value(1)),
                               When(status = Ticket.IN_PROGRESS_STATUS, then=Value(2)),
                               When(status = Ticket.REOPENED_STATUS, then=Value(3)),
                               When(status = Ticket.RESOLVED_STATUS, then=Value(4)),
                               When(status = Ticket.CLOSED_STATUS, then=Value(5)),
                               When(status = Ticket.DUPLICATE_STATUS, then=Value(6)),
                               output_field=IntegerField(),)).order_by('custom_order', '-created')
    paginator = Paginator(tickets, 25)
    ticketsjs = [obj.as_dict() for obj in paginator.page(page)]
    data = json.dumps({'data':ticketsjs, 'last_page':paginator.num_pages})
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_case_references(request, pk):
    case = get_object_or_404(VulnerabilityCase, id=pk)
    if has_case_read_access(request.user, case):
        references = []
        refs = CVEAllocation.objects.filter(vul__case__id=pk).values_list('references', flat=True)
        for vul in refs:
            if vul:
                temp = json.loads(vul)
                for r in temp:
                    if r["url"] not in references:
                        references.append(r["url"])
        data = json.dumps(references)
        logger.debug(data)
        return HttpResponse(data, 'application/json')
    else:
        raise PermissionDenied()

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_users(request):
    userlist = list(User.objects.using('vincecomm').all().order_by('username').values_list('username', flat=True).distinct())
    data = json.dumps(userlist)
    mimetype='application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_contacts(request):
    contactlist = list(Contact.objects.values_list('vendor_name', flat=True).distinct())
    grouplist = list(ContactGroup.objects.values_list('name', flat=True).distinct())
    grouplist = [ "Group: " +  x for x in grouplist ]
    velist = contactlist.extend(grouplist)
    data = json.dumps(contactlist)
    mimetype='application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_assignable_users(request):
    assignable_users = list(User.objects.filter(is_active=True, groups__name='vince').order_by('usersettings__preferred_username').values_list('usersettings__preferred_username', flat=True).exclude(usersettings__preferred_username__isnull=True).distinct())
    data = json.dumps(assignable_users)
    mimetype='application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_template(request, pk):
    template = EmailTemplate.objects.get(id=pk)
    data = json.dumps({'body': template.plain_text, 'subject': template.subject})
    mimetype='application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_cases(request):
    caselist = list(VulnerabilityCase.objects.order_by('vuid').values_list('vuid', flat=True).distinct())
    data = json.dumps(caselist)
    mimetype='application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def autocomplete_tags(request):
    if request.GET.get('term'):
        caselist = list(ArtifactTag.objects.filter(tag__icontains=request.GET.get('term')).order_by('tag').values_list('tag', flat=True).distinct())
    else:
        caselist = list(ArtifactTag.objects.order_by('tag').values_list('tag', flat=True).distinct())
    data = json.dumps(caselist)
    mimetype='application/json'
    return HttpResponse(data, mimetype)

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url="vince:login")
def vince_user_lookup(request):
    if request.POST.get('email'):
        user = User.objects.using('vincecomm').filter(email__iexact=request.POST.get('email')).first()
        if user:
            data = json.dumps({'user': user.email, 'first': user.first_name, 'last': user.last_name})
        else:
            data = json.dumps({'message':'no user'})
        mimetype = 'application/json'
        return HttpResponse(data, mimetype)

def group_name_exists(name):
    groups = ContactGroup.objects.filter(name=name).first()
    if groups:
        return True
    else:
        return False

def srmail_name_exists(name):
    groups = ContactGroup.objects.filter(srmail_peer_name=name).first()
    if groups:
        return True
    contacts = Contact.objects.filter(srmail_peer=name).first()
    if contacts:
        return True

    return False

def _is_my_ticket(user, ticket):
    """Check to see if the user has permission to access
    a ticket. If not then deny access."""
    if user.is_staff or user.id == ticket.assigned_to.id:
        return True
    else:
        return False

def _remove_groupadmin_perms(emailcontact):
    # is this user groupadmin?
    ga = VinceCommGroupAdmin.objects.filter(email__email=emailcontact.email)
    # we already removed groupadmin in prev call to _remove_groupadmin.
    # only remove the group permission if this user isn't a groupadmin of some other vendor
    if not(ga):
        groupadmin = Group.objects.using('vincecomm').filter(name='vince_group_admin').first()
        # look up user by email
        user = User.objects.using('vincecomm').filter(username = emailcontact.email).first()
        if user:
            groupadmin.user_set.remove(user)


def _add_groupadmin_perms(emailcontact):
    groupadmin = Group.objects.using('vincecomm').filter(name='vince_group_admin').first()
    if groupadmin == None:
        # add groupadmin group
        groupadmin = Group(name='vince_group_admin')
        groupadmin.save(using='vincecomm')
    # look up user by email
    user = User.objects.using('vincecomm').filter(username = emailcontact.email).first()
    if user:
        groupadmin.user_set.add(user)

def _add_groupadmin(emailcontact, contact):
    vinny_contact = VinceCommContact.objects.filter(vendor_id=contact.id).first()
    vinny_email_contact = VinceCommEmail.objects.filter(email = emailcontact.email, contact=vinny_contact).first()
    # check for other groupadmins:
    current = VinceCommGroupAdmin.objects.update_or_create(contact=vinny_contact, email=vinny_email_contact)

def _remove_groupadmin(emailcontact, contact):
    vinny_contact = VinceCommContact.objects.filter(vendor_id=contact.id).first()
    vinny_email_contact = VinceCommEmail.objects.filter(email = emailcontact.email, contact=vinny_contact).first()
    # check for other groupadmins:
    current = VinceCommGroupAdmin.objects.filter(contact=vinny_contact, email=vinny_email_contact)
    for x in current:
        x.delete()

def _remove_groupadmin_vc(email, contact):
    vtcontact = Contact.objects.filter(id=contact.vendor_id).first()
    if not(vtcontact):
        return
    ga = GroupAdmin.objects.filter(contact=vtcontact, email__email=email).first()
    if ga:
        _remove_groupadmin(ga.email, vtcontact)
        _remove_groupadmin_perms(ga.email)
        ga.delete()

def _add_group_permissions(email, vince_user):
    email_contact = VinceCommEmail.objects.using('vincecomm').filter(email__iexact=email).exclude(Q(email_list=True)|Q(status=False))
    logger.debug(f"Checking permissions for email address {email}")
    for contact in email_contact:
        logger.debug(f"{contact.email}, {contact.status}, {contact.contact.vendor_name}: {contact.contact.active}")
        if not(contact.contact.active):
            #if this email is inactive, remove group permissions
            logger.debug(f"Contact is inactive, remove permissions {contact.contact.vendor_id}")
            _remove_group_permissions(email, contact.contact, vince_user)
            _remove_groupadmin_vc(email, contact.contact)
            continue

        # now do we have a current VINCE user with this email?
        user = User.objects.using('vincecomm').filter(email__iexact=contact.email).first()
        if user:
            # now do we have a Group for this contact?
            group = Group.objects.using('vincecomm').filter(name=contact.contact.uuid).first()
            if group:
                if user.groups.filter(name=group.name).exists():
                    # user already in group
                    continue
                group.user_set.add(user)
                logger.info(f"Adding user { user.username } to group { group.name }: {contact.contact.vendor_name}")
                vtcontact = Contact.objects.get(id=contact.contact.vendor_id)
                _add_activity(vince_user, 4, vtcontact, f"adding VINCE user {email} to group")
                user.vinceprofile.pending = False
                user.vinceprofile.save()
            else:
                logger.info(f"Creating group { contact.contact.uuid } for { contact.contact.vendor_name }")
                group = Group(name=contact.contact.uuid)
                group.save(using='vincecomm')
                logger.info(f"Adding user { user.username } to group { group.name }: {contact.contact.vendor_name}")
                vtcontact = Contact.objects.get(id=contact.contact.vendor_id)
                _add_activity(vince_user, 4, vtcontact, f"adding VINCE user {email} to group")
                group.user_set.add(user)
                #Connecting Group to Contact
                gc = GroupContact(group=group,
                                  contact=contact.contact)
                gc.save(using='vincecomm')
                user.vinceprofile.pending = False
                user.vinceprofile.save()
        else:
            logger.debug("No VINCE user with this email address")

def _remove_group_permissions(email, vinny_contact, vince_user):
    # now do we have a current VINCE user with this email?
    user = User.objects.using('vincecomm').filter(username__iexact=email).first()
    if user:
        # now do we have a Group for this contact?
        group = Group.objects.using('vincecomm').filter(name=vinny_contact.uuid).first()
        if group:
            if user.groups.filter(name=group.name).exists():
                #remove user from group
                group.user_set.remove(user)
                logger.info(f"Removing user {user.username} from group: {vinny_contact.vendor_name}")
                vtcontact = Contact.objects.get(id=vinny_contact.vendor_id)
                _add_activity(vince_user, 5, vtcontact, f"removing VINCE user {email} from group {vtcontact.vendor_name}")


def check_misconfiguration(user):
    user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
    if len(user_groups) == 0:
        return True
    return False

def date_rel_to_today(today, offset):
    return today - timedelta(days=offset)


def sort_string(begin, end):
    return 'date_from=%s&date_to=%s&status=%s&status=%s&status=%s&status=%s' % (
        begin, end, Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.RESOLVED_STATUS, Ticket.IN_PROGRESS_STATUS)

def generate_vend_id(request):
    allvends = Contact.objects.all().values_list('lotus_id', flat=True)
    newvend = random.randrange(100000, 999999)
    while (newvend in allvends):
        newvend = random.randrange(100000, 999999)
    return JsonResponse({'id':newvend})


def lotus_contact_new(lotus_id, srmail, vendor, email):
    return None

def lotus_contact_update(lotus_id, srmail, vendor, email):
    return None


def get_cve_assigner(user, case):
    email = None
    
    if case:
        try:
            email = case.team_owner.groupsettings.cna_email
            if email:
                return email
            else:
                #get team email (public email address)
                email = get_public_email(case.team_owner.groupsettings.contact)
        except:
            pass

    if email:
        return email
    return settings.DEFAULT_REPLY_EMAIL

def get_all_artifacts(case):
    ticket_list = Ticket.objects.filter(case=case)
    tartifacts = Artifact.objects.select_related('ticketartifact').filter(ticketartifact__ticket__in=ticket_list)
    cartifacts = Artifact.objects.select_related('caseartifact').filter(caseartifact__case=case)
    artifacts = tartifacts|cartifacts
    artifacts = artifacts.order_by('-date_added')
    return artifacts


def calc_average_nbr_days_until_ticket_resolved(Tickets):
    nbr_closed_tickets = len(Tickets)
    days_per_ticket = 0
    days_each_ticket = list()

    for ticket in Tickets:
        time_ticket_open = ticket.modified - ticket.created
        days_this_ticket = time_ticket_open.days
        days_per_ticket += days_this_ticket
        days_each_ticket.append(days_this_ticket)

    if nbr_closed_tickets > 0:
        mean_per_ticket = days_per_ticket / nbr_closed_tickets
    else:
        mean_per_ticket = 0

    return mean_per_ticket

def calc_basic_ticket_stats(Tickets):
    # all not closed tickets (open, reopened, resolved,) - independent of user
    all_open_tickets = Tickets.exclude(status=Ticket.CLOSED_STATUS)
    today = datetime.today()

    date_7 = date_rel_to_today(today, 7)
    date_14 = date_rel_to_today(today, 14)
    date_7_str = date_7.strftime('%Y-%m-%d')
    date_14_str = date_14.strftime('%Y-%m-%d')

    # > 0 & <= 7
    ota_le_7 = all_open_tickets.filter(created__gte=date_7_str)
    N_ota_le_7 = len(ota_le_7)
    # >= 7 & <= 14
    ota_le_14_ge_7 = all_open_tickets.filter(created__gte=date_14_str, created__lte=date_7_str)
    N_ota_le_14_ge_7 = len(ota_le_14_ge_7)

    # >= 14
    ota_ge_14 = all_open_tickets.filter(created__lte=date_14_str)
    N_ota_ge_14 = len(ota_ge_14)

    # (O)pen (T)icket (S)tats
    ots = list()
    # label, number entries, color, sort_string
    ots.append(['Tickets < 7 days', N_ota_le_7, 'good',
                sort_string(date_7_str, ''), ])
    ots.append(['Tickets 7 - 14 days', N_ota_le_14_ge_7,
                'good' if N_ota_le_14_ge_7 == 0 else 'warn',
                sort_string(date_14_str, date_7_str), ])
    ots.append(['Tickets > 14 days', N_ota_ge_14,
                'good' if N_ota_ge_14 == 0 else 'bad',
                sort_string('', date_14_str), ])
    # all closed tickets - independent of user.
    all_closed_tickets = Tickets.filter(status=Ticket.CLOSED_STATUS)
    average_nbr_days_until_ticket_closed = \
        calc_average_nbr_days_until_ticket_resolved(all_closed_tickets)
    # all closed tickets that were opened in the last 14 days.
    all_closed_last_14_days = all_closed_tickets.filter(created__gte=date_14_str)
    average_nbr_days_until_ticket_closed_last_14_days = \
        calc_average_nbr_days_until_ticket_resolved(all_closed_last_14_days)

    # put together basic stats
    basic_ticket_stats = {
        'average_nbr_days_until_ticket_closed': average_nbr_days_until_ticket_closed,
        'average_nbr_days_until_ticket_closed_last_14_days':
            average_nbr_days_until_ticket_closed_last_14_days,
        'open_ticket_stats': ots,
    }

    return basic_ticket_stats



def is_query_ticket_id(s):
    if s.isnumeric():
        return True, None, int(s)
    queues = list(TicketQueue.objects.all().values_list('slug', flat=True))
    queues.append("General")
    rq= '|'.join(queues)
    rq = "(?i)(" + rq + ")-(\d+)"
    m = re.search(rq, s)
    if m:
        return True, m.group(1), m.group(2)
    else:
        return False, None, None


def process_query_for_tags(s):
    t = s.lower()
    ret = t.split()
    ret.append(s)
    return ret

def process_query(s, live=True):
    query = re.sub(r'[!\'()|&<>]', ' ', s).strip()
    # get rid of empty quotes
    query = re.sub(r'""', '', s)
    if query == '"':
        return None
    if query.startswith(settings.CASE_IDENTIFIER):
        query = query[len(settings.CASE_IDENTIFIER):]

    if query:
        #sub spaces between quotations with <->
        #if re.search(r'\"', query) and not re.search(r'\".*\"', query):
        try:
            query = '&'.join(shlex.split(query))
        except ValueError:
            query = query + '"'
            query = re.sub(r'\s+', '&', query)
        query = re.sub(r'\s+', '<->', query)
        # Support prefix search on the last word. A tsquery of 'toda:*' will
        # match against any words that start with 'toda', which is good for
        # search-as-you-type.
        if query.endswith("<->"):
            query = query[:-3]
    if query and live:
        query += ':*'

    return query

# Create your views here.
class RemindersView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/reminders.html'
    login_url="vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RemindersView, self).get_context_data(**kwargs)
        context['reminderpage'] = 1
        context['my_reminders'] = VinceReminder.objects.filter(user=self.request.user).order_by('alert_date')
        context['other_reminders'] = VinceReminder.objects.filter(created_by=self.request.user).exclude(user=self.request.user).order_by('alert_date')
        return context

class RemoveReminderView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/reminders.html'
    login_url="vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        reminder = get_object_or_404(VinceReminder, id=self.request.POST.get('id'))
        if self.request.POST.get('later'):
            reminder.alert_date = timezone.now() + timedelta(days=1)
            reminder.save()
        elif self.request.POST.get('delete'):
            reminder.delete()
        else:
            if reminder.frequency:
                reminder.alert_date = reminder.alert_date + timedelta(days=reminder.frequency)
            else:
                reminder.delete()

        return JsonResponse({'status':'success'}, status=200)



class ErrorView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/misconfigured.html'
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)
    
class NewReminderView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    template_name = 'vince/new_reminder.html'
    login_url="vince:login"
    form_class=ReminderForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(NewReminderView, self).get_context_data(**kwargs)
        context['reminderpage'] = 1

        assignable_users = User.objects.filter(is_active=True, groups__name='vince').exclude(id=self.request.user.id).order_by(User.USERNAME_FIELD)
        initial = {}
        if self.request.GET.get('case'):
            initial['case'] = self.request.GET.get('case')

        form = ReminderForm(initial=initial)

        form.fields['user'].choices = [(self.request.user.id, 'Myself')] + [(u.id, u.get_full_name()) for u in assignable_users]
        context['form'] = form
        return context

    def form_invalid(self, form):
        return JsonResponse({'errors':form.errors}, status=401)

    def post(self, request, *args, **kwargs):
        logger.debug(f"NewReminder Post: {self.request.POST}")
        form = ReminderForm(request.POST)
        assignable_users = User.objects.filter(is_active=True, groups__name='vince').exclude(id=self.request.user.id).order_by(User.USERNAME_FIELD)
        form.fields['user'].choices = [(self.request.user.id, 'Myself')] + [(u.id, u.get_full_name()) for u in assignable_users]

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):

        reminder = form.save()
        reminder.created_by = self.request.user
        reminder.save()
        return redirect("vince:reminders")


class PreferenceView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    template_name='vince/preferences.html'
    login_url="vince:login"
    form_class=PreferencesForm
    success_url="/vince/preferences"

    def test_func(self):
        if cognito_check_track_permissions(self.request):
            return is_in_group_vincetrack(self.request.user)
        return False

    def get_initial(self):
        queues = TicketQueue.objects.filter(queuepermissions__group__in=self.request.user.groups.all(), queuepermissions__group_read=True).order_by('slug').distinct()
        s = self.request.user.usersettings
        initial = s.settings

        if self.request.user.usersettings.case_template:
            initial['case_template'] = self.request.user.usersettings.case_template.id
        initial['templates'] =  [('', '--------')] + [(q.id, q.title) for q in CaseTemplate.objects.all()]
        return initial


    def get_context_data(self, **kwargs):
        context = super(PreferenceView, self).get_context_data(**kwargs)
        context['queues'] = TicketQueue.objects.filter(queuepermissions__group__in=self.request.user.groups.all(), queuepermissions__group_read=True).order_by('slug').distinct()
        return context

    def post(self, request, *args, **kwargs):
        form = PreferencesForm(request.POST)
        form.fields['case_template'].choices = [('', '--------')] + [
            (q.id, q.title) for q in CaseTemplate.objects.all()]
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        logger.debug(self.request.POST)
        newtickets = self.request.POST.getlist('new_tickets[]')
        newtix = []
        uptix = []
        for q in newtickets:
            queue = TicketQueue.objects.get(id=int(q))
            newtix.append(int(q))
            if queue.new_ticket_cc:
                if self.request.user.username not in queue.new_ticket_cc:
                    queue.new_ticket_cc = queue.new_ticket_cc + ", " + self.request.user.username
                    queue.save()
            else:
                queue.new_ticket_cc = self.request.user.username
                queue.save()

        oqueues = TicketQueue.objects.all().exclude(id__in=newtix)
        for q in oqueues:
            if not(q.new_ticket_cc):
                continue
            ntc = q.new_ticket_cc.split(', ')
            if self.request.user.username in ntc:
                ntc.remove(self.request.user.username)
                q.new_ticket_cc = ", ".join(ntc)
                q.save()


        s = self.request.user.usersettings
        settings = s.settings
        for k,v in form.cleaned_data.items():
            settings[k] = v
        if form.cleaned_data['case_template']:
            s.case_template = CaseTemplate.objects.get(id=form.cleaned_data['case_template'])
        else:
            s.case_template = None
        s.settings = settings
        s.save()
        messages.success(
            self.request,
            "Got it! Your preferences have been saved"
            )
        return super().form_valid(form)

class IndexView(generic.TemplateView):
    template_name = 'vince/index.html'

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context['vincepage'] = 1
        return context


class TeamDashView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/teamdash.html'
    login_url="vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        if check_misconfiguration(self.request.user):
            return redirect("vince:misconfigured")
        return super().get(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super(TeamDashView, self).get_context_data(**kwargs)

        #open & reopened tickets
        #my primary team
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if len(user_groups) > 1:
            if self.kwargs.get('pk'):
                context['team'] = self.request.user.groups.get(id=self.kwargs.get('pk'))
                context['other_teams'] = user_groups.exclude(id=self.kwargs.get('pk'))
                user_groups = self.request.user.groups.filter(id=self.kwargs.get('pk'))
            else:
                context['team'] = user_groups[0]
                context['other_teams'] = user_groups.exclude(id=user_groups[0].id)
                user_groups=[user_groups[0]]
        else:
            context['team'] = user_groups[0]
        team_users = User.objects.filter(is_active=True, groups__id=context['team'].id).order_by(User.USERNAME_FIELD)
        queues = TicketQueue.objects.filter(queuepermissions__group__id=context['team'].id, queuepermissions__group_write=True).distinct()
        tickets = Ticket.objects.filter(queue__in=queues).order_by('modified')
        context['tickets'] = tickets.exclude(status__in=[Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS, Ticket.DUPLICATE_STATUS])
        threads = TicketThread.objects.filter(ticket__in=context['tickets']).values_list('ticket', flat=True)
        context['new_messages'] = tickets.filter(id__in=threads).count()
        context['dashboard']=1
        context['triage_user'] = get_triage_users(self.request.user)
        context['cases'] = VulnerabilityCase.objects.filter(team_owner=context['team'], status=1).count()        
        return context
        
class DashboardView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    """A quick summary overview for users. A list of their own tickets,
    and a list of unassigned tickets"""
    template_name='vince/dashboard.html'
    login_url="vince:login"

    def test_func(self):
        if cognito_check_track_permissions(self.request):
            return is_in_group_vincetrack(self.request.user)
        return False

    def get_context_data(self, **kwargs):
        context = super(DashboardView, self).get_context_data(**kwargs)

#        cognito_verify_email(self.request)

        #open & reopened tickets
        tickets = Ticket.objects.select_related('queue').filter(assigned_to=self.request.user).order_by('modified')

        context['tickets'] = tickets.exclude(status__in=[Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS, Ticket.DUPLICATE_STATUS])

        context['ticketsjs'] = [ obj.as_dict() for obj in context['tickets']]
        context['breakdown'] = context['tickets'].values('status').order_by('status').annotate(count=Count('status'))
        my_cases = CaseAssignment.objects.filter(assigned=self.request.user).distinct().values_list('case')
        context['dashboard']=1
        context['triage_user'] = get_triage_users(self.request.user)

        ca = Action.objects.select_related('caseaction').filter(caseaction__case__in=my_cases)
        ta = Action.objects.select_related('followup').filter(followup__ticket__in=tickets)
        context['activity'] = ca | ta
        context['activity'] = context['activity'].order_by('-date')[:15]
        #allcases
        cases = CaseAssignment.objects.filter(assigned=self.request.user)
        context['publishedcases'] = CaseAssignment.objects.filter(assigned=self.request.user, case__status=1).exclude(case__vulnote__date_published__isnull=True).order_by('case__due_date')
        context['cases'] = CaseAssignment.objects.filter(assigned=self.request.user, case__status=1, case__vulnote__date_published__isnull=True).order_by('case__due_date')
        my_case_list = list(cases.values_list('case__vuid', flat=True))
        vc_cases = Case.objects.filter(vuid__in=my_case_list)
        redlight = []
        context['new_posts'] = 0
        post_ids = []
        for case in vc_cases:
            lastpost = Post.objects.filter(case=case).exclude(author__username=self.request.user).order_by('-modified')
            last_viewed = CaseViewed.objects.filter(user__username=self.request.user.username, case=case).first()
            if lastpost and last_viewed:
                posts = lastpost.filter(modified__gt=last_viewed.date_viewed)
                if posts:
                    redlight.append(case.vuid)
                    context['new_posts'] += posts.count()
                    for post in posts:
                        post_ids.append(post.id)

        context['redlight'] = cases.filter(case__vuid__in=redlight)
        context['cases'] = context['cases'].exclude(case__vuid__in=redlight)
        context['publishedcases'] = context['publishedcases'].exclude(case__vuid__in=redlight)
        context['post_activity'] = Post.objects.filter(id__in=post_ids).order_by('-modified')
        context['new_messages'] = TicketThread.objects.filter(ticket__in=context['tickets']).count()
        today = datetime.now(pytz.utc)
        reminders = VinceReminder.objects.filter(user=self.request.user, alert_date__lte=today).order_by('-alert_date')
        context['len_reminders'] = len(reminders)
        context['reminders'] = reminders[:10]
        return context

class DashboardCaseChartView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name="vince/include/case_chart.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(DashboardCaseChartView, self).get_context_data(**kwargs)

        cases = CaseAssignment.objects.filter(assigned=self.request.user)
        context['cases'] = CaseAssignment.objects.filter(assigned=self.request.user, case__status=1, case__vulnote__date_published__isnull=True).order_by('case__due_date')
        context['publishedcases'] = CaseAssignment.objects.filter(assigned=self.request.user, case__status=1).exclude(case__vulnote__date_published__isnull=True).order_by('case__due_date')
        my_case_list = list(cases.values_list('case__vuid', flat=True))
        vc_cases = Case.objects.filter(vuid__in=my_case_list)
        redlight = []
        for case in vc_cases:
            lastpost = Post.objects.filter(case=case).exclude(author__username=self.request.user).order_by('-modified')
            last_viewed = CaseViewed.objects.filter(user__username=self.request.user.username, case=case).first()
            if lastpost and last_viewed:
                posts = lastpost.filter(modified__gt=last_viewed.date_viewed)
                if posts:
                    redlight.append(case.vuid)
        context['redlight'] = cases.filter(case__vuid__in=redlight)
        context['cases'] = context['cases'].exclude(case__vuid__in=redlight)
        context['publishedcases'] = context['publishedcases'].exclude(case__vuid__in=redlight)
        return context

class DashboardStatsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url="vince:login"
    template_name="vince/include/dashboard_stats.html"

    def test_func(self):
        if cognito_check_track_permissions(self.request):
            return is_in_group_vincetrack(self.request.user)
        return False

    def get_context_data(self, **kwargs):
        context = super(DashboardStatsView, self).get_context_data(**kwargs)
        context['new_posts'] = 0
        cases = CaseAssignment.objects.filter(assigned=self.request.user)
        my_case_list = list(cases.values_list('case__vuid', flat=True))
        vc_cases = Case.objects.filter(vuid__in=my_case_list)
        new_posts = 0
        for case in vc_cases:
            lastpost = Post.objects.filter(case=case).exclude(author__username=self.request.user).order_by('-modified')
            last_viewed = CaseViewed.objects.filter(user__username=self.request.user.username, case=case).first()
            if lastpost and last_viewed:
                posts = lastpost.filter(modified__gt=last_viewed.date_viewed)
                if posts:
                    new_posts += posts.count()
        context['new_posts'] = new_posts
        tickets = Ticket.objects.select_related('queue').filter(assigned_to=self.request.user).exclude(status__in=[Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS, Ticket.DUPLICATE_STATUS]).order_by('modified')
        context['breakdown'] = tickets.values('status').order_by('status').annotate(count=Count('status'))
        context['new_messages'] = TicketThread.objects.filter(ticket__in=tickets).count()
        today = datetime.now(pytz.utc)
        reminders = VinceReminder.objects.filter(user=self.request.user, alert_date__lte=today).order_by('-alert_date')
        context['len_reminders'] = len(reminders)
        context['reminders'] = reminders[:10]
        return context

    def post(self, request, *args, **kwargs):
        all_cases = CaseAssignment.objects.filter(assigned=self.request.user)
        publishedcases = CaseAssignment.objects.filter(assigned=self.request.user, case__status=1).exclude(case__vulnote__date_published__isnull=True).order_by('case__due_date')
        cases = CaseAssignment.objects.filter(assigned=self.request.user, case__status=1, case__vulnote__date_published__isnull=True).order_by('case__due_date')
        my_case_list = list(all_cases.values_list('case__vuid', flat=True))
        vc_cases = Case.objects.filter(vuid__in=my_case_list)

        redlight = []
        new_posts = 0
        postsjs = []
        post_ids = []
        for case in vc_cases:
            lastpost = Post.objects.filter(case=case).exclude(author__username=self.request.user).order_by('-modified')
            last_viewed = CaseViewed.objects.filter(user__username=self.request.user.username, case=case).first()
            if lastpost and last_viewed:
                posts = lastpost.filter(modified__gt=last_viewed.date_viewed)
                if posts:
                    redlight.append(case.vuid)
                    new_posts += posts.count()
                    for post in posts:
                        post_ids.append(post.id)
                        try:
                            postsjs.append({'url': reverse("vinny:case", args=[case.id]), 'case': f"{settings.CASE_IDENTIFIER}{post.case.vuid}", 'from': post.author.vinceprofile.preferred_username, 'group': post.group.groupcontact.contact.vendor_name})
                        except:
                            postsjs.append({'url': reverse("vinny:case", args=[case.id]), 'case': f"{settings.CASE_IDENTIFIER}{post.case.vuid}", 'from': post.author.vinceprofile.preferred_username, 'group': 'No affiliation'})
        redlight = cases.filter(case__vuid__in=redlight)
        cases = context['cases'].exclude(case__vuid__in=redlight)
        publishedcases = context['publishedcases'].exclude(case__vuid__in=redlight)
        post_activity = Post.objects.filter(id__in=post_ids).order_by('-modified')
        return context

class AttachmentView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url="vince:login"

    def test_func(self):
        if cognito_check_track_permissions(self.request):
            return is_in_group_vincetrack(self.request.user)
        return False

    def get(self, request, *args, **kwargs):
        logger.debug(self.kwargs['path'])
        try:
            attachment = Attachment.objects.filter(uuid=self.kwargs['path']).first()
            # if the UUID is not valid, this will throw a ValidationError
        except:
            raise Http404

        if attachment:
            filename = attachment.filename
            # do this for old files
            filename = filename.replace("\r", "")
            filename = filename.replace("\n", "")
            filename = filename.strip()
            mime_type = attachment.mime_type
            response = HttpResponseRedirect(attachment.access_url, content_type = mime_type)

            #test URL
            if not(attachment.file.storage.exists(attachment.file.name)):
                # try uuid instead
                if not(attachment.file.storage.exists(str(attachment.uuid))):
                    raise Http404
                else:
                    url = attachment.file.storage.url(str(attachment.uuid), parameters={'ResponseContentDisposition': f'attachment; filename="{attachment.filename}"'})
                    response = HttpResponseRedirect(url)

            response['ResponseContentDisposition'] = f"attachment; filename=\"{filename}\""
            response["Content-type"] = mime_type
            response["Cache-Control"] = "must-revalidate"
            response["Pragma"] = "must-revalidate"

            return response
        raise Http404


def quickSearch(request):
    input = request.GET.get('searchbar', False)
    if input == False:
        #try again for backwards compatibility with old kb
        input = request.GET.get('query', False)
        if input:
            if "Keywords=" in input:
                keywords = input.split("=")
                if len(keywords) > 1:
                    input = keywords[1]

    if input:
        response = redirect("vince:search")
        input=input.replace('#', '%23')
        response['Location'] += '?q='+input
        return response
    else:
        return redirect("vince:search")


class UnattachVinceFile(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/confirm_unattach.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VinceFile, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case.case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(UnattachVinceFile, self).get_context_data(**kwargs)
        context['file'] = get_object_or_404(VinceFile, id=self.kwargs['pk'])
        context['case'] = context['file'].case
        return context

    def post(self, request, *args, **kwargs):
        file = get_object_or_404(VinceFile, id=self.kwargs['pk'])

        logger.debug("IN UNATTACH FILE!!!!")

        post = file.post
        vulnote = file.vulnote
        #getattachment
        vt = VinceTrackAttachment.objects.using('vincecomm').filter(id=file.comm_id).first()
        if vt:
            if vt.shared:
                file.to_remove = True
                file.save()
            else:
                logger.debug("REMOVE FILE!!!")
                vt.file.file.delete(save=False)
                vt.file.delete()

                file.delete()

        if post:
            files = VinceFile.objects.filter(case=file.case, post=post)
        elif vulnote:
            files = VinceFile.objects.filter(case=file.case, vulnote=True)
        else:
            files = VinceFile.objects.filter(case=file.case, vulnote=False).exclude(post__isnull=False)

        return render(request, "vince/vulnote_files.html", {'files': files})

class UploadFile(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    template_name = "vince/upload.html"
    login_url = "vince:login"
    form_class = UploadFileForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_form_kwargs(self):
        kwargs = super(UploadFile, self).get_form_kwargs()
        kwargs.update({
            "user": self.request.user,
        })
        return kwargs

#    def post(self, request, *args, **kwargs):
#        logger.debug(f"TicketFilterResults Post: {self.request.POST}")
#        form = UploadFileForm(self.request.POST)
#        if form.is_valid():
#            return self.form_valid(form)
#        else:
#            return super().form_invalid(form)
#
    def form_valid(self, form):
        vc = form.save()

        if vc:
            attach = VinceTrackAttachment.objects.using('vincecomm').filter(id=vc.comm_id).first()
            url = reverse("vinny:attachment", args=["track", attach.file.uuid])
            return JsonResponse({'status': 'success', 'image_url': url, 'id': vc.id, 'filename': vc.filename, 'remove_link': reverse('vince:unattachfile', args=[vc.id])}, status=200)
        else:
            return JsonResponse({'status': 'invalid file'}, status=400)



class SearchAll(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    template_name = 'vince/search.html'
    login_url = "vince:login"
    form_class = AllSearchForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(SearchAll, self).get_context_data(**kwargs)
        context['searchpage']=1
        search = self.request.GET.get('q', False)
        facet = self.request.GET.get('facet', False)
        if facet and facet != "All":
            context['facet'] = facet
        if search:
            context['form'] = self.form_class(initial={'searchbar':search})
            context['search'] = search
        return context

class AllResults(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/results.html'
    paginate_by = 50
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        logger.debug(f"TicketFilterResults GET: {self.request.GET}")
        search_term = self.request.GET.get('searchbar', None)
        tktsearch, queue, tktid = is_query_ticket_id(search_term)
        search_query = process_query(search_term)
        search_tags = process_query_for_tags(search_term)
        facet = self.request.GET.get('facet', 'All')
        search_nolive_query = process_query(search_term, False)
        case_results=[]
        contact_results=[]
        ticket_results=[]
        ticket_spec_results = []
        vul_results=[]
        cve_results=[]
        vince_user_results=[]
        group_results=[]

        my_queues = get_r_queues(self.request.user)
        
        if facet == "All":
            ticket_results = Ticket.objects.search(search_query).filter(queue__in=my_queues)
            tkttags = TicketTag.objects.filter(ticket__queue__in=my_queues, tag__in=search_tags).values_list('ticket__id', flat=True)
            if ticket_results and tkttags:
                ticket_results = Ticket.objects.filter(Q(id__in=tkttags) | Q(id__in=ticket_results))
            elif tkttags:
                ticket_results = Ticket.objects.filter(id__in=tkttags)
            tkt_title = Ticket.objects.filter(queue__in=my_queues, title__icontains=search_nolive_query)
            activity_results = FollowUp.objects.filter(ticket__queue__in=my_queues).filter(Q(title__icontains=search_term)|Q(comment__icontains=search_term)).values_list('ticket', flat=True)
            activities = Ticket.objects.filter(id__in=activity_results)
            ticket_results = ticket_results | tkt_title | activities
            
            case_results = VulnerabilityCase.objects.search(search_query)
            casetags = CaseTag.objects.filter(tag__in=search_tags).values_list('case__id', flat=True)
            if case_results and casetags:
                case_results = VulnerabilityCase.objects.filter(Q(id__in=casetags) | Q(id__in=case_results))
            elif casetags:
                case_results = VulnerabilityCase.objects.filter(id__in=casetags)
            casetitlesearch = VulnerabilityCase.objects.filter(title__icontains=search_nolive_query)
            case_results = case_results | casetitlesearch

            vince_user_results = VinceProfile.objects.using('vincecomm').filter(Q(user__first_name__icontains=search_term) | Q(user__last_name__icontains=search_term) | Q(preferred_username__icontains=search_term) | Q(user__email__icontains=search_term))
            user_contacts = list(vince_user_results.values_list('user__email', flat=True))
            email_contacts = EmailContact.objects.filter(contact__vendor_type="Contact", email__in=user_contacts).values_list('contact__id', flat=True)
            email_results = EmailContact.objects.filter(Q(email__icontains=search_term) | Q(name__icontains=search_term)).exclude(contact__id__in=email_contacts).values_list('contact', flat=True)
            emails = Contact.objects.filter(id__in=email_results)
            contact_results = Contact.objects.search(search_nolive_query).exclude(id__in=email_contacts)
            group_results = ContactGroup.objects.filter(Q(name__icontains=search_term) | Q(srmail_peer_name__icontains=search_term))
            ctags = ContactTag.objects.filter(tag__in=search_tags).values_list('contact__id', flat=True)
            if ctags:
                ctags = Contact.objects.filter(id__in=ctags)
                contact_results = contact_results | emails | ctags
            else:
                contact_results = contact_results | emails
            vul_results = Vulnerability.objects.search(search_query)
            vultags = VulnerabilityTag.objects.filter(tag__in=search_tags).values_list('vulnerability__id', flat=True)
            if vultags:
                vultags = Vulnerability.objects.filter(id__in=vultags)
                vul_results = vul_results | vultags
            cve_results = CVEAllocation.objects.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],
                                                      params=[search_query])

            vulnote_results = VulNoteRevision.objects.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"], params=[search_query]).values_list('vulnote__case__id', flat=True)
            if vulnote_results:
                vnote_cases = VulnerabilityCase.objects.filter(id__in=vulnote_results)
                case_results = case_results | vnote_cases

                
        elif facet == "Tickets":
            ticket_results = Ticket.objects.search(search_query).filter(queue__in=my_queues)
            tkttags = TicketTag.objects.filter(ticket__queue__in=my_queues, tag__in=search_tags).values_list('ticket__id', flat=True)
            if ticket_results and tkttags:
                ticket_results = Ticket.objects.filter(Q(id__in=tkttags) | Q(id__in=ticket_results))
            elif tkttags:
                ticket_results = Ticket.objects.filter(id__in=tkttags)
            tkt_title = Ticket.objects.filter(queue__in=my_queues, title__icontains=search_nolive_query)
            activity_results = FollowUp.objects.filter(ticket__queue__in=my_queues).filter(Q(title__icontains=search_term)|Q(comment__icontains=search_term)).values_list('ticket', flat=True)
            activities = Ticket.objects.filter(id__in=activity_results)
            ticket_results = ticket_results | tkt_title | activities
        elif facet == "Contacts":
            vince_user_results = VinceProfile.objects.using('vincecomm').filter(Q(user__first_name__icontains=search_term) | Q(user__last_name__icontains=search_term) | Q(preferred_username__icontains=search_term) | Q(user__email__icontains=search_term))
            user_contacts = list(vince_user_results.values_list('user__email', flat=True))
            email_contacts = EmailContact.objects.filter(contact__vendor_type="Contact", email__in=user_contacts).values_list('contact__id', flat=True)
            email_results = EmailContact.objects.filter(Q(email__icontains=search_term) | Q(name__icontains=search_term)).exclude(contact__id__in=email_contacts).values_list('contact', flat=True)
            emails = Contact.objects.filter(id__in=email_results)
            ctags = ContactTag.objects.filter(tag__in=search_tags).values_list('contact__id', flat=True)
            contact_results = Contact.objects.search(search_nolive_query).exclude(id__in=email_contacts)
            if ctags:
                ctags = Contact.objects.filter(id__in=ctags)
                contact_results = contact_results | emails | ctags
            else:
                contact_results = contact_results | emails

            group_results = ContactGroup.objects.filter(Q(name__icontains=search_term) | Q(srmail_peer_name__icontains=search_term))
        elif facet == "Cases":
            case_results = VulnerabilityCase.objects.search(search_query)
            casetags = CaseTag.objects.filter(tag__in=search_tags).values_list('case__id', flat=True)
            if case_results and	casetags:
                case_results = VulnerabilityCase.objects.filter(Q(id__in=casetags) | Q(id__in=case_results))
            elif casetags:
                case_results = VulnerabilityCase.objects.filter(id__in=casetags)

            casetitlesearch = VulnerabilityCase.objects.filter(title__icontains=search_nolive_query)
            case_results = case_results | casetitlesearch

            vulnote_results = VulNoteRevision.objects.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"], params=[search_query]).values_list('vulnote__case__id', flat=True)
            if vulnote_results:
                vnote_cases = VulnerabilityCase.objects.filter(id__in=vulnote_results)
                case_results = case_results | vnote_cases
                
        elif facet == "Vuls":
            vul_results = Vulnerability.objects.search(search_query)
            cve_results = CVEAllocation.objects.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],
                                                      params=[search_query])
            vultags = VulnerabilityTag.objects.filter(tag__in=search_tags).values_list('vulnerability__id', flat=True)
            if vultags:
                vultags = Vulnerability.objects.filter(id__in=vultags)
                vul_results = vul_results | vultags
        elif facet == "Vince":
            vince_user_results = VinceProfile.objects.using('vincecomm').filter(Q(user__first_name__icontains=search_term) | Q(user__last_name__icontains=search_term) | Q(preferred_username__icontains=search_term) | Q(user__email__icontains=search_term))

        if tktsearch:
            ticket_spec_results = Ticket.objects.filter(id=tktid, queue__in=my_queues)

        results = chain(ticket_spec_results, ticket_results, case_results, contact_results, vul_results, cve_results, vince_user_results, group_results)

        qs = sorted(results,
                    key=lambda instance: instance.modified,
                    reverse=True)

        page = self.request.GET.get('page', 1)

        paginator = Paginator(qs, 50)

        return render(request, self.template_name, {'object_list': paginator.page(page), 'total': len(qs) })

class TicketFilterResults(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    template_name = 'vince/searchresults.html'
    paginate_by = 50
    model = Ticket
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(TicketFilterResults, self).get_context_data(**kwargs)
        context['ticketpage']=1
        return context

    def get_queryset(self):
        return Ticket.objects.filter(status__in=[Ticket.OPEN_STATUS, Ticket.IN_PROGRESS_STATUS, Ticket.REOPENED_STATUS]).order_by('-modified')

    def post(self, request, *args, **kwargs):
        logger.debug(f"TicketFilterResults Post: {self.request.POST}")
        form = TicketFilterForm(self.request.POST)

        res = Ticket.objects.filter(queue__queuepermissions__group__in=self.request.user.groups.all(), queue__queuepermissions__group_read=True).order_by('-modified').distinct()

        page = self.request.POST.get('page', 1)
        if 'status' in self.request.POST:
            statuslist = self.request.POST.getlist('status')
            res = res.filter(status__in=statuslist)

        if 'datestart' in self.request.POST:
            # add a day to dateend since it translates to 0AM
            enddate = DateTimeField().clean(self.request.POST['dateend']) + timedelta(days=1)
            if self.request.POST['datestart']:
                res = res.filter(created__range=(DateTimeField().clean(self.request.POST['datestart']),
                                                 enddate))
            elif 'dateend' in self.request.POST:
                if self.request.POST['dateend']:
                    res = res.filter(created__range=(DateTimeField().clean('1970-01-01'),
                                                     enddate))
        if 'queue' in self.request.POST:
            queuelist = self.request.POST.getlist('queue')
            res = res.filter(queue__id__in=queuelist)

        if 'case' in self.request.POST:
            caselist = self.request.POST.getlist('case')
            res = res.filter(case__id__in=caselist)

        if 'team' in self.request.POST:
            teamlist = self.request.POST.getlist('team')
            groups = Group.objects.filter(id__in=teamlist)
            res = res.filter(assigned_to__groups__in=groups)

        if 'owner' in self.request.POST:
            ownerlist = self.request.POST.getlist('owner')
            if '0' in ownerlist:
                res = res.filter(Q(assigned_to__isnull=True) | Q(assigned_to__id__in=ownerlist))
            else:
                res = res.filter(assigned_to__id__in=ownerlist)

        if 'contact' in self.request.POST:
            if self.request.POST['contact']:
                tkts = TicketContact.objects.filter(contact__vendor_name=self.request.POST['contact']).values_list('ticket', flat=True)
                res = res.filter(pk__in=tkts)
                print(res)
                self.template_name = 'vince/include/case_tasks.html'
                sort = self.request.POST.get('sort', None)
                if sort:
                    sort = int(sort)
                    # 0 is all tickets
                    if sort:
                        if sort > 1:
                            res = res.filter(status=Ticket.CLOSED_STATUS)
                        else:
                            # opened tickets
                            res = res.exclude(status=Ticket.CLOSED_STATUS)
        if self.request.POST.get('submitted_by'):
            res = res.filter(submitter_email=self.request.POST.get('submitted_by'))
            self.template_name = 'vince/include/case_tasks.html'
            sort = self.request.POST.get('sort', None)
            if sort:
                sort = int(sort)
                # 0 is all tickets
                if sort:
                    if sort > 1:
                        res = res.filter(status=Ticket.CLOSED_STATUS)
                    else:
                        # opened tickets
                        res = res.exclude(status=Ticket.CLOSED_STATUS)

        if self.request.POST.get('tag'):
            tags = process_query_for_tags(self.request.POST['tag'])

            tkttags = TicketTag.objects.filter(tag__in=tags).values_list('ticket__id', flat=True)
            res = res.filter(id__in=tkttags)

        if 'wordSearch' in self.request.POST:
            if self.request.POST['wordSearch']:
                tktsearch, queue, tktid = is_query_ticket_id(self.request.POST['wordSearch'])
                if tktsearch:
                    tktsearch = Ticket.objects.filter(id=tktid).first()

                # also search for tags
                tags = process_query_for_tags(self.request.POST['wordSearch'])
                # limit to what this user can see
                tkttags = list(TicketTag.objects.filter(tag__in=tags, ticket__in=res).values_list('ticket__id', flat=True))
                if tktsearch:
                    tkttags.append(tktsearch.id)

                wordSearch = process_query(self.request.POST['wordSearch'])
                tkt_ids = res.values_list('id', flat=True)
                titlesearch = list(res.filter(title__icontains=self.request.POST['wordSearch']).values_list('id', flat=True))
                res = list(res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[wordSearch]).values_list('id', flat=True))

                activity_results = list(FollowUp.objects.filter(Q(title__icontains=self.request.POST['wordSearch'])|Q(comment__icontains=self.request.POST['wordSearch'])).filter(ticket__id__in=tkt_ids).values_list('ticket', flat=True))

                activities = list(Ticket.objects.filter(id__in=activity_results).values_list('id', flat=True))
                res = titlesearch + res + activities

                # build query
                if res and tkttags:
                    results = Ticket.objects.filter(Q(id__in=tkttags) | Q(id__in=res))
                elif tkttags:
                    results = Ticket.objects.filter(id__in=tkttags)
                else:
                    results = Ticket.objects.filter(id__in=res)

                res = results



        res = res.order_by('-modified')

        paginator = Paginator(res, 50)

        if self.request.POST.get('contact') or self.request.POST.get('submitted_by'):
            return render(request, self.template_name, {'ticket_list': paginator.page(page), 'total': res.count() })
        else:
            return render(request, self.template_name, {'object_list': paginator.page(page), 'total': res.count(), 'form': form })


class ActivityFilterResults(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    template_name = 'vince/include/case_timeline.html'
    paginate_by = 50
    model = Ticket
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ActivityFilterResults, self).get_context_data(**kwargs)
        context['activitypage']=1
        return context

    def get_queryset(self):
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        case_perms = CasePermissions.objects.filter(group_read=True, group__in=user_groups).values_list('case', flat=True)
        ca = list(CaseAction.objects.filter(case__in=case_perms).values_list('action_ptr_id', flat=True))
        queue_perms = QueuePermissions.objects.filter(group_read=True, group__in=user_groups).values_list('queue', flat=True)
        ta = list(FollowUp.objects.filter(ticket__queue__in=queue_perms).values_list('action_ptr_id', flat=True))
        #ca = Action.objects.select_related('caseaction').all()
        #ta = Action.objects.select_related('followup').all()
        actions = ca + ta
        return Action.objects.filter(id__in=actions).order_by('-date')

    def post(self, request, *args, **kwargs):
        logger.debug(f"ActivityFilterResults Post: {self.request.POST}")

        res = self.get_queryset()

        page = self.request.POST.get('page', 1)

        if 'datestart' in self.request.POST:
            # add a day to dateend since it translates to 0AM
            enddate = DateTimeField().clean(self.request.POST['dateend']) + timedelta(days=1)
            if self.request.POST['datestart']:
                res = res.filter(date__range=(DateTimeField().clean(self.request.POST['datestart']),enddate))
            elif 'dateend' in self.request.POST:
                if self.request.POST['dateend']:
                    res = res.filter(date__range=(DateTimeField().clean('1970-01-01'), enddate))

        if 'user' in self.request.POST:
            userlist = self.request.POST.getlist('user')
            if '0' in userlist:
                res = res.filter(Q(user__isnull=True) | Q(user__id__in=userlist))
            else:
                res = res.filter(user__id__in=userlist)

        if 'wordSearch' in self.request.POST:
            if self.request.POST['wordSearch']:
                wordSearch = self.request.POST['wordSearch']
                res = res.filter((Q(title__icontains=wordSearch) | Q(comment__icontains=wordSearch)))

        paginator = Paginator(res, 50)

        return render(request, self.template_name, {'activity': paginator.page(page), 'paginator': 1, 'total': res.count() })

class ActivityView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/activity.html'
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ActivityView, self).get_context_data(**kwargs)
        context['activitypage'] = 1
        context['triage_user'] = get_triage_users(self.request.user)
        assignable_users = User.objects.filter(is_active=True, groups__name='vince').order_by(User.USERNAME_FIELD)

        date_from = self.request.GET.get('date_from')
        initial = {}
        if date_from:
            initial['datestart'] = DateField().clean(date_from)
        date_to = self.request.GET.get('date_to')
        if date_to:
            initial['dateend'] = DateField().clean(date_to)
        if self.request.GET.get('user'):
            initial['user'] = int(self.request.GET.get('user'))
        form = ActivityFilterForm(initial=initial)
        form.fields['user'].choices = [
            (u.id, u.usersettings.vince_username) for u in assignable_users]
        context['form'] = form
        return context


class TicketFilter(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = TicketFilterForm
    template_name = 'vince/searchtickets.html'
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(TicketFilter, self).get_context_data(**kwargs)
        context['ticketpage']=1
        assignable_users = User.objects.filter(is_active=True, groups__name='vince').order_by(User.USERNAME_FIELD)

        readable_queues = TicketQueue.objects.filter(queuepermissions__group__in=self.request.user.groups.all(), queuepermissions__group_read=True).distinct()

        date_from = self.request.GET.get('date_from')
        initial = {}
        if date_from:
            initial['datestart'] = DateField().clean(date_from)
        date_to = self.request.GET.get('date_to')
        if date_to:
            initial['dateend'] = DateField().clean(date_to)
        if self.request.GET.get('owner'):
            initial['owner'] = int(self.request.GET.get('owner'))
        queue = self.request.GET.get('queue')
        if queue:
            queue = TicketQueue.objects.filter(title=queue).first()
            initial['queue'] = queue.id
        unassigned = self.request.GET.get('unassigned')
        if unassigned:
            initial['owner'] = ['0']
        status = self.request.GET.getlist('status')
        logger.debug(status)
        tag = self.request.GET.get('tag')
        if tag:
            initial['tag'] = tag

        if status:
            initial['status'] = status
        else:
            if tag:
                #if tag and not status, search for tags in all statuses
                initial['status'] = []
            else:
                initial['status'] = [Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS]

        team = self.request.GET.get('team')
        if team:
            initial['team'] = team
        form = TicketFilterForm(initial=initial)
        form.fields['queue'].choices = [
            (q.id, q.title) for q in readable_queues]

        form.fields['owner'].choices = [(0, 'Unassigned')] + [
            (u.id, u.usersettings.vince_username) for u in assignable_users]

        form.fields['team'].choices = [(g.id, g.name) for g in Group.objects.filter(groupsettings__contact__isnull=False)]

        context['form'] = form
        return context


class AddCaseArtifactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = AddArtifactForm
    template_name='vince/addartifact.html'
    login_url = "vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        else:
            return False

    def get(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(AddCaseArtifactView, self).get_context_data(**kwargs)
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        artifacts = Artifact.objects.filter(caseartifact__case=case)
        ticketartifacts = Artifact.objects.filter(ticketartifact__ticket__case=case)
        allartifacts = artifacts | ticketartifacts
        context['case'] = case
        context['artifacts'] = allartifacts.order_by('-date_added')
        return context

    def form_valid(self, form):
        #logger.debug("IN FORM AVALID")
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        artifact = form.save(case=case, user=self.request.user)
        tags = self.request.POST.getlist('taggles[]')
        for tag in tags:
            tag = ArtifactTag(artifact=artifact,
                              tag = tag,
                              user = self.request.user)
            tag.save()
        return redirect("vince:case", case.id)

    def form_invalid(self, form):
        logger.debug(f"AddCaseArtifactsView errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        form = AddArtifactForm(request.POST, request.FILES)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

class AddTicketArtifactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = AddArtifactForm
    template_name='vince/addartifact.html'
    login_url = "vince:login"


    def	test_func(self):
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        return is_in_group_vincetrack(self.request.user) and has_queue_write_access(self.request.user, ticket.queue)

    def get(self, request, *args, **kwargs):
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        return super().get(request, *args, **kwargs)


    def get_context_data(self, **kwargs):
        context = super(AddTicketArtifactView, self).get_context_data(**kwargs)
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        artifacts = Artifact.objects.filter(ticketartifact__ticket=ticket)
        context['ticket'] = ticket
        context['artifacts'] = artifacts.order_by('-date_added')
        return context

    def form_valid(self, form):
        #logger.debug("IN FORM AVALID")
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        artifact = form.save(ticket=ticket, user=self.request.user)
        tags = self.request.POST.getlist('taggles[]')
        for tag in tags:
            tag = ArtifactTag(artifact=artifact,
                              tag = tag,
                              user = self.request.user)
            tag.save()
        return HttpResponseRedirect(ticket.get_absolute_url())

    def form_invalid(self, form):
        logger.debug(f"AddTicketArtifactView errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        form = AddArtifactForm(request.POST, request.FILES)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

class CaseTaskFilter(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    template_name = 'vince/include/case_tasks.html'
    model = Ticket

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(CaseTaskFilter, self).get_context_data(**kwargs)
        return context

    def get_queryset(self):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        return Tickets.objects.filter(case=case).order_by('status', '-modified')

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])

        sort = self.request.POST.get('sort', None)
        if sort:
            sort = int(sort)
            # 0 is all tickets
        if sort:
            if sort > 1:
                # closed tickets
                res = Ticket.objects.filter(case=case, status=Ticket.CLOSED_STATUS)
            else:
                # opened tickets
                res = Ticket.objects.filter(case=case).exclude(status=Ticket.CLOSED_STATUS)
        else:
            res = Ticket.objects.filter(case=case)

        res = res.filter(Q(description__icontains=self.request.POST['keyword']) | Q(submitter_email__icontains=self.request.POST['keyword']) | Q(title__icontains=self.request.POST['keyword']))

        res = res.order_by('status', '-modified')

        ticketsjs = [obj.as_dict() for obj in res]
        return JsonResponse(ticketsjs, safe=False, status=200)



class CommunicationsFilterResults(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    template_name= 'vince/include/case_timeline.html'
    paginate_by = 10
    model = CaseAction
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(CommunicationsFilterResults, self).get_context_data(**kwargs)
        return context

    def get_queryset(self):
        return CaseAction.objects.order_by('-date')

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])

        keyword = self.request.POST.get('keyword', None)
        if keyword == '':
            keyword = None
        vendorlist = self.request.POST.getlist('vendor')
        commslist = self.request.POST.getlist('communication_type', ['0','1','2','3','4','5','6','7','8','9'])
        participantlist = self.request.POST.getlist('participants')
        vcmembers_list=None
        if participantlist:
            #get vc participants
            members = CaseMember.objects.filter(id__in=participantlist)
            vcmembers_list = list(members.values_list('participant', flat=True))
        if vendorlist:
            # get vc vendors
            contacts = list(VulnerableVendor.objects.filter(id__in=vendorlist).values_list('contact', flat=True))
            vc_groups = Group.objects.using('vincecomm').filter(groupcontact__contact__vendor_id__in=contacts)
            # add to vcmembers_list
            if vcmembers_list:
                vcmembers_list.extend(list(User.objects.using('vincecomm').filter(groups__in=vc_groups).values_list('id', flat=True)))
            else:
                vcmembers_list = list(User.objects.using('vincecomm').filter(groups__in=vc_groups).values_list('id', flat=True))

        vt_results = []
        # vincetrack things
        if commslist:
            if '1' in commslist:
                # vincetrack is 0 and 1
                commslist.append('0')

            ca = Action.objects.select_related('caseaction').filter(caseaction__case=case, caseaction__action_type__in=commslist)
            ta = []
            if '8' in commslist:
                ta = Action.objects.select_related('followup').filter(followup__ticket__case=case)
                vt_results = ca|ta
            else:
                vt_results = ca

            vt_results = vt_results.order_by('-date')
            if vendorlist:
                vt_results = vt_results.filter(caseaction__vendor__in=vendorlist)
            if participantlist:
                vt_results = vt_results.filter(caseaction__title__icontains="Participant")
            if 'datestart' in self.request.POST:
                enddate = DateTimeField().clean(self.request.POST['dateend']) + timedelta(days=1)
                if self.request.POST['datestart']:
                    vt_results = vt_results.filter(date__range=(DateTimeField().clean(self.request.POST['datestart']), enddate))
            elif 'dateend' in self.request.POST:
                if self.request.POST['dateend']:
                    vt_results=vt_results.filter(date__range=(DateTimeField().clean('1970-01-01'),
                                                     enddate))
            if keyword:
                vt_results = vt_results.filter((Q(title__icontains=keyword) | Q(comment__icontains=keyword)))
                print("AFTER KEYWORDS SEARCH")
                print(vt_results)
        posts = []
        messages = []

        vc_case = Case.objects.filter(vince_id=case.id).first()
        #vincecomm things
        vc_activity = []
        if any(elem in commslist for elem in [4, 5, 7]):
            vc_activity = VendorAction.objects.filter(case=vc_case)
            if keyword:
                vc_activity = vc_activity.filter(title__search=keyword)
        if '2' in commslist:
            posts = Post.objects.search(case=vc_case, query=keyword, author_list=vcmembers_list)
        if '3' in commslist:
            messages = Message.objects.search(case=vc_case, query=keyword, author_list=vcmembers_list)

        case_activity = chain(vt_results, vc_activity, posts, messages)
        activity = sorted(case_activity,
                          key=lambda instance:instance.created,
                          reverse=True)

        paginator = Paginator(activity, 10)
        print(paginator.page(1))
        return render(request, self.template_name, {'activity': activity, 'total': activity.count(), 'case': case, 'allow_edit': True})


class CaseFilterResults(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    template_name = 'vince/searchresults.html'
    paginate_by = 50
    model = VulnerabilityCase
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CaseFilterResults, self).get_context_data(**kwargs)
        context['casepage']=1
        return context

    def get_queryset(self):
        return VulnerabilityCase.objects.order_by('-modified')

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        res = VulnerabilityCase.objects.all().order_by('-modified')
        form = CaseFilterForm(self.request.POST)
        page = self.request.POST.get('page', 1)
        if 'status' in self.request.POST:
            statuslist = self.request.POST.getlist('status')
            if len(statuslist) == 1 and '3' in statuslist:
                res = res.exclude(vulnote__date_published__isnull=True)
            elif len(statuslist) == 1 and '4' in statuslist:
                res = res.exclude(vulnote__date_published__isnull=False)
            if '3' in statuslist:
                statuslist.remove('3')
            if '4' in statuslist:
                statuslist.remove('4')
            if statuslist:
                res = res.filter(status__in=statuslist)


        if 'datestart' in self.request.POST:
            enddate = DateTimeField().clean(self.request.POST['dateend']) + timedelta(days=1)
            if self.request.POST['datestart']:
                res = res.filter(created__range=(DateTimeField().clean(self.request.POST['datestart']),
                                                 enddate))
            elif 'dateend' in self.request.POST:
                if self.request.POST['dateend']:
                    res = res.filter(created__range=(DateTimeField().clean('1970-01-01'),
                                                     enddate))

        if 'owner' in self.request.POST:
            ownerlist = self.request.POST.getlist('owner')
            if '0' in ownerlist:
                all_assigned_cases = list(CaseAssignment.objects.all().values_list('case', flat=True))
                all_unassigned_cases = list(VulnerabilityCase.objects.exclude(id__in=all_assigned_cases).values_list('id', flat=True))
                cases = list(CaseAssignment.objects.filter(assigned__id__in=ownerlist).values_list('case', flat=True))
                cases = cases + all_unassigned_cases
            else:
                cases = CaseAssignment.objects.filter(assigned__id__in=ownerlist).values_list('case', flat=True)
            res = res.filter(id__in=cases)

        if 'team' in self.request.POST:
            teamlist = self.request.POST.getlist('team')
            groups = Group.objects.filter(id__in=teamlist)
            cases = list(CaseAssignment.objects.filter(assigned__groups__in=groups).values_list('case', flat=True))
            res = res.filter(id__in=cases)

        if self.request.POST.get('tag'):
            tags = process_query_for_tags(self.request.POST['tag'])
            casetags = CaseTag.objects.filter(tag__in=tags).values_list('case__id', flat=True)
            res = res.filter(id__in=casetags)
            
        if 'wordSearch' in self.request.POST:
            if self.request.POST['wordSearch']:
                wordSearch = process_query(self.request.POST['wordSearch'])
                titlesearch = res.filter(title__icontains=self.request.POST['wordSearch'])
                res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[wordSearch])
                res = res | titlesearch
                # also search for tags
                tags = process_query_for_tags(self.request.POST['wordSearch'])
                # limit to what this user can see
                casetags = list(CaseTag.objects.filter(tag__in=tags).values_list('case__id', flat=True))

                if res and casetags:
                    results = VulnerabilityCase.objects.filter(Q(id__in=casetags) | Q(id__in=res))
                elif casetags:
                    results = VulnerabilityCase.objects.filter(id__in=casetags)
                else:
                    results = VulnerabilityCase.objects.filter(id__in=res)

                vulnote_results = VulNoteRevision.objects.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"], params=[wordSearch]).values_list('vulnote__case__id', flat=True)
                if vulnote_results:
                    vnote_cases = VulnerabilityCase.objects.filter(id__in=vulnote_results)
                    results = results | vnote_cases
                res = results

        res = res.order_by('-modified')
        
        paginator = Paginator(res, 50)
        return render(request, self.template_name, {'object_list': paginator.page(page), 'total': res.count(), 'form': form, 'case':1 })

class CaseFilter(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = CaseFilterForm
    template_name = 'vince/searchcases.html'
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CaseFilter, self).get_context_data(**kwargs)

        assignable_users = User.objects.filter(is_active=True, groups__name='vince').order_by(User.USERNAME_FIELD)
        context['casepage']=1
        date_from = self.request.GET.get('date_from')
        initial = {}
        if date_from:
            initial['datestart'] = DateField().clean(date_from)
        date_to = self.request.GET.get('date_to')
        if date_to:
            initial['dateend'] = DateField().clean(date_to)
        owner = self.request.GET.get('owner')
        if self.request.GET.get('owner'):
            initial['owner'] = int(owner)
        else:
            initial['owner'] = self.request.user.id
        status = self.request.GET.getlist('status')
        team = self.request.GET.get('team')
        if team:
            initial['team'] = team

        tag = self.request.GET.get('tag')
        if tag:
            initial['tag'] = tag

        if status:
            initial['status'] = status
        else:
            if tag:
                #if tag and not status, search for tags in all statuses
                initial['status'] = []
            else:
                initial['status'] = [VulnerabilityCase.ACTIVE_STATUS]

        form = CaseFilterForm(initial=initial)

        form.fields['owner'].choices = [(0, 'Unassigned')] + [
            (u.id, u.usersettings.vince_username) for u in assignable_users]
        form.fields['team'].choices = [(g.id, g.name) for g in Group.objects.filter(groupsettings__contact__isnull=False)]

        context['form'] = form
        return context


class EditCaseRequestView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = EditCaseRequestForm
    model = CaseRequest
    template_name = 'vince/edit_cr.html'
    login_url = "vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
            return has_queue_write_access(self.request.user, ticket.queue)
        return False

    def form_valid(self, form):
        ticket = form.save()
        return HttpResponseRedirect(ticket.get_absolute_url())

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        cr = get_object_or_404(CaseRequest, id=ticket.id)
        form = EditCaseRequestForm(request.POST, instance=cr)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get(self, request, *args, **kwargs):
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        cr = CaseRequest.objects.filter(id=ticket.id).first()
        if cr:
            return super().get(request, *args, **kwargs)
        else:
            return redirect("vince:newcr", ticket.id)

    def get_context_data(self, **kwargs):
        context = super(EditCaseRequestView, self).get_context_data(**kwargs)
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        cr = get_object_or_404(CaseRequest, id=ticket.id)
        form = EditCaseRequestForm(instance=cr)
        context['form'] = form
        context['ticket_id'] = ticket.id
        context['ticket'] = ticket
        return context


class AssignTicketNewTeam(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = AssignTicketTeamForm
    template_name = 'vince/assignteam.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
            if ticket.case:
                return has_case_write_access(self.request.user, ticket.case)
            return has_queue_write_access(self.request.user, ticket.queue)
        return False

    def get_context_data(self, **kwargs):
        context = super(AssignTicketNewTeam, self).get_context_data(**kwargs)
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        initial = {}
        initial['team'] = self.request.user.groups.exclude(groupsettings__contact__isnull=True).first()
        initial['team'] = initial['team'].id
        form = AssignTicketTeamForm(initial=initial)
        form.fields['team'].choices = [(g.id, g.name) for g in Group.objects.exclude(groupsettings__contact__isnull=True)]

        context['form'] = form
        context['ticket'] = ticket
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        if not has_queue_write_access(self.request.user, ticket.queue):
            raise PermissionDenied()
        form = AssignTicketTeamForm(request.POST)
        form.fields['team'].choices = [(g.id, g.name) for g in Group.objects.exclude(groupsettings__contact__isnull=True)]
        tqa = False
        error = None
        if form.is_valid():
            new_group = Group.objects.filter(id=form.cleaned_data['team']).first()
            #get queues associated with this group
            if ticket.case:
                # does the new group have access to this case?
                if CasePermissions.objects.filter(case=ticket.case, group=new_group, group_read=True, group_write=True).exists():
                    logger.debug("new_group has access to case")
                    # this case can be read/write by the group - so change it to appropriate case queue
                    new_queue = QueuePermissions.objects.filter(queue__queue_type=2, group__in=[new_group], group_read=True, group_write=True).first()
                    if new_queue:
                        ticket.queue = new_queue.queue
                        tqa = True
                        ticket.save()
                    # if there is a user assigned to this case from the new_group - assign them
                    u_in_g = User.objects.filter(groups__in=[new_group])
                    if u_in_g:
                        assignments = CaseAssignment.objects.filter(case=ticket.case, assigned__in=u_in_g).first()
                        if assignments:
                            ticket.assigned_to = assignments.assigned
                            ticket.save()
                        else:
                            ticket.assigned_to = None
                            ticket.save()
                    else:
                        ticket.assigned_to = None
                        ticket.save()
            #this group doesn't have access to the case or this doesn't belong to a case
            # put this in General queue
            if not tqa:
                new_queue = QueuePermissions.objects.filter(queue__queue_type=1, group__in=[new_group], group_read=True, group_write=True).first()
                if new_queue:
                    ticket.queue = new_queue.queue
                    ticket.assigned_to = None
                    ticket.save()
                    tqa = True
                else:
                    error = f"Error reassigning to new team: No General Queue available for {new_group}"
                
            if tqa:
                #make sure it's changed to open
                ticket.status = Ticket.OPEN_STATUS
                ticket.save()
                
                fup = FollowUp(ticket=ticket,
                               user=self.request.user,
                               title=f"Ticket re-assigned to team {new_group.name}",
                               date=timezone.now())
                fup.save()

                if form.cleaned_data['reason']:
                    fup = FollowUp(ticket=ticket,
                                   user=self.request.user,
                                   title=f"Transfer reason",
                                   date=timezone.now(),
                                   comment=form.cleaned_data['reason'])
                    fup.save()

                #is this a CR?
                cr = CaseRequest.objects.filter(ticket_ptr_id=ticket.id).first()
                if cr:
                    # need to change permissions if VTCR
                    if cr.vc_id:
                        vtcr = VTCaseRequest.objects.filter(id=cr.vc_id).first()
                        if vtcr:
                            #get new team group in VINCEComm
                            group = Group.objects.using('vincecomm').filter(name=new_group.groupsettings.contact.uuid).first()
                            if group:
                                vtcr.coordinator = group
                                vtcr.save()

                messages.success(
                    self.request,
                    _(f"Ticket has been reassigned to {new_group.name}"))
                return redirect("vince:dashboard")
        logger.debug(form.errors)
        if error:
            messages.error(
                self.request,
                _(f"{error}"))
        else:
            messages.error(
                self.request,
                _(f"Error reassigning to new team"))

        return HttpResponseRedirect(ticket.get_absolute_url())

class EditTicketResolutionView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = EditTicketResolutionForm
    template_name = 'vince/edit_ticket_resolution.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
            if ticket.case:
                return has_case_write_access(self.request.user, ticket.case)
            return has_queue_write_access(self.request.user, ticket.queue)
        return False

    def form_valid(self, form):
        logger.debug("IN TICKET VALID")
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        ticket.resolution = form.cleaned_data['resolution']
        ticket.save()
        return HttpResponseRedirect(ticket.get_absolute_url())

    def get_context_data(self, **kwargs):
        context = super(EditTicketResolutionView, self).get_context_data(**kwargs)
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        context['ticket'] = ticket
        initial = {}
        initial['resolution'] = ticket.resolution
        form = EditTicketResolutionForm(initial=initial)
        context['form'] = form
        return context
        
    
class EditTicketView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = EditTicketForm
    model = Ticket
    template_name = 'vince/edit_ticket.html'
    login_url = "vince:login"
    ContactFormSet = inlineformset_factory(Ticket, TicketContact, form=TicketContactForm, max_num=10, min_num=1, can_delete=True, extra=0)

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
            if ticket.case:
                return has_case_write_access(self.request.user, ticket.case)
            return has_queue_write_access(self.request.user, ticket.queue)
        return False

    def form_valid(self, form):
        logger.debug("IN TICKET VALID")
        ticket = form.save()
        #if form.cleaned_data['case']:
        #    queue = get_case_case_queue(form.cleaned_data['case'])
        #    logger.debug(f"queue is {queue}")
        #    logger.debug(f"ticket.queue is {ticket.queue}")
        #    if ticket.queue != queue:
        #        ticket.queue = queue
        #        ticket.save()

        contacts = TicketContact.objects.filter(ticket=self.kwargs['ticket_id'])
        contactformset = self.ContactFormSet(self.request.POST, prefix='contact', queryset=contacts, instance=ticket)

        if contactformset.is_valid():
            try:
                contactformset.save()
            except:
                logger.debug("this was probably unchanged, I don't know why this fails")
                pass

        return HttpResponseRedirect(ticket.get_absolute_url())

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        form = EditTicketForm(request.POST, instance=ticket)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return render(request, 'vince/edit_ticket.html', {'ticket':ticket, 'form':form, 'ticketpage':1, 'ticket_id': ticket.id})
        #return super().form_invalid(form)

    def get(self, request, *args, **kwargs):
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(EditTicketView, self).get_context_data(**kwargs)
        context['ticketpage']=1
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        initial = {}
        if ticket.case:
            initial['case'] = ticket.case.vu_vuid
        form = EditTicketForm(instance=ticket, initial=initial)
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        writable_queues = TicketQueue.objects.filter(queuepermissions__group__in=user_groups, queuepermissions__group_write=True).distinct()
        if ticket.case:
            queue = get_case_case_queue(ticket.case)
            form.fields['queue'].choices = [(queue.id, queue.title)]
        else:
            form.fields['queue'].choices = [('', '--------')] + [
                (q.id, q.title) for q in writable_queues]
        contacts = TicketContact.objects.filter(ticket=ticket)
        print(contacts)
        context['contactform'] = self.ContactFormSet(prefix='contact', queryset=contacts, instance=ticket)
        context['ticket'] = ticket
        context['form'] = form
        context['ticket_id'] = ticket.id
        return context



class CreateTicketView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = TicketForm
    template_name='vince/newticket.html'
    login_url="vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            if self.kwargs.get('pk'):
                if self.request.user.groups.filter(id=self.kwargs.get('pk')).exists():
                    return True
                return False
            else:
                return True
        return False

    def form_valid(self, form):
        queue = TicketQueue.objects.get(id=form.cleaned_data['queue'])
        if (form.cleaned_data['assigned_to'] == "-2"):
            role = form.cleaned_data['role']
            if role:
                role = UserRole.objects.filter(id=int(role)).first()

            if role == None:
                form._errors.setdefault("role", ErrorList([
                    u'Role does not exist']))
                return self.form_invalid(form)

            if form.cleaned_data['vulnote_approval']:
                # this can't be assigned to the person requesting it
                assignment = auto_assignment(role.id, exclude=self.request.user)
            else:
                assignment = auto_assignment(role.id)

            if assignment:
                if (assignment.id == self.request.user.id) and form.cleaned_data['vulnote_approval']:

                    assignment = auto_assignment(role.id)


                form.cleaned_data['assigned_to'] = assignment.id
            else:
                form._errors.setdefault("assigned_to", ErrorList([
                    u'There are no users available for this role']))
                return super().form_invalid(form)

        elif form.cleaned_data['assigned_to']:
            #make sure this user has access to this queue
            u = User.objects.get(id=form.cleaned_data['assigned_to'])
            if not has_queue_write_access(u, queue):
                form._errors.setdefault("assigned_to", ErrorList([
                    u'User does not have access to ticket queue.']))
                return self.form_invalid(form)
            
        ticket = form.save(user=self.request.user)
        queue = TicketQueue.objects.get(id=form.cleaned_data['queue'])
        if queue.queue_type == CASE_REQUEST_QUEUE:
            return redirect("vince:newcr", ticket.id)

        return HttpResponseRedirect(ticket.get_absolute_url())

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)


    def get(self, request, *args, **kwargs):
        if check_misconfiguration(self.request.user):
            return redirect("vince:misconfigured")
        return super().get(request, *args, **kwargs)
    
    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if len(user_groups) > 1:
            if self.kwargs.get('pk'):
                user_groups = self.request.user.groups.filter(id=self.kwargs.get('pk'))
            else:
                user_groups=[user_groups[0]]
        assignable_users = User.objects.filter(is_active=True, groups__in=user_groups).order_by(User.USERNAME_FIELD)
        readable_queues = TicketQueue.objects.filter(queuepermissions__group__in=user_groups, queuepermissions__group_write=True).distinct()
        form_class = self.get_form_class()
        form = TicketForm(request.POST, request.FILES, request=request)
        logger.debug(f"{self.__class__.__name__} request.files: {self.request.FILES}")
        case = None
        if 'case_id' in self.kwargs:
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
            queue = get_case_case_queue(case)
            #form.fields['case'].choices = [(case.id, case.get_title())]
            form.fields['queue'].choices = [(queue.id, queue.title)]
        else:
            form.fields['queue'].choices = [('', '--------')] + [
                (q.id, q.title) for q in readable_queues]
            #form.fields['case'].choices = [('', '-------')] + [
            #    (case.id, case.get_title()) for case in
            #    VulnerabilityCase.objects.filter(status=1)]
        form.fields['assigned_to'].choices = [('-2', 'Auto Assign'),('', '--------')] + [(u.id, u.get_full_name()) for u in assignable_users]
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        roles = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True))
        form.fields['role'].choices = [(u.id, u.role) for u in roles]

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)


    def get_context_data(self, **kwargs):
        context = super(CreateTicketView, self).get_context_data(**kwargs)
        context['ticketpage']=1
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if len(user_groups) > 1:
            if self.kwargs.get('pk'):
                context['team'] = self.request.user.groups.get(id=self.kwargs.get('pk')).name
                context['other_teams'] = user_groups.exclude(id=self.kwargs.get('pk'))
                user_groups = self.request.user.groups.filter(id=self.kwargs.get('pk'))
            else:
                #this user is in multiple teams
                context['team'] = user_groups[0].name
                context['other_teams'] = user_groups.exclude(id=user_groups[0].id)
                user_groups=[user_groups[0]]
            logger.debug(user_groups)
        assignable_users = User.objects.filter(is_active=True, groups__in=user_groups).order_by(User.USERNAME_FIELD).distinct()
        logger.debug(assignable_users)
        readable_queues = TicketQueue.objects.filter(queuepermissions__group__in=user_groups, queuepermissions__group_write=True).distinct()

        if self.request.POST:
            # don't overwrite form with errors
            if (self.request.POST.get('assigned_to') == "-2"):
                context['show_role'] = True
            return context

        initial_data = {}
        initial_data['submitter_email'] = self.request.user.email

        if 'queue' in self.request.GET:
            initial_data['queue'] = self.request.GET['queue']

        case = None
        if 'case_id' in self.kwargs:
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
            if 'approval' in self.request.GET:
                initial_data['title'] = f"Approve Case {case.vu_vuid} vulnerability note for publishing"
                link_to_review = reverse("vince:vulnotereviewal", args=[case.vulnote.id])
                initial_data['body'] = f"Please proofread vul note for publishing ASAP.\r\n\r\n{settings.SERVER_NAME}{link_to_review}"
                initial_data['priority'] = 2
                initial_data['due_date'] = datetime.now() + timedelta(days=3)
                initial_data['vulnote_approval'] = 1
                initial_data['submitter_email'] = self.request.user.email
                assignable_users = assignable_users.exclude(id=self.request.user.id)

        if case:
            context['case'] = case
            initial_data['case'] = case.vu_vuid

        form = TicketForm(initial=initial_data)

        if case:
            queue = get_case_case_queue(case)
            form.fields['queue'].choices = [(queue.id, queue.title)]
        else:
            form.fields['queue'].choices = [('', '--------')] + [
                (q.id, q.title) for q in readable_queues]

        roles = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True))
        form.fields['role'].choices = [(u.id, u.role) for u in roles]
        if roles:
            form.fields['assigned_to'].choices = [('-2', 'Auto Assign'),('', '--------')] + [
            (u.id, u.get_full_name()) for u in assignable_users]

            context['show_role'] = True
            # set role to vul note reviewer
            if initial_data.get('vulnote_approval'):
                for r in roles:
                    if r.role == "Vul Note Reviewer":
                        form.fields['role'].initial = r.id
                        break
            else:
                for r in roles:
                    if r.role == "Coordinator" or r.role == "General":
                        form.fields['role'].initial = r.id
                        break
            
            if not(form.fields['role'].initial):
                form.fields['role'].initial = roles[0].id
                
            form.fields['assigned_to'].initial = -2
            form.fields['role'].required=True
            

        else:
            form.fields['assigned_to'].choices = [('', '--------')] + [
            (u.id, u.get_full_name()) for u in assignable_users]

        context['form'] = form
        return context


class CreateNewCaseRequestView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    form_class = CreateCaseRequestForm
    login_url = "vince:login"
    template_name = "vince/create_case.html"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CreateNewCaseRequestView, self).get_context_data(**kwargs)

        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if len(user_groups) > 1:
            if self.kwargs.get('pk'):
                context['team'] = self.request.user.groups.get(id=self.kwargs.get('pk')).name
                context['other_teams'] = user_groups.exclude(id=self.kwargs.get('pk'))
                user_groups = self.request.user.groups.filter(id=self.kwargs.get('pk'))
            else:
                #this user is in multiple teams          
                context['team'] = user_groups[0].name
                context['other_teams'] = user_groups.exclude(id=user_groups[0].id)
                user_groups=[user_groups[0]]

        queue = TicketQueue.objects.filter(queuepermissions__group__in=user_groups, queuepermissions__group_write=True, queue_type=2).first()

        if queue == None:
            context['misconfiguration'] = 1
            return context
        
        form = None
        logger.debug(queue)

        if self.request.POST:
            form = CreateCaseRequestForm(self.request.POST)
        else:

            if self.request.GET.get('case'):
                #user wants to create case
                initial = {}
                initial['queue'] = queue.id
                initial['create_case'] = 1
                context['create_case'] = 1
                form = CreateCaseRequestForm(initial=initial)

            if "ticket_id" in self.kwargs:
                ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
                description = ticket.description
                cr = CaseRequest(product_name=description)
                if ticket.case:
                    cr['product_name'] = ticket.case.product_name
                    cr['product_version'] = ticket.case.product_version
                cr['ticket_ref'] = ticket.id
                cr['submission_type'] = "manual"
                cr['queue'] = queue.id
                form = CreateCaseRequestForm(initial=cr)
            elif "case_id" in self.kwargs:
                case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])

                ticket = Ticket(title = f"Case Request for {case.vu_vuid}",
                                created = timezone.now(),
                                status = Ticket.CLOSED_STATUS,
                                submitter_email = self.request.user.email,
                                assigned_to = self.request.user,
                                queue = get_user_cr_queue(self.request.user),
                                description = f"Details for Case {case.vu_vuid}",
                                case = case)
                ticket.save()
                cr = {}
                cr['product_name'] = ticket.case.product_name
                cr['product_version'] = ticket.case.product_version
                cr['ticket_ref'] = ticket.id
                cr['submission_type'] = "manual"
                cr['queue'] = queue.id
                form = CreateCaseRequestForm(initial=cr)

        if form:
            context['form'] = form
        else:
            initial = {}
            initial['queue'] = queue.id
            initial['create_case'] = 1
            context['create_case'] = 1
            context['form'] = CreateCaseRequestForm(initial=initial)
            
        return context


    def form_valid(self, form):
        caserequest = form.save(user=self.request.user)

        if caserequest.case:
            return HttpResponseRedirect(caserequest.case.get_absolute_url())

        elif form.cleaned_data['create_case']:
            return redirect("vince:newcase", caserequest.id)

        return HttpResponseRedirect(caserequest.get_absolute_url())


    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        form = CreateCaseRequestForm(self.request.POST)
        # just filling in fake values to pass validation
        form.fields['title'].value = "test"
        form.fields['status'].value = 1
        if form.is_valid():
            return self.form_valid(form)
        else:
            logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
            return super().form_invalid(form)

def generate_vuid():
    while (1):
        vuid = randint(100000, 999999)
        #check if already used
        case = VulnerabilityCase.objects.filter(vuid=vuid).first()
        if case == None:
            return vuid


class MuteCaseView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/mutecase.html'
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def post(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        user = self.request.user
        unmute = False
        settings = user.usersettings.settings
        logger.debug(user.usersettings.settings)
        if user.usersettings.settings.get('muted_cases'):
            muted_cases = user.usersettings.settings['muted_cases']
            logger.debug(muted_cases)
            if case.id in muted_cases:
                #this case has already been muted, unmute this case:
                muted_cases.remove(case.id)
                logger.debug(muted_cases)
                settings.update({'muted_cases': muted_cases})
                user.usersettings.settings = settings
                user.usersettings.save()
                logger.debug(user.usersettings.settings)
                unmute = True
            else:
                muted_cases.append(case.id)
                settings.update({'muted_cases': muted_cases})
                user.usersettings.settings = settings
                user.usersettings.save()
        else:
            # this user hasn't muted any cases yet
            settings.update({'muted_cases': [case.id]})
            user.usersettings.settings = settings
            user.usersettings.save()
            logger.debug(user.usersettings.settings)

        if unmute:
            button = "<i class=\"fas fa-volume-mute\"></i> Mute Reminders"
        else:
            button = "<i class=\"fas fa-volume-up\"></i> Unmute Reminders"
            #remove reminders for this user
            reminders = VinceReminder.objects.filter(case=case, user=user)
            for x in reminders:
                x.delete()

        return JsonResponse({'response': 'success', 'button': button}, status=200)

class CreateNewCaseView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = CreateCaseForm
    template_name = "vince/newcase.html"
    login_url="vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)


    def get_form_kwargs(self):
        kwargs = super(CreateNewCaseView, self).get_form_kwargs()
        kwargs.update({
            "user": self.request.user,
        })
        return kwargs
    
    def get_context_data(self, **kwargs):
        context = super(CreateNewCaseView, self).get_context_data(**kwargs)
        ticket = None
        if self.request.POST:
            if (self.request.POST.get('auto_assign') == "True"):
                context['show_role'] = True
            pass
        else:
            cr = {}
            has_cr = False
            if "ticket_id" in self.kwargs:
                ticket = CaseRequest.objects.filter(id=self.kwargs['ticket_id']).first()
                if ticket:
                    #if ticket:
                    cr['summary'] = (ticket.vul_description[:995] + '..') if len(ticket.vul_description) > 995 else ticket.vul_description
                    cr['vuid'] = generate_vuid()
                    cr['product_name'] = ticket.product_name
                    cr['product_version'] = ticket.product_version
                    cr['title'] = ticket.product_name
                    has_cr = True
                else:
                    ticket = Ticket.objects.filter(id=self.kwargs['ticket_id']).first()
                    if ticket:
                        cr['summary'] = (ticket.description[:995] + '..') if len(ticket.description) > 995 else ticket.description
                        cr['vuid'] = generate_vuid()
                        cr['title'] = ticket.title
                    else:
                        cr['vuid'] = generate_vuid()
            else:
                cr['vuid'] = generate_vuid()


            user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            if ticket:
                #get team from Ticket
                queue = ticket.queue
                if queue.team:
                    if self.request.user.groups.filter(id=queue.team.id).exists():
                        #if this user is a member of this team, use this group to determine roles
                        user_groups=[queue.team]
                
            # if this user has a default template, set it in initial values
            if self.request.user.usersettings.case_template:
                cr['template'] = self.request.user.usersettings.case_template.id
            form_class = self.get_form_class()
            form = self.get_form(form_class)
            form.initial = cr
            #form = CreateCaseForm(initial=cr)
            # get templates for users in my group
            ugroups = User.objects.filter(groups__in=user_groups)
            form.fields['template'].choices = [('', '---------')] + [
                (q.id, q.title) for q in CaseTemplate.objects.filter(user__in=ugroups)]

            roles = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True))
            form.fields['role'].choices = [(q.id, q.role) for q in roles]
            if roles:
                context['show_role'] = True
                form.fields['role'].initial = roles[0].id

            context['form'] = form
        context['casepage']=1
        return context


    def form_valid(self, form):

        assignment = self.request.user
        if (form.cleaned_data['auto_assign'] == "True"):
            role = form.cleaned_data['role']
            if role:
                role = UserRole.objects.filter(id=int(role)).first()

            if role == None:
                form._errors.setdefault("role", ErrorList([
                    u'Role does not exist']))
                return self.form_invalid(form)

            assignment = auto_assignment(role.id)
            if assignment == None:
                form._errors.setdefault("auto_assign", ErrorList([
                    u'There are no users available for this role']))
                return super().form_invalid(form)

        if self.request.POST.get('vuid'):
            old_case = VulnerabilityCase.objects.filter(vuid = self.request.POST['vuid']).first()
            if old_case:
                form._errors.setdefault("vuid", ErrorList([
                    u'Case ID Collision Error']))
                return super().form_invalid(form)
        saved = False
        if "ticket_id" in self.kwargs:
            cr = CaseRequest.objects.filter(id=self.kwargs['ticket_id']).first()
            if cr:
                case = form.save(case=cr, user=assignment)
                saved = True
            else:
                ticket = get_object_or_404(Ticket, id=self.kwargs["ticket_id"])
                case = form.save(user=assignment, ticket=ticket)
                saved=True
                
        if not saved:
            case = form.save(user=assignment)

        if "ticket_id" in self.kwargs:
            # this was just a general ticket, and not a CR. So add it to
            # the case and close it.
            ticket = get_object_or_404(Ticket, id=self.kwargs["ticket_id"])
            ticket.case = case
            ticket.status = Ticket.CLOSED_STATUS
            ticket.close_reason = 1
            #make sure we're adding this to the right queue
            if ticket.queue.team:
                if self.request.user.groups.filter(id=ticket.queue.team.id).exists():
                    #get case queue for this team
                    ticket.queue = TicketQueue.objects.filter(queue_type=3, team=ticket.queue.team).first()
                    # if it returns none, then try the default
                    if ticket.queue == None:
                        ticket.queue = get_user_case_queue(self.request.user)
                else:
                    ticket.queue = get_user_case_queue(self.request.user)
            else:
                ticket.queue = get_user_case_queue(self.request.user)

            ticket.save()

        return HttpResponseRedirect(case.get_absolute_url())

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        form_class = self.get_form_class()
        form = self.get_form(form_class)
        form.fields['template'].choices = [('', '---------')] + [
            (q.id, q.title) for q in CaseTemplate.objects.all()]
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        roles = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True))
        form.fields['role'].choices = [(q.id, q.role) for q in roles]
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

class ShareVulNote(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/share_vulnote.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vulnote.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(ShareVulNote, self).get_context_data(**kwargs)
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        context['vulnote'] = vulnote
        vc_case = Case.objects.filter(vince_id=vulnote.case.id).first()
        link_to_vulnote = reverse('vinny:vulnote', args=[vc_case.id])
        if not vulnote.date_shared:
            if vulnote.case.due_date:
                initial = {'content': f"Please [view this draft vulnerability note]({settings.KB_SERVER_NAME}{link_to_vulnote}) that we expect to publish on {vulnote.case.due_date.strftime('%Y-%m-%d')}."}
            else:
                initial = {'content': f"Please [view this draft vulnerability note]({settings.KB_SERVER_NAME}{link_to_vulnote})."}
            context['form'] = ShareVulNoteForm(initial=initial)
        else:
            initial = {'content': f"The [draft vulnerability note]({settings.KB_SERVER_NAME}{link_to_vulnote}) has been updated."}
            context['form'] = ShareVulNoteForm(initial=initial)
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        vc_vulnote = share_vulnote(vulnote)
        ca = CaseAction(case=vulnote.case, title="Shared Vulnerability Note in VinceComm",
                        user=self.request.user, vulnote=vulnote.current_revision,
                        action_type=1)
        ca.save()
        vc_case = Case.objects.filter(vince_id=vulnote.case.id).first()
        vc_case.note = vc_vulnote
        vc_case.save()
        if not vulnote.date_shared:
            vulnote.date_shared = timezone.now()
            vulnote.save()
        if self.request.POST['content'] != "":
            notification = VendorNotificationContent(content = self.request.POST['content'],
                                                     case=vulnote.case,
                                                     user = self.request.user,
                                                     published=True,
                                                     published_date=timezone.now())
            notification.save()
            update_vinny_post(vulnote.case, notification)

        vulnote.revision_shared = vulnote.current_revision.revision_number
        vulnote.save()
        vulnote.current_revision.date_shared = vulnote.date_shared
        vulnote.current_revision.save()

        return HttpResponseRedirect(reverse('vince:case', args=[vulnote.case.id]) + '#vulnote')

class PublishVulNote(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/publish_vulnote.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            case = vulnote.case
            return has_case_publish_access(self.request.user, case)
        return False

    def get_context_data(self, **kwargs):
        context = super(PublishVulNote, self).get_context_data(**kwargs)
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        context['vulnote'] = vulnote
        context['files'] = VinceFile.objects.filter(case=vulnote.case, vulnote=True, to_remove=False)
        context['files_to_remove'] = VinceFile.objects.filter(case=vulnote.case, vulnote=True, to_remove=True)
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])

        content = vulnote.current_revision.content
        #copy any images
        staticfiles = VinceFile.objects.filter(case=vulnote.case, vulnote=True)
        remove_files = []
        replace_files = []
        unchanged_files = []
        copy_files = []
        for file in staticfiles:
            vt_file = VinceTrackAttachment.objects.filter(id=file.comm_id).first()
            if vt_file == None:
                continue
            if file.to_remove:
                #this file needs to be removed from the vulnote
                logger.debug(f"removing file {str(vt_file.file.uuid)} {vt_file.file.filename}")
                remove_files.append(vulnote.case.vuid + "_" + vt_file.file.filename)
                vt_file.file.file.delete(save=False)
                vt_file.file.delete()
                file.delete()
            if vt_file.shared:
                # already copied
                unchanged_files.append(vulnote.case.vuid+"_"+vt_file.file.filename)
                continue

            image_link = reverse("vinny:attachment", args=["track", vt_file.file.uuid])
            #get file from bucket by uuid
            copy_source = {'Bucket': settings.VINCE_SHARED_BUCKET,
                           'Key': "vince_attachments/"+str(vt_file.file.file.name)
            }
            copy_files.append(vulnote.case.vuid+"_"+vt_file.file.filename)
            replace_files.append(image_link)
            logger.debug(f"copying file {str(vt_file.file.uuid)}")
            #adding ID to prevent file collisions
            try:
                if settings.AWS_DEPLOYED:
                    #copy file into kb shared bucket using filename: vuid_filename to prevent collisions
                    s3 = boto3.resource('s3', region_name=settings.AWS_REGION)
                    bucket = s3.Bucket(settings.KB_SHARED_BUCKET)
                    bucket.copy(copy_source, vulnote.case.vuid + "_" + vt_file.file.filename)
                    vt_file.shared = True
                    vt_file.save()
            except:
                logger.debug(traceback.format_exc())
                messages.error(
                    self.request,
                    _(f"Error copying file {vt_file.file.filename}. Publish failed."))
                return HttpResponseRedirect(reverse('vince:case', args=[vulnote.case.id]) + '#vulnote')

        if vulnote.date_published:
            vulnote.date_last_published = timezone.now()
        else:
            vulnote.date_last_published = timezone.now()
            vulnote.date_published = timezone.now()

        vulnote.save()

        # set publicdate if not already set (VIN-180)
        if not vulnote.case.publicdate:
            vulnote.case.publicdate = vulnote.date_published
            vulnote.case.save()

        copy_vulnote(vulnote, 'vincepub')

        vulnote.revision_published = vulnote.current_revision.revision_number
        vulnote.save()

        vulnote.current_revision.date_published = vulnote.date_published
        vulnote.current_revision.save()

        vu_info = {}
        vu_info['cert_id'] = vulnote.case.vu_vuid
        vu_info['name'] = vulnote.current_revision.title
        vu_info['idnumber'] = vulnote.case.vuid
        vu_info['vince'] = 1
        vu_info['copy_files'] = copy_files
        vu_info['remove_files'] = remove_files
        vu_info['replace_files'] = replace_files
        vu_info['unchanged_files'] = unchanged_files

        # reset changes_to_publish flag
        vulnote.case.changes_to_publish = False
        vulnote.case.save()

        try:
            publish_vul_note(vu_info, f"vu_{vulnote.case.vuid}.json")
        except:
            logger.debug(traceback.format_exc())
            send_error_sns(vulnote.case.vu_vuid, "Publishing vul note", traceback.format_exc())
            messages.error(
                self.request,
                _("Write error occurred while publishing your vulnerability note."))
            return HttpResponseRedirect(reverse('vince:case', args=[vulnote.case.id]) + '#vulnote')
        else:
            messages.success(
                self.request,
	        _("Congratulations! Your vul note has been published."))

        ca = CaseAction(case=vulnote.case, title="Published Vulnerability Note",
                        user=self.request.user, vulnote=vulnote.current_revision,
                        action_type=9)
        ca.save()

        #mark published in vincecomm - this will run through and copy the note and status
        update_vinny_case(vulnote.case)

        return HttpResponseRedirect(reverse('vince:case', args=[vulnote.case.id]) + '#vulnote')

def share_vulnote(vulnote):
    case = vulnote.case

    vpnote = VCVUReport.objects.filter(idnumber=vulnote.case.vuid).exclude(vulnote__isnull=True).first()
    if vpnote:
        #then do update
        vpnote.vulnote.content = vulnote.current_revision.content
        vpnote.vulnote.title = vulnote.current_revision.title
        vpnote.vulnote.references = vulnote.current_revision.references
        vpnote.vulnote.revision_number = vpnote.vulnote.revision_number + 1
        vpnote.vulnote.dateupdated = timezone.now()
        vpnote.vulnote.save()
        vpnote.overview = vulnote.current_revision.content
        vpnote.name = vulnote.current_revision.title
        vpnote.dateupdated = timezone.now()
        vpnote.save()

    else:
        note, created = VCVulnerabilityNote.objects.update_or_create(vuid = vulnote.case.vuid,
                                                                     defaults = {
                                                                         'content':vulnote.current_revision.content,
                                                                         'title': vulnote.current_revision.title,
                                                                         'references':vulnote.current_revision.references})
        # create a VUReport Record
        vpnote, created = VCVUReport.objects.update_or_create(idnumber = note.vuid,
                                                              vuid = f"{settings.CASE_IDENTIFIER}{note.vuid}",
                                                              defaults = {
                                                                  'name': note.title,
                                                                  'overview': note.content,
                                                                  'datefirstpublished':note.datefirstpublished,
                                                                  'vulnote': note})

    for vul in case.vulnerability_set.all():
        if vul.deleted:
            vp_vul = VCNoteVulnerability.objects.filter(case_increment=vul.case_increment, note=vpnote.vulnote).first()
            if vp_vul:
                vp_vul.delete()
            continue
        vp_vul = VCNoteVulnerability.objects.update_or_create(case_increment=vul.case_increment,
                                                              note=vpnote.vulnote,
                                                              defaults={'cve': vul.cve,
                                                                        'description': vul.description,
                                                                        'uid': vul.uid})
    for vtvendor in case.vulnerablevendor_set.all():
        if vtvendor.deleted:
            vp_vendor = VCVendor.objects.filter(note=vpnote.vulnote,
                                                uuid = vtvendor.contact.uuid).first()
            #vendor=vtvendor.contact.vendor_name).first()
            if vp_vendor:
                vp_vendor.delete()
            continue
        elif vtvendor.share and vtvendor.approved:
            vp_vendor, created = VCVendor.objects.update_or_create(
                note=vpnote.vulnote,
                uuid=vtvendor.contact.uuid,

                defaults={'contact_date':vtvendor.contact_date,
                          'references': vtvendor.references,
                          'statement': vtvendor.statement,
                          'statement_date': vtvendor.statement_date,
                          'vendor': vtvendor.contact.vendor_name,
                          'addendum':vtvendor.addendum})
        else:
            vp_vendor, created = VCVendor.objects.update_or_create(
                note=vpnote.vulnote,
                uuid=vtvendor.contact.uuid,
                defaults={'contact_date':vtvendor.contact_date,
                          'vendor':vtvendor.contact.vendor_name
                })
            # not approved so don't need to update
        for status in vtvendor.vendorstatus_set.all():
            if not status.vul.deleted and status.approved:
                vp_vul = VCNoteVulnerability.objects.filter(case_increment = status.vul.case_increment, note=vpnote.vulnote).first()
                if vp_vul:
                    if vtvendor.share:
                        vp_vulstatus = VCVendorVulStatus.objects.update_or_create(
                            vendor=vp_vendor,
                            vul = vp_vul,
                            defaults={'status':status.status,
                                      'references':status.references,
                                      'statement':status.statement})
                    else:
                        vp_vulstatus = VCVendorVulStatus.objects.update_or_create(
                            vendor=vp_vendor,
                            vul = vp_vul)

    # now make it public
    return vpnote


def copy_vulnote(vulnote, database):
    case = vulnote.case

    #is this vulnote in vincepub
    vpnote = VUReport.objects.using(database).filter(idnumber=vulnote.case.vuid).exclude(vulnote__isnull=True).first()
    if vpnote:
        #then do update

        vpnote.vulnote.content = vulnote.current_revision.content
        vpnote.vulnote.title = vulnote.current_revision.title
        vpnote.vulnote.references = vulnote.current_revision.references
        vpnote.vulnote.revision_number = vpnote.revision + 1
        vpnote.vulnote.dateupdated = vulnote.date_last_published
        vpnote.vulnote.publicdate = vulnote.case.publicdate
        vpnote.vulnote.save(using=database)
        vpnote.overview = vulnote.current_revision.content
        vpnote.name = vulnote.current_revision.title
        vpnote.dateupdated = vulnote.date_last_published
        if vulnote.current_revision.references:
            vpnote.public = vulnote.current_revision.references.splitlines()
        vpnote.cveids = case.get_cves()
        vpnote.revision = vpnote.vulnote.revision_number
        vpnote.publicdate = vulnote.case.publicdate
        vpnote.save(using=database)


        for vul in case.vulnerability_set.all():
            if vul.deleted:
                vp_vul = NoteVulnerability.objects.using(database).filter(case_increment=vul.case_increment, note=vpnote.vulnote).first()
                if vp_vul:
                    logger.debug("DELETE VULNERABILITY!!!")
                    vp_vul.delete()
                continue
            # only copy over vulnerabilities that have a CVE
            vp_vul = NoteVulnerability.objects.using(database).update_or_create(case_increment=vul.case_increment,
                                                                                note=vpnote.vulnote,
                                                                                defaults={'cve': vul.cve,
                                                                                          'description': vul.description,
                                                                                          'uid': vul.uid})
        for vtvendor in case.vulnerablevendor_set.all():
            updated = False
            if vtvendor.deleted:
                vp_vendor = Vendor.objects.using(database).filter(note=vpnote.vulnote,
                                                                  uuid=vtvendor.contact.uuid).first()
                if vp_vendor:
                    vp_vendor.delete(using=database)
                continue
            elif vtvendor.approved:
                vp_vendor = Vendor.objects.using(database).filter(note=vpnote.vulnote, uuid=vtvendor.contact.uuid).first()
                if vp_vendor:
                    # did this vendor change status/statement?
                    if ((vtvendor.references != vp_vendor.references)
                        or (vtvendor.statement != vp_vendor.statement) or
                        (vtvendor.statement_date != vp_vendor.statement_date) or
                        (vtvendor.addendum != vp_vendor.addendum)):
                        updated = True
                        logger.debug("VENDOR CHANGED STATEMENT")

                vp_vendor, created = Vendor.objects.using(database).update_or_create(
                    note=vpnote.vulnote,
                    uuid = vtvendor.contact.uuid,
                    defaults={'contact_date':vtvendor.contact_date,
                              'references': vtvendor.references,
                              'statement': vtvendor.statement,
                              'vendor': vtvendor.contact.vendor_name,
                              'statement_date': vtvendor.statement_date,
                              'addendum':vtvendor.addendum})
            else:
                vp_vendor, created = Vendor.objects.using(database).update_or_create(
                    note=vpnote.vulnote,
                    uuid = vtvendor.contact.uuid,
                    defaults={'contact_date':vtvendor.contact_date,
                              'vendor': vtvendor.contact.vendor_name
                    })
                # not approved so don't need to update
            for status in vtvendor.vendorstatus_set.all():
                if not status.vul.deleted and status.approved:
                    vp_vul = NoteVulnerability.objects.using(database).filter(case_increment=status.vul.case_increment,
                                                                              note=vpnote.vulnote).first()
                    if vp_vul:
                        if vtvendor.approved:
                            vp_vulstatus = VendorVulStatus.objects.using(database).filter(
                                vendor=vp_vendor,
                                vul=vp_vul).first()
                            if vp_vulstatus:
                                # did status or statement change?
                                if ((vp_vulstatus.status != status.status) or
                                    (vp_vulstatus.references != status.references) or
                                    (vp_vulstatus.statement != status.statement)):
                                    updated = True

                            vp_vulstatus = VendorVulStatus.objects.using(database).update_or_create(
                                vendor=vp_vendor,
                                vul = vp_vul,
                                defaults={'status':status.status,
                                          'references':status.references,
                                          'statement':status.statement})
                        else:
                            vp_vulstatus = VendorVulStatus.objects.using(database).update_or_create(vendor=vp_vendor,vul = vp_vul)
            if updated:
                # need to update the date for this vendor
                vp_vendor.dateupdated = timezone.now()
                vp_vendor.save(using=database)
                logger.debug("UPDATED VENDOR STATEMENT FOR NEW TIME %s" % vp_vendor.vendor)

    else:
        vpnote = VulnerabilityNote(content = vulnote.current_revision.content,
                                   title = vulnote.current_revision.title,
                                   references = vulnote.current_revision.references,
                                   vuid=vulnote.case.vuid)

        if vulnote.case.publicdate:
            vpnote.publicdate = vulnote.case.publicdate

        vpnote.save(using=database)

        #is this a pre-vince vulnote
        old_report = VUReport.objects.filter(idnumber=vpnote.vuid).first()

        # add vulnerabilities
        for vul in Vulnerability.casevuls(case):
            vp_vul = NoteVulnerability(cve=vul.cve,
                                       case_increment=vul.case_increment,
                                       description=vul.description,
                                       uid = vul.uid,
                                       note=vpnote)
            vp_vul.save(using=database)
        # add vendors
        for vul in VulnerableVendor.casevendors(case):
            vendor = Vendor(note = vpnote,
                            uuid = vul.contact.uuid,
                            vendor = vul.contact.vendor_name,
                            contact_date = vul.contact_date)
            if vul.approved:
                vendor.references = vul.references
                vendor.statement = vul.statement
                vendor.addendum = vul.addendum
                vendor.statement_date = vul.statement_date
            vendor.save(using=database)

            if old_report and vul.lotus_id:
                vr = VendorRecord.objects.using(database).filter(vendorrecordid=vul.lotus_id).first()
                if vr:
                    # assume this wasn't updated because it's difficult to tell since we changed
                    # fields on notes->vince migration
                    vendor.dateupdated = vr.datelastupdated
                    vendor.save(using=database)

            # get statuses for each vul in case for this vendor
            for status in vul.vendorstatus_set.all():
                vp_vul = NoteVulnerability.objects.filter(case_increment = status.vul.case_increment,
                                                          note=vpnote).first()
                if vp_vul:
                    vp_vulstatus = VendorVulStatus(vendor=vendor,
                                                   vul = vp_vul,
                                                   status = status.status)
                    if status.approved:
                        vp_vulstatus.references = status.references
                        vp_vulstatus.statement = status.statement
                    vp_vulstatus.save(using=database)
                else:
                    logger.debug("why is the NoteVulnerability not there?")
                # now make it public
        vpnote.published = True
        vpnote.save(using=database)
        # create a VUReport Record
        report, created = VUReport.objects.update_or_create(idnumber = vpnote.vuid,
                                                            vuid = f"{settings.CASE_IDENTIFIER}{vpnote.vuid}",
                                                            defaults={'name':vpnote.title,
                                                                      'overview':vpnote.content,
                                                                      'dateupdated':vulnote.date_last_published,
                                                                      'vulnote':vpnote,
                                                                      'public': vulnote.current_revision.references.splitlines(),
                                                                      'cveids': vulnote.case.get_cves(),
                                                                      'publicdate': vulnote.case.publicdate})
        if created:
            report.datefirstpublished=timezone.now()
            report.save()
        else:
            vpnote.revision_number = report.revision + 1
            vpnote.save(using=database)


        vpnote = report


    return vpnote


class VulNoteReviewView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name="vince/review.html"
    login_url="vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNoteRevision, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vulnote.vulnote.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(VulNoteReviewView, self).get_context_data(**kwargs)
        revision = get_object_or_404(VulNoteRevision, id=self.kwargs['pk'])
        context['vulnote'] = revision.vulnote
        context['case'] = revision.vulnote.case
        #get reviews for this revision:
        reviews = VulNoteReview.objects.filter(vulnote=revision, complete=True).order_by('-date_complete')
        context['review'] = reviews.first()
        if reviews.count() > 1:
            context['next'] = reviews[1]
            logger.debug(context['next'])
            context['reviews'] = reviews.exclude(id=context['review'].id)

        return context

class VulNoteReviewDetail(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name="vince/review.html"
    login_url="vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNoteReview, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vulnote.vulnote.vulnote.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(VulNoteReviewDetail, self).get_context_data(**kwargs)
        review = get_object_or_404(VulNoteReview, id=self.kwargs['pk'])
        context['vulnote'] = review.vulnote.vulnote
        context['case'] = review.vulnote.vulnote.case
        context['review'] = review
        #get reviews for this ticket:
        if review.ticket:
            logger.debug("HERE")
            context['reviews'] = VulNoteReview.objects.filter(ticket=review.ticket, complete=True, date_complete__lte=review.date_complete).exclude(id=review.id).order_by('-date_complete')
            logger.debug(context['reviews'])
            if context['reviews']:
                context['next'] = context['reviews'].first()
        return context



class ApplyVulNoteReview(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name="vince/confirm_apply.html"
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNoteReview, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vulnote.vulnote.vulnote.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(ApplyVulNoteReview, self).get_context_data(**kwargs)
        context['review'] = get_object_or_404(VulNoteReview, id=self.kwargs['pk'])
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        review = get_object_or_404(VulNoteReview, id=self.kwargs['pk'])
        rev = VulNoteRevision()
        rev.inherit_predecessor(review.vulnote.vulnote)
        rev.title = review.vulnote.title
        rev.content = review.review
        rev.user_message = f"Added review done by {review.reviewer.usersettings.vince_username}"
        rev.references = review.vulnote.references
        rev.deleted = False
        logger.debug(rev)
        rev.set_from_request(self.request)
        review.vulnote.vulnote.add_revision(rev)
        return HttpResponseRedirect(reverse('vince:case', args=[review.vulnote.vulnote.case.id]) + '#vulnote')

class VulNoteReviewal(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView, FormMixin):
    template_name="vince/vulnote_reviewal.html"
    login_url="vince:login"
    form_class = VulNoteReviewForm

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vulnote.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(VulNoteReviewal, self).get_context_data(**kwargs)
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        context['vulnote'] = vulnote
        context['case'] = vulnote.case
        if self.request.POST:
            return context

        #did this user already start a review of this revision?
        check = VulNoteReview.objects.filter(vulnote=vulnote.current_revision.id,
                                             reviewer=self.request.user,
                                             complete=False).first()
        if check:
            initial = {'content': check.review,
		       'current_revision': vulnote.current_revision.id,
                       'feedback': check.feedback}
            context['marks'] = json.loads(check.marks)

        else:
            initial = {'content': vulnote.current_revision.content,
		       'current_revision': vulnote.current_revision.id}

        context['form'] = VulNoteReviewForm(initial=initial)
        context['action'] = reverse("vince:vulnotereviewal", args=[vulnote.id])
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        form = VulNoteReviewForm(self.request.POST)
        logger.debug(form)
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        rev = VulNoteReview()
        if form.is_valid():
            logger.debug("FORM IS VALID")
            #is this an edit?
            check = VulNoteReview.objects.filter(vulnote=vulnote.current_revision.id,
                                                 reviewer=self.request.user,
                                                 complete=False).first()
            if check:
                rev = check

            rev.vulnote = VulNoteRevision.objects.get(id=form.cleaned_data['current_revision'])

            rev.review = form.cleaned_data['content']
            rev.reviewer = self.request.user
            rev.feedback = form.cleaned_data['feedback']
            rev.marks = self.request.POST.get('marks')
            rev.complete = form.cleaned_data['completed']
            rev.approve = form.cleaned_data['approved']

            if form.cleaned_data['completed']:
                rev.date_complete = timezone.now()

            rev.save()
            #is this user assigned a ticket to do review?
            tkt = Ticket.objects.filter(case=vulnote.case,
                                        assigned_to=self.request.user,
                                        title__icontains="vulnerability note for publishing").first()
            if tkt:
                logger.debug("WE HAVE A REVIEW TICKET")
                rev.ticket = tkt
                rev.save()
                if rev.complete:
                    if rev.approve:
                        tkt.status = Ticket.CLOSED_STATUS
                        tkt.save()
                        action = FollowUp(ticket=tkt,
                                          title = "Vul note review completed and approved for publication",
			                  date = timezone.now(),
                                          user=self.request.user)

                        action.save()
                        if tkt.submitter_email != self.request.user.email:
                            # don't let submitter circumvent process
                            vulnote.approved = True
                            vulnote.save()
                            #getuser
                            if tkt.submitter_email:
                                u = User.objects.filter(email=tkt.submitter_email).first()
                                if u:
                                    #add a reminder to publish vul note
                                    rem = VinceReminder(alert_date=timezone.now(),
                                                        title=f"Your vulnote has been approved for publication by {self.request.user.usersettings.preferred_username}",
                                                        case=vulnote.case,
                                                        user=u)
                                    rem.save()

                    else:
                        tkt.status = Ticket.CLOSED_STATUS
                        tkt.save()
                        if tkt.submitter_email:
                            action = FollowUp(ticket=tkt,
                                              title = "Vul Note review completed",
                                              comment="Review complete but not approved.",
                                              date = timezone.now(),
                                              user=self.request.user)

                            action.save()
                else:
                    tkt.status = Ticket.IN_PROGRESS_STATUS
                    tkt.save()
                    action = FollowUp(ticket=tkt,
                                      title = "Vul Note review started",
                                      date = timezone.now(),
                                      user=self.request.user)

                    action.save()

            return JsonResponse({'redirect':reverse('vince:case', args=[vulnote.case.id]) + '#vulnote'}, status=200)
        else:
            logger.debug("FORM IS INVALID")
            logger.debug(form.errors)
            return JsonResponse({'error':form.errors}, status=401)


class ApproveVulNote(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/approve_vulnote.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vulnote.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(ApproveVulNote, self).get_context_data(**kwargs)
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        context['vulnote'] = vulnote
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        if vulnote.ticket_to_approve:

            if (not self.request.user.is_superuser) and (vulnote.ticket_to_approve.submitter_email == self.request.user):
                messages.error(
                    self.request,
                    _("You are not permitted to approve this vul note."))
                return HttpResponseRedirect(reverse('vince:case', args=[vulnote.case.id]) + '#vulnote')

            vulnote.approved = True
            vulnote.save()

            #getuser
            u = User.objects.filter(email=vulnote.ticket_to_approve.submitter_email).first()
            if u:
                #add a reminder to publish vul note
                rem = VinceReminder(alert_date=timezone.now(),
                                    title=f"Your vulnote has been approved for publication by {self.request.user.usersettings.preferred_username}",
                                    case=vulnote.case,
                                    user=u)
                rem.save()

            request.POST = {
                'new_status': Ticket.RESOLVED_STATUS
            }
            kwargs['ticket_id']=vulnote.ticket_to_approve.id
            update_ticket(request, vulnote.ticket_to_approve.id)
        return HttpResponseRedirect(reverse('vince:case', args=[vulnote.case.id]) + '#vulnote')

class AskApprovalVulNote(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vince/vn.html"
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, ticket.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])

        ticket.status = Ticket.REOPENED_STATUS
        ticket.save()
        action = FollowUp(ticket=ticket,
                          title = "Request for approval",
                          date = timezone.now(),
                          user=self.request.user)

        action.save()

        return JsonResponse({'location': reverse('vince:ticket', args=[ticket.id])}, status=200)

def add_vendor(vul):
    v = {'uid': str(vul.contact.uuid), 'vendor': vul.contact.vendor_name, 'overall_status': vul.get_status()}

    if vul.contact_date:
        v['contact_date'] = vul.contact_date.strftime('%Y-%m-%d')
    else:
        v['contact_date'] = None
    
    if vul.date_modified:
        v['dateupdated']= vul.date_modified.strftime('%Y-%m-%d')
    else:
        v['dateupdated'] = None
        
    if vul.approved:
        v['references'] = vul.references
        v['statement'] = vul.statement
        v['addendum'] = vul.addendum
        if vul.statement_date:
            v['statement_date'] = vul.statement_date.strftime('%Y-%m-%d')
        else:
            v['statement_date'] = None

    v['status'] = []

    for status in vul.vendorstatus_set.all():
        s = {'vul': status.vul.vul, 'vul_increment':status.vul.case_increment, 'status': status.get_status_display()}
        if status.approved:
            s['references'] = status.references
            s['statement'] = status.statement
        v['status'].append(s)
    
    return v

    
class DownloadVulNote(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vulnote.case)

    def dispatch(self, request, *args, **kwargs):

        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        case = vulnote.case
        
        vu_info = {}
        vu_info['content'] = vulnote.current_revision.content
        vu_info['title'] = vulnote.current_revision.title
        vu_info['references'] = vulnote.current_revision.references
        vu_info['vuid'] = vulnote.case.vuid
        if vulnote.case.publicdate:
            vu_info['publicdate'] = vulnote.case.publicdate.strftime('%Y-%m-%d')
        else:
            vu_info['publicdate'] = None
        vu_info['vuls'] = []
        vu_info['deleted_vuls'] = []
        for vul in Vulnerability.casevuls(case):
            v = {'cve': vul.cve, 'case_increment': vul.case_increment, 'description': vul.description, 'uid': vul.uid}
            vu_info['vuls'].append(v)

        for vul in case.vulnerability_set.filter(deleted=True):
            vu_info['deleted_vuls'].append(vul.case_increment)
            
        vu_info['vendors'] = []
        vu_info['deleted_vendors'] = []
        vendors = []
        
        for vul in VulnerableVendor.casevendors(case).filter(vendorstatus__status=VendorStatus.AFFECTED_STATUS).distinct('vendor').order_by('vendor'):
            v = add_vendor(vul)
            if v['vendor'] not in vu_info['vendors']:
                vu_info['vendors'].append(v)

        for vul in VulnerableVendor.casevendors(case).filter(vendorstatus__status=VendorStatus.UNAFFECTED_STATUS).distinct('vendor').order_by('vendor'):
            v =	add_vendor(vul)
            if v['vendor'] not in vu_info['vendors']:
                vu_info['vendors'].append(v)
                
        for vul in VulnerableVendor.casevendors(case).filter(Q(vendorstatus__status=VendorStatus.UNKNOWN_STATUS)|Q(vendorstatus__isnull=True)).distinct('vendor').order_by('vendor'):
            v = add_vendor(vul)
            if v['vendor'] not in vu_info['vendors']:
                vu_info['vendors'].append(v)

        for vul in case.vulnerablevendor_set.filter(deleted=True):
            vu_info['deleted_vendors'].append(vul.contact.uuid)

        vu_info['cveids'] = vulnote.case.get_cves()
        if vulnote.date_last_published:
            vu_info['dateupdated'] = vulnote.date_last_published.strftime('%Y-%m-%d')
        else:
            vu_info['dateupdated'] = None
        vu_info['cert_id'] = vulnote.case.vu_vuid
        vu_info['name'] = vulnote.current_revision.title
        vu_info['idnumber'] = vulnote.case.vuid
        
        vu_json = json.dumps(vu_info, indent=4)

        json_file = ContentFile(vu_json)
        json_file.name = case.vu_vuid + ".json"
        mime_type = 'application/json'
        response = HttpResponse(json_file, content_type = mime_type)
        response['Content-Disposition'] = 'attachment; filename=' + json_file.name
        response["Content-type"] = "application/json"
        response["Cache-Control"] = "must-revalidate"
        response["Pragma"] = "must-revalidate"
        return response

class DownloadVulNoteHtml(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vulnote.case)

    def dispatch(self, request, *args, **kwargs):

        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        case = vulnote.case

        vu_html = markdown.markdown(vulnote.current_revision.content)

        html_file = ContentFile(vu_html)
        html_file.name = case.vu_vuid + ".html"
        mime_type = 'text/html'
        response = HttpResponse(html_file, content_type = mime_type)
        response['Content-Disposition'] = 'attachment; filename=' + html_file.name
        response["Content-type"] = "text/html"
        response["Cache-Control"] = "must-revalidate"
        response["Pragma"] = "must-revalidate"
        return response
    
    
class EditVulNote(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView, FormMixin):
    form_class = EditVulNote
    template_name = "vince/edit_vulnote.html"
    login_url = "vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vulnote.case)
        return False

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        rev = VulNoteRevision()
        rev.inherit_predecessor(vulnote)
        rev.title = form.cleaned_data['title']
        rev.content = form.cleaned_data['content']
        rev.user_message = form.cleaned_data['summary']
        rev.references = form.cleaned_data['references']
        rev.deleted = False
        logger.debug(rev)
        rev.set_from_request(self.request)
        vulnote.add_revision(rev)

        action = CaseAction(case = vulnote.case,
                            title = "Edited Vul Note",
                            date = timezone.now(),
                            user=self.request.user,
                            comment=form.cleaned_data['summary'],
                            action_type = 1)
        action.save()

        vulnote.case.changes_to_publish = True
        vulnote.case.save()

        artifacts = list(map(int, self.request.POST.getlist('artifacts[]')))
        logger.debug(artifacts)
        # record the artifacts that have been added to the vulnote
        arts =  get_all_artifacts(vulnote.case)

        for artifact in arts:
            if artifact.id in artifacts:
                artifact.added_to_note = True
            else:
                artifact.added_to_note = False
            artifact.save()

        formvuls = list(map(int, self.request.POST.getlist('vuls[]')))
        logger.debug(formvuls)
        vuls = Vulnerability.casevuls(vulnote.case)
        for vul in vuls:
            if vul.id in formvuls:
                vul.added_to_note = True
            else:
                vul.added_to_note = False
            vul.save()

        return HttpResponseRedirect(reverse('vince:case', args=[vulnote.case.id]) + '#vulnote')

    def get_form(self, form_class=None):
        """
        Checks from querystring data that the edit form is actually being saved,
        otherwise removes the 'data' and 'files' kwargs from form initialisation.
        """
        if form_class is None:
            form_class = self.get_form_class()
        kwargs = self.get_form_kwargs()
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        if self.request.POST.get(
                'save',
                '') != '1' and self.request.POST.get('preview') != '1':
            kwargs['data'] = None
            kwargs['files'] = None
            kwargs['no_clean'] = True
        return form_class(self.request, vulnote.current_revision, **kwargs)


    def get_context_data(self, **kwargs):
        vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
        kwargs['form'] = self.get_form()

        kwargs['case'] = vulnote.case
        kwargs['artifacts'] = get_all_artifacts(vulnote.case)
        kwargs['vuls'] = Vulnerability.casevuls(vulnote.case)

        kwargs['files'] = VinceFile.objects.filter(case=vulnote.case, vulnote=True)

        if vulnote.case.case_request:
            cr = CaseRequest.objects.filter(id=vulnote.case.case_request.id).first()
            if cr:
                if cr.share_release == False:
                    kwargs['warning'] = True
                if cr.credit_release == False:
                    kwargs['nocredit'] = True
        return super().get_context_data(**kwargs)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)


class CreateVulNote(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = CreateVulNote
    template_name = "vince/create.html"
    login_url = "vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
            return has_case_write_access(self.request.user, case)
        return False

    def form_valid(self, form):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
        # create initial vul note revision

        vulnote = VulNote(case = case,
                          owner=self.request.user)
        vulnote.save()
        vulnote.add_revision(VulNoteRevision(title=form.cleaned_data['title'],
                                             content=form.cleaned_data['content'],
                                             references=form.cleaned_data['references'],
                                             user_message = form.cleaned_data['summary'],
                                             user=self.request.user),
                             save=True)

        action = CaseAction(case = case,
                            title = "Created vul note",
                            date = timezone.now(),
                            user=self.request.user,
                            comment=self.request.POST['summary'],
                            action_type = 1)
        action.save()

        artifacts = list(map(int, self.request.POST.getlist('artifacts[]')))
        logger.debug(artifacts)
        # record the artifacts that have been added to the vulnote
        arts =  get_all_artifacts(vulnote.case)

        for artifact in arts:
            if artifact.id in artifacts:
                artifact.added_to_note = True
            else:
                artifact.added_to_note = False
            artifact.save()

        formvuls = list(map(int, self.request.POST.getlist('vuls[]')))
        logger.debug(formvuls)
        vuls = Vulnerability.casevuls(vulnote.case)
        for vul in vuls:
            if vul.id in formvuls:
                vul.added_to_note = True
            else:
                vul.added_to_note = False
            vul.save()

        return HttpResponseRedirect(reverse('vince:case', args=[case.id]) + '#vulnote')

    def get_form_kwargs(self):
        kwargs = super(CreateVulNote, self).get_form_kwargs()
        references = []
        refs = CVEAllocation.objects.filter(vul__case__id=self.kwargs['case_id']).values_list('references', flat=True)
        for vul in refs:
            if vul:
                temp = json.loads(vul)
                for r in temp:
                    if r["url"] not in references:
                        references.append(r["url"])
        
        kwargs.update({
            "case": get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id']),
            "references": references
        })
        return kwargs

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)


    def get_context_data(self, **kwargs):
        c = super(CreateVulNote, self).get_context_data(**kwargs)
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
        c['case'] = case
        c['form'] = self.get_form()
        c['artifacts'] = get_all_artifacts(case)
        c['vuls'] = Vulnerability.casevuls(case=case)
        c['files'] = VinceFile.objects.filter(case=case, vulnote=True)
        if case.case_request:
            cr = CaseRequest.objects.filter(id=case.case_request.id).first()
            if cr:
                if cr.share_release == False:
                    c['warning'] = True
        return c

class PostView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = VendorNotificationContent
    login_url = "vince:login"
    template_name = 'vince/post.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            post = get_object_or_404(VendorNotificationContent, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, post.case)
        else:
            return False


class CRVRFFullScreen(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = CaseRequest
    login_url = "vince:login"
    template_name = 'vince/vrf_full_screen.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
            if ticket.case:
                return has_case_read_access(self.request.user, ticket.case)
            return has_queue_read_access(self.request.user, ticket.queue)
        else:
            return False


class CaseRequestView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = CaseRequest
    login_url = "vince:login"
    template_name = 'vince/cr.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
            if ticket.case:
                return has_case_read_access(self.request.user, ticket.case)
            return has_queue_read_access(self.request.user, ticket.queue)
        else:
            return False

    def get(self, request, *args, **kwargs):
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])

        if 'autoassign' in request.GET:
            if not(has_queue_write_access(self.request.user, ticket.queue)):
                raise PermissionDenied()

            context = {}
            user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            roles = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True))
            form = AutoAssignForm()
            form.fields['role'].choices = [
                (q.id, q.role) for q in roles]
            context['form'] = form
            context['ticket'] = ticket
            return render(request, "vince/autoassign.html", context)

        if 'take' in request.GET:
            if not(has_queue_write_access(self.request.user, ticket.queue)):
                raise PermissionDenied()

            request.POST = {
                'owner': request.user.id,
                'title': ticket.title,
                'comment': ''
                }
            kwargs['ticket_id']=self.kwargs['pk']
            logger.debug("REDIRECT!!!")
            return update_ticket(request, self.kwargs['pk'])
        if 'assign' in request.GET:
            if not(has_queue_write_access(self.request.user, ticket.queue)):
                raise PermissionDenied()

            request.POST = {
                'owner': request.GET['assign'],
                'title': ticket.title,
                'comment': ''
                }
            logger.debug(request.GET['assign'])
            kwargs['ticket_id']=self.kwargs['pk']
            logger.debug("REDIRECT!!!")
            return update_ticket(request, self.kwargs['pk'])
        elif 'close' in request.GET and ticket.status == Ticket.RESOLVED_STATUS:
            if not(has_queue_write_access(self.request.user, ticket.queue)):
                raise PermissionDenied()

            if not ticket.assigned_to:
                owner = 0
            else:
                owner = ticket.assigned_to.id
	    # Trick the update_ticket() view into thinking it's being called with
            # a valid POST.
            request.POST = {
                'new_status': Ticket.CLOSED_STATUS,
                'public': 1,
                'owner': owner,
                'title': ticket.title,
                'comment': _('Accepted resolution and closed ticket'),
            }
            return update_ticket(request, self.kwargs['pk'])
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__} post!")
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        if not(has_queue_write_access(self.request.user, ticket.queue)):
            raise PermissionDenied()

        kwargs['ticket_id']=self.kwargs['pk']
        return update_ticket(request, self.kwargs['pk'])

    def get_context_data(self, **kwargs):
        context = super(CaseRequestView, self).get_context_data(**kwargs)
        context['ticket'] = get_object_or_404(CaseRequest, id=self.kwargs['pk'])
        user_groups = context['ticket'].queue.queuepermissions_set.filter(group_read=True, group_write=True).values_list('group', flat=True)
        if context['ticket'].assigned_to:
            context['assignable_users'] = User.objects.filter(is_active=True, groups__in=user_groups).order_by(User.USERNAME_FIELD).exclude(id=context['ticket'].assigned_to.id)
        else:
            context['assignable_users'] = User.objects.filter(is_active=True, groups__in=user_groups).order_by(User.USERNAME_FIELD)

        #context['subscribed_users'] = [ticketcc.user.usersettings.preferred_username for ticketcc in context['ticket'].ticketcc_set.all()]
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        context['auto_assign'] = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True)).count()
        context['old_tags'] = [tag.tag for tag in context['ticket'].tickettag_set.all()]
        context['other_tags'] = [tag.tag for tag in TagManager.objects.filter(tag_type=1).filter(Q(team__in=user_groups)|Q(team__isnull=True)).exclude(tag__in=context['old_tags']).order_by('tag').distinct('tag')]
        context['assignable'] = [user.usersettings.preferred_username for user in context['assignable_users']]

        artifacts = Artifact.objects.filter(ticketartifact__ticket=context['ticket'])
        context['artifacts'] = artifacts.order_by('-date_added')
        context['artifactsjs'] = [ obj.as_dict() for obj in context['artifacts'] ]
        context['form'] = AddArtifactForm()
        context['vrf_url'] = download_vrf(context['ticket'].vrf_id)
        # look up vrf in vincecomm:
        vc_cr = VTCaseRequest.objects.filter(vrf_id=context['ticket'].vrf_id).first()
        if vc_cr:
            context['vincecomm_link'] = reverse("vinny:cr_report", args=[vc_cr.id])
            context['vc_cr'] = vc_cr
            if vc_cr.user:
                context['vince_user_submission'] = vc_cr.user.vinceprofile.vince_username
        context['ticketpage'] = 1
        return context

class TicketActivityView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Ticket
    login_url="vince:login"
    template_name = 'vince/ticket_activity.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
            if ticket.case:
                return has_case_read_access(self.request.user, ticket.case)
            return has_queue_read_access(self.request.user, ticket.queue)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(TicketActivityView, self).get_context_data(**kwargs)
        context['ticketpage']=1
        context['ticket'] = get_object_or_404(Ticket, id=self.kwargs['pk'])
        return context

class TicketAutoAssign(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/autoassign.html"
    form_class = AutoAssignForm

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            return True
        return False

    def get_context_data(self, **kwargs):
        context = super(TicketAutoAssign, self).get_context_data(**kwargs)
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        roles = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True))
        form = AutoAssignForm()
        form.fields['role'].choices = [
            (q.id, q.role) for q in roles]
        context['form'] = form
        return context

class TicketView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model=Ticket
    login_url="vince:login"
    fields="__all__"
    template_name = 'vince/ticket.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
            if has_queue_read_access(self.request.user, ticket.queue):
                return True
            if ticket.case:
                return has_case_read_access(self.request.user, ticket.case)

        return False

    @staticmethod
    def get_subscribers(ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)
        users = [ticketcc.user.usersettings.preferred_username for ticketcc in ticket.ticketcc_set.all()]
        logger.debug("subscribed_users")
        logger.debug(ticket.ticketcc_set.all())
        allusers = [ user.usersettings.preferred_username for user in User.objects.filter(is_active=True, groups__name='vince').exclude(usersettings__preferred_username__isnull=True)]
        return JsonResponse({'subscribed_users': users, 'assignable_users':allusers}, status=200)

    @staticmethod
    def get_tags(ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)
        tags = [tag.tag for tag in ticket.tickettag_set.all()]
        all_tags = [tag.tag for tag in TicketTag.objects.order_by('tag').distinct('tag')]
        return JsonResponse({'old_tags': tags, 'other_tags':all_tags}, status=200)

    @staticmethod
    def get_all_users():
        #users = [{'label': f"{user.first_name} {user.last_name} {user.username}", 'internalValue': user.username } for user in User.objects.all()]
        #users = [{'name': f"{user.first_name} {user.last_name} ({user.username})", 'username': user.username } for user in User.objects.all()]
        users = [ user.username for user in User.objects.all()]

        all_users = { 'all_users': users}
        return JsonResponse(all_users, status=200)


    def get(self, request, *args, **kwargs):
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])

        cr = CaseRequest.objects.filter(ticket_ptr_id=ticket.id).first()

        if 'autoassign' in request.GET:
            if not(has_queue_write_access(self.request.user, ticket.queue)):
                raise PermissionDenied()
            context = {}
            user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            roles = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True))
            form = AutoAssignForm()
            form.fields['role'].choices = [
                (q.id, q.role) for q in roles]
            context['form'] = form
            context['ticket'] = ticket
            return render(request, "vince/autoassign.html", context)


        if 'take' in request.GET:
            if not(has_queue_write_access(self.request.user, ticket.queue)):
                raise PermissionDenied()
            logger.debug("UPDATE TICKET!")
            request.POST = {
                'owner': request.user.id,
                'title': ticket.title,
                'comment': ''
                }
            kwargs['ticket_id']=self.kwargs['pk']
            return update_ticket(request, self.kwargs['pk'])
        elif 'assign' in request.GET:
            if not(has_queue_write_access(self.request.user, ticket.queue)):
                raise PermissionDenied()

            logger.debug("ASSIGN TICKET!")
            if request.GET['assign']:
                request.POST = {
                    'owner': request.GET['assign'],
                    'title': ticket.title,
                    'comment': ''
                }
                kwargs['ticket_id']=self.kwargs['pk']
                return update_ticket(request, self.kwargs['pk'])
            #else this isn't really assigned to anyone
        elif 'close' in request.GET and ticket.status == Ticket.RESOLVED_STATUS:
            if not(has_queue_write_access(self.request.user, ticket.queue)):
                raise PermissionDenied()

            if not ticket.assigned_to:
                owner = 0
            else:
                owner = ticket.assigned_to.id
            # Trick the update_ticket() view into thinking it's being called with
            # a valid POST.
            request.POST = {
                'new_status': Ticket.CLOSED_STATUS,
                'public': 1,
                'owner': owner,
                'title': ticket.title,
                'comment': _('Accepted resolution and closed ticket'),
            }
            return update_ticket(request, self.kwargs['pk'])
        elif cr:
            # this is a cr and doesn't have args above
            return HttpResponseRedirect(reverse('vince:cr', args=[cr.id]))
        elif 'subscribed_users' in request.GET:
            return TicketView.get_subscribers(self.kwargs['pk'])
        elif 'all_users' in request.GET:
            return TicketView.get_all_users()

        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__} post!")
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        kwargs['ticket_id']=self.kwargs['pk']

        if not(has_queue_write_access(self.request.user, ticket.queue)):
            raise PermissionDenied()

        if self.request.POST.get('role'):
            #do auto assignment
            role = get_object_or_404(UserRole, id=self.request.POST.get('role'))
            assignment = auto_assignment(role.id)
            if assignment == None:
                return JsonResponse({'error':'There are no available users for this role.'}, status=401)
            #update the ticket
            request.POST = {
                'owner': assignment.id,
                'title': ticket.title,
                'comment': '',
                'auto': 1
            }
            kwargs['ticket_id']=self.kwargs['pk']
            update = update_ticket(request, self.kwargs['pk'])
            return JsonResponse({'assignment': assignment.usersettings.preferred_username}, status=200)

        test = update_ticket(request, self.kwargs['pk'])
        return JsonResponse({'message': 'success'}, status=200)


    def get_context_data(self, **kwargs):
        context = super(TicketView, self).get_context_data(**kwargs)
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        context['auto_assign'] = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True)).count()
        context['ticketpage']=1
        # set session var so after ticket activity, we can go back to where they came from
        self.request.session["vince_referer"] = self.request.META.get('HTTP_REFERER')
        
        context['ticket'] = get_object_or_404(Ticket, id=self.kwargs['pk'])
        #context['subscribed_users'] = [ticketcc.user.usersettings.preferred_username for ticketcc in context['ticket'].ticketcc_set.all()]
        user_groups = context['ticket'].queue.queuepermissions_set.filter(group_read=True, group_write=True).values_list('group', flat=True)
        if context['ticket'].assigned_to:
            context['assignable_users'] = User.objects.filter(is_active=True, groups__in=user_groups).order_by(User.USERNAME_FIELD).exclude(id=context['ticket'].assigned_to.id)
        else:
            context['assignable_users'] = User.objects.filter(is_active=True, groups__in=user_groups).order_by(User.USERNAME_FIELD)
        context['assignable'] = [user.usersettings.preferred_username for user in context['assignable_users']]
        if context['ticket'].submitter_email:
            # do we have a user for this submitter?
            vincomm_user = User.objects.using('vincecomm').filter(email=context['ticket'].submitter_email).first()
            if vincomm_user:
                context['vincecomm_user'] = vincomm_user


        if context['ticket'].title.startswith('Contact change'):
            if vincomm_user:
                groups = vincomm_user.groups.all()
                if groups:
                    for ug in groups:
                        try:
                            if ug.groupcontact:
                                contact = ug.groupcontact.contact
                                context['contact_link'] = contact.vendor_id
                        except:
                            continue
        # Are we subscribed to this ticket?
        if TicketCC.objects.filter(user_id=self.request.user.id):
            context['subscribed'] = True
        else:
            context['subscribed'] = False

        #context['ticketcc_list'] = [ ticketcc.user.username for ticketcc in context['ticket'].ticketcc_set.all() ]
        context['old_tags'] = [tag.tag for tag in context['ticket'].tickettag_set.all()]
        logger.debug(context['old_tags'])
        context['other_tags'] = [tag.tag for tag in TagManager.objects.filter(tag_type=1).filter(Q(team__in=user_groups)|Q(team__isnull=True)).exclude(tag__in=context['old_tags']).order_by('tag').distinct('tag')]
        #context['other_tags'] = [tag.tag for tag in TicketTag.objects.exclude(ticket=context['ticket']).order_by('tag').distinct('tag')]
        context['form'] = AddArtifactForm()
        artifacts = Artifact.objects.filter(ticketartifact__ticket=context['ticket'])
        context['artifacts'] = artifacts.order_by('-date_added')
        context['artifactsjs'] = [ obj.as_dict() for obj in context['artifacts'] ]

        # is this a contact assoc ticket?
        ca = ContactAssociation.objects.filter(ticket=context['ticket']).first()
        if ca:
            context['ca'] = ca
        return context

class ConfirmCaseUpdateStatus(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/updatecase.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(ConfirmCaseUpdateStatus, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['action'] = reverse("vince:updatecase", args=[context['case'].id])
        return context


class UpdateCaseView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = VulnerabilityCase
    login_url = "vince:login"
    fields = "__all__"
    template_name = 'vince/case.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        else:
            return False

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__} post: {self.request.POST}!")
        if request.POST.get('new_status'):
            case = get_object_or_404(VulnerabilityCase, id=kwargs['pk'])
            old_status_str = case.get_status_display()
            old_status = case.status
            new_status = int(self.request.POST.get('new_status', old_status))
            if new_status != case.status:
                case.status = new_status
                case.save()
                new_status_str = case.get_status_display()
                title = f"{request.user.username} changed status of case from {old_status_str} to {new_status_str}"
            else:
                title = None
            if request.POST.get('comment'):
                comment = request.POST.get('comment')
                comment = comment.replace('{%', 'X-HELPDESK-COMMENT-VERBATIM').replace('%}', 'X-HELPDESK-COMMENT-ENDVERBATIM')
                comment = comment.replace('X-HELPDESK-COMMENT-VERBATIM', '{% verbatim %}{%').replace('X-HELPDESK-COMMENT-ENDVERBATIM', '%}{% endverbatim %}')
                if not title:
                    # just a comment
                    title=f"{request.user.usersettings.vince_username} added a comment"
            else:
                comment = ""
                if not title:
                    # no change happened
                    return HttpResponseRedirect(case.get_absolute_url())
            logger.debug("create case action")
            ca = CaseAction(case=case, user=self.request.user, comment=comment, title=title, action_type=1)
            ca.save()
            return HttpResponseRedirect(case.get_absolute_url())

        elif request.POST.get('comment'):
            UpdateCaseView.addComment(kwargs['pk'], request.user, request.POST.get('comment'))
            case = get_object_or_404(VulnerabilityCase, id=kwargs['pk'])
            return HttpResponseRedirect(case.get_absolute_url())
        elif request.POST.get('add_tag'):
            return UpdateCaseView.add_tag(kwargs['pk'], request.user, request.POST.get('tag').lower())
        elif request.POST.get('del_tag'):
            return UpdateCaseView.del_tag(kwargs['pk'], request.user, request.POST.get('tag').lower())

    @staticmethod
    def add_tag(case_id, user, tag):
        case = get_object_or_404(VulnerabilityCase, id=case_id)
        user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
        if len(tag) < 50:
            if TagManager.objects.filter(tag=tag, tag_type=3).filter(Q(team__in=user_groups)|Q(team__isnull=True)).exists():
                tag, created = CaseTag.objects.update_or_create(case=case, tag=tag,
                                                                  defaults={'user':user})
                if created:
                    fup = CaseAction(title=f"Case tagged as \"{tag}\"",
                                   case=case,
	                           user=user)
                    fup.save()
            else:
                logger.debug("invalid tag - tag doesn't exist in tag manager")
                return JsonResponse({'tag': tag, 'case': case.id, 'error': "Invalid Tag."}, status=401)
        else:
            return JsonResponse({'tag': tag, 'case': case.id, 'error': "Tag is too long. Max 50 characters."}, status=401)
        return JsonResponse({'tag_added': tag.tag, 'case': case.id}, status=200)

    @staticmethod
    def del_tag(case_id, user, tag):
        case = get_object_or_404(VulnerabilityCase, id=case_id)
        try:
            CaseTag.objects.get(tag=tag, case=case).delete()
            fup = CaseAction(title=f"Removed case tag \"{tag}\"",
                           case=case,
                           user=user)
            fup.save()
            return JsonResponse({'tag_deleted': tag, 'case':case.id}, status=200)
        except CaseTag.DoesNotExist:
            return JsonResponse({'tag': tag, 'case': case.id, 'error': f"'{tag}' not assigned to case"}, status=401)

    @staticmethod
    def addComment(case_id, user, comment):
        # this prevents system from trying to render any template tags
        # broken into two stages to prevent changes from first replace being themselves
        # changed by the second replace due to conflicting syntax
        comment = comment.replace('{%', 'X-HELPDESK-COMMENT-VERBATIM').replace('%}', 'X-HELPDESK-COMMENT-ENDVERBATIM')
        comment = comment.replace('X-HELPDESK-COMMENT-VERBATIM', '{% verbatim %}{%').replace(
            'X-HELPDESK-COMMENT-ENDVERBATIM', '%}{% endverbatim %}')

        ca = CaseAction(case_id=case_id, user=user, comment=comment, title=f"{user.usersettings.vince_username} added a comment", action_type=1)
        ca.save()

class CloseTicketandTagView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    form_class = CloseTicketForm
    template_name = "vince/why_close.html"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
            if ticket.case:
                return has_case_write_access(self.request.user, ticket.case)
            return has_queue_write_access(self.request.user, ticket.queue)

    def get_context_data(self, **kwargs):
        context = super(CloseTicketandTagView, self).get_context_data(**kwargs)
        form = CloseTicketForm()
        templates = EmailTemplate.objects.filter(locale="en", body_only=True)
        form.fields['email_template'].choices = [
            (q.id, q.template_name) for q in templates]
        context['form'] = form
        context['ticket'] = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        cr = CaseRequest.objects.filter(ticket_ptr_id=self.kwargs['ticket_id']).first()

        referer = self.request.META.get('HTTP_REFERER')
        logger.debug(f"REFERER IS {referer}") 
        
        #is this ticket from a VINCE user?
        if context['ticket'].submitter_email:
            #lookup user
            vcuser = User.objects.using('vincecomm').filter(email=context['ticket'].submitter_email).first()
            if vcuser == None:
                # no option to send message
                form.fields['send_email'].choices = [(1, "No"), (2, "Send Email")]
        elif cr:
            if cr.contact_email:
                vcuser = User.objects.using('vincecomm').filter(email=context['ticket'].submitter_email).first()
                if vcuser == None:
                    # no option to send message
                    form.fields['send_email'].choices = [(1, "No"), (2, "Send Email")]
        else:
            #no one to email
            form.fields['send_email'].choices=[(1, "No")]

        context['form'] = form
        return context

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = CloseTicketForm(self.request.POST)
        templates = EmailTemplate.objects.filter(locale="en", body_only=True)
        form.fields['email_template'].choices = [
            (q.id, q.template_name) for q in templates]
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        ticket.close_reason = form.cleaned_data['close_choice']
        ticket.save()
        # look up cr in vincecomm
        referer = self.request.META.get('HTTP_REFERER')
        logger.debug(f"REFERER IS {referer}")
        cr = CaseRequest.objects.filter(id=ticket.id).first()
        vtcr = None
        if cr:
            # look for vtcaserequest
            vtcr = VTCaseRequest.objects.filter(id=cr.vc_id).first()
            if vtcr:
                vtcr.status = Ticket.CLOSED_STATUS
                vtcr.save()

        email_template = EmailTemplate.objects.get(id=form.cleaned_data['email_template'])
        if int(form.cleaned_data['send_email']) == 2:
            logger.debug(f"sending email to submitter")
            notification = VendorNotificationEmail(subject=email_template.subject,
                                                   email_body = form.cleaned_data['email'])
            if ticket.submitter_email:
                send_submitter_email_notification([ticket.submitter_email], ticket,
                                                  email_template.subject,
                                                  form.cleaned_data['email'],
                                                  vtcr)

                fup = FollowUp(title=f"sent email using template \"{email_template.template_name}\" to {ticket.submitter_email}",
                               comment=form.cleaned_data['email'], ticket=ticket,
                               user=self.request.user)
                fup.save()
                notification.save()
                email = VinceEmail(ticket=ticket,
                                   notification=notification,
                                   user=self.request.user,
                                   email_type = 1,
                                   to=ticket.submitter_email)
                email.save()
            elif cr.contact_email:
                send_submitter_email_notification([cr.contact_email], ticket,
	                                          email_template.subject,
                                                  form.cleaned_data['email'],
                                                  vtcr)

                fup = FollowUp(title=f"sent email using template \"{email_template.template_name}\" to {cr.contact_email}",
                               comment=form.cleaned_data['email'], ticket=ticket,
                               user=self.request.user)
                fup.save()
                notification.save()
                email =	VinceEmail(ticket=ticket,
                                   notification=notification,
                                   user=self.request.user,
                                   email_type =	1,
                                   to=cr.contact_email)
                email.save()
            if vtcr:
                vc_user = User.objects.using('vincecomm').filter(username=self.request.user.username).first()
                crfup = CRFollowUp(title=f"sent email to submitter",
                                   comment=form.cleaned_data['email'],
                                   cr=vtcr, user=vc_user)
                crfup.save()

        elif int(form.cleaned_data['send_email']) == 3:
            logger.debug("send message to VINCE User")
            user_lookup = User.objects.using('vincecomm').filter(email=ticket.submitter_email).first()
            sender = User.objects.using('vincecomm').filter(email=self.request.user.email).first()
            subject = f"[{ticket.ticket_for_url}] {email_template.subject} {ticket.title}"
            if user_lookup:
                msg = Message.new_message(sender, [user_lookup.id], None, subject, form.cleaned_data['email'])
                msg.thread.from_group=ticket.queue.team.groupsettings.contact.vendor_name
                msg.thread.save()

                fup = FollowUp(title=f"sent message using template \"{email_template.template_name}\" to {ticket.submitter_email}",
                               comment=form.cleaned_data['email'], ticket=ticket,
                               user=self.request.user)
                fup.save()
                tm = TicketThread(thread=msg.thread.id,
                                  ticket=ticket.id)
                
                tm.save()
                fm = FollowupMessage(followup=fup,
                                     msg=msg.id)
                fm.save()

        if self.request.session.get('vince_referer'):
            update_ticket(self.request, self.kwargs['ticket_id'])
            return redirect(self.request.session.get('vince_referer'))
        else:
            return update_ticket(self.request, self.kwargs['ticket_id'])



class UpdateTicketView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Ticket
    login_url = "vince:login"
    fields = "__all__"
    template_name = 'vince/ticket.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
            return has_queue_write_access(self.request.user, ticket.queue)

    def post(self, request, *args, **kwargs):
        logger.debug("IN UPDATE TICKET VIEW")
        logger.debug(self.request.POST)
        if request.POST.get('add_subscriber'):
            return UpdateTicketView.add_subscriber(request.POST.get('user'),kwargs['ticket_id'])
        elif request.POST.get('del_subscriber'):
            logger.debug(kwargs['ticket_id'])
            logger.debug(request.POST.get('user'))
            return UpdateTicketView.del_subscriber(request.POST.get('user'), kwargs['ticket_id'])
        elif request.POST.get('add_tag'):
            return UpdateTicketView.add_tag(request.POST.get('tag').lower(), kwargs['ticket_id'], self.request.user)
        elif request.POST.get('del_tag'):
            return UpdateTicketView.del_tag(request.POST.get('tag').lower(), kwargs['ticket_id'], self.request.user)
        else:
            ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
            return update_ticket(request, self.kwargs['ticket_id'])

    @staticmethod
    def add_subscriber(username, ticket_id):
        """ Add a subscriber to a ticket """
        logger.debug("IN ADD SUBSCRIBER")
        user = get_object_or_404(User, usersettings__preferred_username__iexact=username)
        ticket = get_object_or_404(Ticket, id=ticket_id)
        if TicketCC.objects.filter(ticket=ticket, user=user):
            return JsonResponse({'subscriber_added': user.username,
                                 'ticket': ticket.id,
                                 'error': f"User '{user.username}' already subscribed to ticket '{ticket.id}'."},
                                status=401)
        else:
            tf = TicketCC(ticket=ticket, user=user)
            tf.save()
            logger.debug("successfully added user")
            return JsonResponse({'subscriber_added': user.username, 'ticket': ticket.id}, status=200)

    @staticmethod
    def del_subscriber(username, ticket_id):
        """ Del a subscriber from a ticket"""
        user = get_object_or_404(User, usersettings__preferred_username__iexact=username)
        ticket = get_object_or_404(Ticket, id=ticket_id)

        try:
            TicketCC.objects.get(user=user, ticket=ticket).delete()
            return JsonResponse({'subscriber_deleted': user.username, 'ticket':ticket.id}, status=200)
        except TicketCC.DoesNotExist:
            return JsonResponse({'user': user.username, 'ticket': ticket.id, 'error': f"User '{user.username}' is not subscribed to ticket '{ticket.id}'"}, status=401)

    @staticmethod
    def add_tag(tag, ticket_id, user):
        ticket = get_object_or_404(Ticket, id=ticket_id)
        user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
        if len(tag) < 50:
            if TagManager.objects.filter(tag=tag, tag_type=1).filter(Q(team__in=user_groups)|Q(team__isnull=True)).exists():
                tag, created = TicketTag.objects.update_or_create(ticket=ticket, tag=tag,
                                                                  defaults={'user':user})
                if created:
                    fup = FollowUp(title=f"Ticket tagged as \"{tag}\"",
                                   ticket=ticket,
                                   user=user)
                    fup.save()
            else:
                logger.debug("invalid tag - tag doesn't exist in tag manager")
                return JsonResponse({'tag': tag, 'ticket': ticket.id, 'error': "Invalid Tag."}, status=401)
        else:
            return JsonResponse({'tag': tag, 'ticket': ticket.id, 'error': "Tag is too long. Max 50 characters."}, status=401)
        return JsonResponse({'tag_added': tag.tag, 'ticket': ticket.id}, status=200)

    @staticmethod
    def del_tag(tag, ticket_id, user):
        ticket = get_object_or_404(Ticket, id=ticket_id)
        try:
            TicketTag.objects.get(tag=tag, ticket=ticket).delete()
            fup = FollowUp(title=f"Removed ticket tag \"{tag}\"",
                           ticket=ticket,
                           user=user)
            fup.save()
            return JsonResponse({'tag_deleted': tag, 'ticket':ticket.id}, status=200)
        except TicketTag.DoesNotExist:
            return JsonResponse({'tag': tag, 'ticket': ticket.id, 'error': f"'{tag}' not assigned to ticket '{ticket.id}'"}, status=401)

    def get_context_data(self, **kwargs):
        context = super(UpdateTicketView, self).get_context_data(**kwargs)
        context['ticket'] = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        return context


@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def followup_delete(request, ticket_id, followup_id):
    """followup delete for superuser"""

    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not request.user.is_superuser:
        return HttpResponseRedirect(reverse('vince:ticket', args=[ticket.id]))

    followup = get_object_or_404(FollowUp, id=followup_id)
    followup.delete()
    return HttpResponseRedirect(reverse('vince:ticket', args=[ticket.id]))

class FollowupEditView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Action
    login_url = "vince:login"
    template_name = 'vince/followup_edit.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            action = get_object_or_404(Action, id=self.kwargs['pk'])
            self.form_name = "followup-edit-form"
            if action.get_related_ticket:
                return has_queue_write_access(self.request.user, action.get_related_ticket.queue)
            elif action.get_related_case:
                self.form_name = "case-edit-form"
                return has_case_write_access(self.request.user, action.get_related_case)
            return False


    def post(self, request, *args, **kwargs):
        logger.debug("IN UPDATE Followup VIEW")
        logger.debug(self.request.POST)
        comment = request.POST['comment']

        action = get_object_or_404(Action, id=self.kwargs['pk'])

        action.comment = comment
        action.last_edit = timezone.now()
        action.save()

        return JsonResponse({'success': True}, status=200)


    def get_context_data(self, **kwargs):
        context = super(FollowupEditView, self).get_context_data(**kwargs)
        context['action'] = get_object_or_404(Action, id=self.kwargs['pk'])
        context['form_name'] = self.form_name
        return context



@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def hold_ticket(request, ticket_id, unhold=False):

    ticket = get_object_or_404(Ticket, id=ticket_id)

    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()

    if unhold:
        ticket.on_hold = False
        title = _('Ticket taken off hold')
    else:
        ticket.on_hold = True
        title = _('Ticket placed on hold')

    f = FollowUp(
        ticket=ticket,
        user=request.user,
        title=title,
        date=timezone.now(),
    )
    f.save()

    ticket.save()

    return HttpResponseRedirect(ticket.get_absolute_url())

@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def unhold_ticket(request, ticket_id):
    return hold_ticket(request, ticket_id, unhold=True)

class DeleteTicketView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Ticket
    login_url = "vince:login"
    template_name = 'vince/delete_ticket.html'

    def	test_func(self):
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        return is_in_group_vincetrack(self.request.user) and has_queue_write_access(self.request.user, ticket.queue)

    def get_context_data(self, **kwargs):
        context = super(DeleteTicketView, self).get_context_data(**kwargs)
        context['ticket'] = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        return context

    def post(self, request, *args, **kwargs):
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        if not(self.request.user.is_superuser):
            messages.error(
                self.request,
		_("User must be an administrator to perform this action"))
            return redirect("vince:ticket", self.kwargs['ticket_id'])
        else:
            ticket.delete()
            return HttpResponseRedirect(reverse('vince:dashboard'))



class EditCaseView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.UpdateView):
    form_class = EditCaseForm
    model = VulnerabilityCase
    login_url = "vince:login"
    template_name = 'vince/edit_case.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        else:
            return False

    def get_form_kwargs(self):
        kwargs = super(EditCaseView, self).get_form_kwargs()
        kwargs.update({
            "user": self.request.user,
        })
        return kwargs

    def form_valid(self, form):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        template = case.template
        title = "Edited Case Details"
        new_tasks = False
        if template:
            if self.request.POST['template']:
                if template.id != int(self.request.POST['template']):
                    new_tasks = True
                    #this is a change in template
                    title = title + ", changed case template"
            else:
                title = title + ", removed case template"
                case.template = None
                case.save()
        elif self.request.POST['template']:
            new_tasks = True
            case.template = CaseTemplate.objects.get(id=self.request.POST['template'])
            case.save()
            title = title + ", added case template"
        if new_tasks:
            #get new template
            newtemplate = CaseTemplate.objects.get(id=self.request.POST['template'])
            for task in CaseTask.objects.filter(template=newtemplate):
                ticket = Ticket(title = task.task_title,
                                created = timezone.now(),
                                status = Ticket.OPEN_STATUS,
                                queue = newtemplate.queue,
                                description = task.task_description,
				priority = task.task_priority,
                                case = case)
                ticket.save()
                ca = CaseAssignment.objects.filter(case=case).first()
                # assign to user assigned to case.
                if ca:
                    ticket.assigned_to = ca.assigned
                    ticket.save()
                # create dependencies
                if task.dependency:
                    dep = CaseDependency(case=case, depends_on=ticket)
                    dep.save()
                fup = FollowUp(ticket=ticket,
                               title=f"Ticket Opened By {newtemplate.title} Template",
                               date=timezone.now(),
                               comment=task.task_title)
                fup.save()

        if case.owner != form.cleaned_data['owner']:
            new_owner = form.cleaned_data['owner']
            if case.owner:
                if new_owner:
                    title = title + f", changed Case Owner from {case.owner.usersettings.vince_username} to {new_owner.usersettings.vince_username}"
                else:
                    title = title + f", removed case owner {case.owner.usersettings.vince_username}"
            else:
                title = title + f", changed Case from Unassigned to {new_owner.usersettings.vince_username}"

            ca = CaseAssignment.objects.filter(case=case, assigned=new_owner).first()
            if ca == None:
                # assign user to this case
                if new_owner:
                    ca = CaseAssignment(case=case,
                                        assigned=new_owner)
                    ca.save()

        if case.team_owner != form.cleaned_data['team_owner']:
            new_group = form.cleaned_data['team_owner']
            if case.team_owner:
                title = title + f", changed Case Owner from {case.team_owner.name} to {new_group.name}"
            else:
                title = title + f", set Case Owner to {new_group.name}"

            _transfer_case(case, new_group)

        case = form.save()

        if case.owner and case.team_owner:
            if not(case.owner.groups.filter(id=case.team_owner.id).exists()):
               # if the owner isn't in the team owner, change the owner
               case.owner = self.request.user
               case.save()
        
        ca = CaseAction(case=case, user=self.request.user, title=title, action_type=1)
        ca.save()
        return HttpResponseRedirect(reverse("vince:case", args=[case.id])+"#details")

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        self.object = self.get_object()
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        form.instance = case
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(EditCaseView, self).get_context_data(**kwargs)
        context['casepage']=1
        return context


class CaseActivityView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/include/case_timeline.html"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(CaseActivityView, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        ca = Action.objects.select_related('caseaction').filter(caseaction__case=context['case'])
        ta = Action.objects.select_related('followup').filter(followup__ticket__case=context['case'])
        context['activity'] = ca | ta
        context['activity'] = context['activity'].order_by('-date')
        context['allow_edit'] = True
        return context

class DashboardPostView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = 'vince/case.html'

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        context = {}
        cases = CaseAssignment.objects.filter(assigned=self.request.user)
        my_case_list = list(cases.values_list('case__vuid', flat=True))
        vc_cases = Case.objects.filter(vuid__in=my_case_list)
        new_posts = 0
        post_ids=[]
        context['postsjs'] = []
        for case in vc_cases:
            lastpost = Post.objects.filter(case=case).exclude(author__username=self.request.user).order_by('-modified')
            last_viewed = CaseViewed.objects.filter(user__username=self.request.user.username, case=case).first()
            if lastpost and last_viewed:
                posts = lastpost.filter(modified__gt=last_viewed.date_viewed)
                if posts:
                    for post in posts:
                        post_ids.append(post.id)
                        try:
                            context['postsjs'].append({'url': reverse("vinny:case", args=[case.id]),
                                                       'case': f"{post.case.vu_vuid}",
                                                       'from': post.author.vinceprofile.preferred_username,
                                                       'group': post.group.groupcontact.contact.vendor_name,
                                                       'revision': post.current_revision.revision_number})
                        except:
                            context['postsjs'].append({'url': reverse("vinny:case", args=[case.id]),
                                                       'case': f"{post.case.vu_vuid}",
                                                       'from': post.author.vinceprofile.preferred_username,
                                                       'group': 'No affiliation',
                                                       'revision': post.current_revision.revision_number})

                            #context['post_activity'] = Post.objects.filter(id__in=post_ids).order_by('-modified')
        return JsonResponse(context, safe=False, status=200)

class DashboardPostActivityView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/include/case_timeline.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(DashboardPostActivityView, self).get_context_data(**kwargs)
        context = {}
        cases = CaseAssignment.objects.filter(assigned=self.request.user)
        my_case_list = list(cases.values_list('case__vuid', flat=True))
        vc_cases = Case.objects.filter(vuid__in=my_case_list)
        post_ids=[]
        for case in vc_cases:
            lastpost = Post.objects.filter(case=case).exclude(author__username=self.request.user).order_by('-modified')
            last_viewed = CaseViewed.objects.filter(user__username=self.request.user.username, case=case).first()
            if lastpost and last_viewed:
                posts = lastpost.filter(modified__gt=last_viewed.date_viewed)
                if posts:
                    for post in posts:
                        post_ids.append(post.id)

        context['activity'] = Post.objects.filter(id__in=post_ids).order_by('-modified')
        return context

class DashboardTicketView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Ticket
    login_url = "vince:login"
    template_name = 'vince/case.html'

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        if self.kwargs['type'] == "Open":
            tickets = Ticket.objects.filter(status__in=[1,2,6], assigned_to=self.request.user).order_by('-modified')
        elif self.kwargs['type'] == "Progress":
            tickets = Ticket.objects.filter(status__in=[6], assigned_to=self.request.user).order_by('-modified')
        elif self.kwargs['type'] == "Message":
            tickets = Ticket.objects.filter(assigned_to=self.request.user, status__in=[1,2,6]).values_list('id', flat=True)
            tickets = TicketThread.objects.filter(ticket__in=tickets).values_list('ticket', flat=True)
            tickets = Ticket.objects.filter(id__in=tickets).order_by('-modified')
        else:

            tickets = Ticket.objects.select_related('queue').filter(assigned_to=self.request.user).exclude(status__in=[Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS, Ticket.DUPLICATE_STATUS]).order_by('modified')

        ticketsjs = [ obj.as_dict() for obj in tickets]
        return JsonResponse(ticketsjs, safe=False, status=200)

class CaseTicketView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Ticket
    login_url = "vince:login"
    template_name = 'vince/case.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        tickets = Ticket.objects.filter(case=case).annotate(custom_order=DBCase(When(status = Ticket.OPEN_STATUS, then=Value(1)),
                               When(status = Ticket.IN_PROGRESS_STATUS, then=Value(2)),
                               When(status = Ticket.REOPENED_STATUS, then=Value(3)),
                               When(status = Ticket.RESOLVED_STATUS, then=Value(4)),
                               When(status = Ticket.CLOSED_STATUS, then=Value(5)),
                               When(status = Ticket.DUPLICATE_STATUS, then=Value(6)),
                               output_field=IntegerField(),)).order_by('custom_order', '-modified')
        ticketsjs = [ obj.as_dict() for obj in tickets]
        return JsonResponse(ticketsjs, safe=False, status=200)

class DashboardQueueActivityView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/include/case_timeline.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(DashboardQueueActivityView, self).get_context_data(**kwargs)
        status = 0
        if self.kwargs['title'] == "Open":
            status = [1,2]
        elif self.kwargs['title'] == "Progress":
            status = [6]
        elif self.kwargs['title'] == 'Message':
            tickets = Ticket.objects.filter(assigned_to=self.request.user, status__in=[1,2,6]).values_list('id', flat=True)
            tickets = TicketThread.objects.filter(ticket__in=tickets).values_list('ticket', flat=True)
            context['activity'] = FollowUp.objects.filter(ticket__id__in=tickets).order_by('-date')
            return context

        context['activity'] = FollowUp.objects.filter(ticket__status__in=status, ticket__assigned_to=self.request.user).order_by('-date')
        return context

class DashboardCaseActivityView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/include/case_timeline.html"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(DashboardCaseActivityView, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        ca = Action.objects.select_related('caseaction').filter(caseaction__case=context['case'])
        ta = Action.objects.select_related('followup').filter(followup__ticket__case=context['case'])
        context['activity'] = ca | ta
        context['activity'] = context['activity'].order_by('-date')
        return context


class VendorViewDetailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/vendor_viewed.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case.case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(VendorViewDetailView, self).get_context_data(**kwargs)
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
        if vendor.seen:
            context['timeseen'] = CaseAction.objects.filter(case=vendor.case, vendor=vendor, action_type=7).first()

        vc_case = Case.objects.using('vincecomm').filter(vuid=vendor.case.vuid).first()
        #get users in group
        vc_contact = VinceCommContact.objects.using('vincecomm').filter(vendor_id=vendor.contact.id).first()
        if vc_contact:
            groupcontact = GroupContact.objects.using('vincecomm').filter(contact=vc_contact).first()
            if groupcontact:
                context['vince_users'] = list(User.objects.using('vincecomm').filter(groups=groupcontact.group).values_list('id', flat=True))
                context['views'] = CaseViewed.objects.filter(case=vc_case, user__in=context['vince_users'])

        return context


class CompleteCaseTransferView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/complete_transfer.html"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(CompleteCaseTransferView, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        #does a case request exist?
        cr = CaseParticipant.objects.filter(case=context['case'], status__in=["Lead Requested", "Lead Suggested"]).first()
        if cr:
            # get ticket
            context['ticket'] = Ticket.objects.filter(case=context['case'],
                                                      title__icontains="Case Transfer Request",
                                                      submitter_email = cr.added_by.email,
                                                      status=Ticket.OPEN_STATUS).first()
            
            # how does this user fit in to this request
            # get group
            if cr.status == "Lead Requested":
                # then current owner must approve
                if context['case'].team_owner:
                    if (self.request.user.groups.filter(id=context['case'].team_owner.id).exists()):
                        # present form
                        logger.debug("This user is a member of the current owner group")
                        context['form'] = True
                    else:
                        context['group_to_approve'] = context['case'].team_owner
                elif has_case_write_access(self.request.user, context['case']):
                    logger.debug("This case doesn't have an owner but this user has write access")
                    context['form'] = True
                else:
                    context['group_to_approve'] = context['case'].team_owner
                    
            else:
                # Lead Suggested means that the new group must approve transfer
                group = Group.objects.filter(groupsettings__contact__vendor_name=cr.user_name).first()
                if (self.request.user.groups.filter(id=group.id).exists()):
                    logger.debug("This user is a member of the group proposed owner team")
                    # present form
                    context['form'] = True
                else:
                    context['group_to_approve'] = group

            context['cr'] = cr
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        cp = CaseParticipant.objects.filter(case=case, status__in=["Lead Requested", "Lead Suggested"]).first()
        new_group = Group.objects.filter(groupsettings__contact__vendor_name=cp.user_name).first()

        # get ticket                                                                         
        transfer_tkt = Ticket.objects.filter(case=case,
                                             title__icontains="Case Transfer Request",
                                             submitter_email = cp.added_by.email,
                                             status=Ticket.OPEN_STATUS).first()
        
        if cp and new_group:
            #make the transfer
            case.team_owner=new_group
            #if the current owner is not in the new group
            if not(case.owner.groups.filter(id=new_group.id).exists()):
                # check if the requesting user is
                if self.request.user.groups.filter(id=new_group.id).exists():
                    case.owner = self.request.user
                else:
                    # otherwise set to None
                    case.owner = None
            case.save()

            #remove write permissions
            _transfer_case(case, new_group)

            ca = CaseAction(case=case, title=f"Case ownership transferred to {new_group.name}",
                            user=self.request.user, action_type=1)
            ca.save()

            #add this user to the case assignment so at least SOMEBODY is assigned
            if self.request.user.groups.filter(id=new_group.id).exists():
                newassignment = CaseAssignment.objects.update_or_create(case=case,
                                                                        assigned=self.request.user)
            else:
                #assign requester
                newassignment = CaseAssignment.objects.update_or_create(case=case,
                                                                       assigned=cp.added_by)
            
            #change case assigment
            ca = CaseAssignment.objects.filter(case=case)
            for c in ca:
                if not(c.assigned.groups.filter(id=new_group.id).exists()):
                    #if the assignee isn't in the group - remove them
                    act = CaseAction(case=case, title=f"Removing {c.assigned.usersettings.preferred_username} from case assignment due to team transfer", action_type=1, user=self.request.user)
                    c.delete()
                    act.save()


            if transfer_tkt:
                fup = FollowUp(title="Transfer approved and completed.",
                               user=self.request.user,
                               ticket=transfer_tkt)
                fup.save()
                transfer_tkt.assigned_to = self.request.user
                transfer_tkt.status=Ticket.CLOSED_STATUS
                transfer_tkt.save()

            
        return redirect("vince:case", case.id)

class RejectCaseTransferView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = "vince:login"
    template_name = 'vince/reject_case_transfer.html'
    form_class = RejectCaseTransferForm

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(RejectCaseTransferView, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        cr = CaseParticipant.objects.filter(case=context['case'], status__in=["Lead Requested", "Lead Suggested"]).first()
        if cr:
            context['cr'] = cr
            # how does this user fit in to this request
            # get group
            group = Group.objects.filter(groupsettings__contact__vendor_name=cr.user_name).first()
            if (self.request.user.groups.filter(id=group.id).exists()):
                # present form
                context['form'] = RejectCaseTransferForm()
            else:
                context['noprivs'] = True
        else:
            raise Http404

        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        #roll back request
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])

        cp = CaseParticipant.objects.filter(case=case, coordinator=True,
                                            status__in=["Lead Requested", "Lead Suggested"]).first()
        if cp == None:
            return Http404

        new_group = Group.objects.filter(groupsettings__contact__vendor_name=cp.user_name).first()
        
        ca = CaseAction(case=case, title=f"Case ownership transfer to {new_group.name} rejected.",
                        comment=self.request.POST.get('reason'),
                        user=self.request.user, action_type=1)
        ca.save()

        # get ticket 
        transfer_tkt = Ticket.objects.filter(case=case,
                                             title__icontains="Case Transfer Request",
                                             submitter_email = cp.added_by.email,
                                             status=Ticket.OPEN_STATUS).first()

        # change old team owner to not lead                                                  
        cp.delete()
            
        if transfer_tkt:
            fup = FollowUp(title="Transfer rejected.",
                           user=self.request.user,
                           comment=self.request.POST.get('reason'),
                           ticket=transfer_tkt)
            fup.save()
            transfer_tkt.assigned_to = self.request.user
            transfer_tkt.status=Ticket.CLOSED_STATUS
            transfer_tkt.save()

            
        return redirect("vince:case", case.id)

def _transfer_case(case, new_group):
    #check perms
    #remove old permissions
    old_perms = CasePermissions.objects.filter(case=case)
    for x in old_perms:
        x.delete()

    #get CR queue permissions of new_group and assign same case permssions to case

    qp = QueuePermissions.objects.filter(queue__queue_type=2, queue__team=new_group)
    for x in qp:
        cp = CasePermissions.objects.update_or_create(group=x.group, case=case,
                                                      defaults = {'group_read':x.group_read,
                                                                  'group_write':x.group_write,
                                                                  'publish':x.publish})

    # change old team owner to not lead                                         
    cp = CaseParticipant.objects.filter(case=case, coordinator=True,
                                        status = "Lead")
    for c in cp:
        remove_participant_vinny_case(case, c)
        c.delete()
        
    add_coordinator_case(case, new_group.groupsettings.contact)
    
    
class RequestCaseTransferView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = "vince:login"
    template_name = 'vince/transfer_case.html'
    form_class=RequestCaseTransferForm

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(RequestCaseTransferView, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        initial = {}
        initial['team'] = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if context['case'].team_owner:
            initial['team'] = self.request.user.groups.exclude(id=context['case'].team_owner.id)
        initial['team'] = initial['team'].first().id
        form = RequestCaseTransferForm(initial=initial)
        if context['case'].team_owner:
            form.fields['team'].choices = [(g.id, g.name) for g in Group.objects.exclude(groupsettings__contact__isnull=True).exclude(id=context['case'].team_owner.id)]
        else:
            form.fields['team'].choices = [(g.id, g.name) for g in Group.objects.exclude(groupsettings__contact__isnull=True)]
        if len(form.fields['team'].choices) > 0:
            context['form'] = form
        else:
            context['form'] = None
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        form = RequestCaseTransferForm(request.POST)
        if case.team_owner:
            form.fields['team'].choices = [(g.id, g.name) for g in Group.objects.exclude(groupsettings__contact__isnull=True).exclude(id=case.team_owner.id)]
        else:
            form.fields['team'].choices = [(g.id, g.name) for g in Group.objects.exclude(groupsettings__contact__isnull=True)]

        if form.is_valid():
            # get team
            case_url = str(case.get_absolute_url())
            case_accept_url = reverse("vince:transfer", args=[case.id])
            new_group = Group.objects.filter(id=form.cleaned_data['team']).first()
            # does this group already have write access?
            if CasePermissions.objects.filter(group_write=True, group=new_group, case=case).exists():
                logger.debug("New group already has write access")
                if has_case_write_access(self.request.user, case):
                    logger.debug("User has write access")
                    # just change owner
                    case.team_owner=new_group
                    case.owner = self.request.user
                    case.save()
                    #create log
                    ca = CaseAction(case=case, title=f"Case ownership transferred to {new_group.name}",
                                    user=self.request.user, action_type=1)
                    ca.save()

                    _transfer_case(case, new_group)

                    return HttpResponseRedirect(reverse("vince:case", args=[case.id]) + "#details")
                else:
                    #this user doesn't have write access but wants to assign a team
                    #that already has write access? - WEIRD.
                    # is this group already listed as caseparticipant lead?

                    cp = CaseParticipant.objects.filter(case=case,
                                        user_name=new_group.groupsettings.contact.vendor_name,
                                                        status = "Lead").first()
                    if cp:
                        # this group is basically already the lead, make it offical
                        case.team_owner = new_group
                        case.save()
                        messages.success(
                            self.request,
                            "Your request has been approved."
                        )
                        return redirect("vince:case", case.id)
                    
                    ca = CaseAssignment.objects.filter(case=case).first()
                    ticket = Ticket(title=f"Case Transfer Request for {case.vu_vuid}",
                                    submitter_email=self.request.user.email,
                                    queue = get_case_case_queue(case),
                                    case = case,
                                    description = f"Case Request Transfer Reason: {form.cleaned_data['reason']}\r\n\r\n"\
                                    f"Link to case: {settings.SERVER_NAME}{case_url}\r\n\r\n"\
                                    f"Accept Transfer: {settings.SERVER_NAME}{case_accept_url}")
                    if ca:
                        ticket.assigned_to = ca.assigned
                    ticket.save()
                    fup = FollowUp(ticket=ticket,
                                   title=f"Case Transfer Requested. Request to transfer to {new_group.name}",
                                   comment="View ticket for link to accept",
                                   user=self.request.user)
                    fup.save()
                    messages.success(
                        self.request,
                        "Your request has been sent."
                    )

                    # Add case request               
                    cp = CaseParticipant.objects.update_or_create(case=case,
                                        user_name=new_group.groupsettings.contact.vendor_name,
                                        defaults = {'group':True,
                                                    'added_by': self.request.user,
                                                    'coordinator': True, 'status': "Lead Requested"})
                    
                    return redirect("vince:case", case.id)

                        
            else:
                #this new group doesn't have write access
                #does this user belong in the proposed owner's group
                if self.request.user.groups.filter(id=new_group.id).exists():
                    logger.debug(f"User already belongs in proposed group {new_group.name}")
                    #is this person already in the current owner's group?
                    if has_case_write_access(self.request.user, case):
                        logger.debug("User has write access so just do it")
                        case.team_owner=new_group
                        case.owner = self.request.user
                        case.save()
                        #create log 
                        ca = CaseAction(case=case, title=f"Case ownership transferred to {new_group.name}",
                                        user=self.request.user, action_type=1)
                        ca.save()
                        
                        _transfer_case(case, new_group)
                        return HttpResponseRedirect(reverse("vince:case", args=[case.id]) + "#details")
                    
                    # this person wants the case so assign a request ticket
                    # to the case assignee
                    ca = CaseAssignment.objects.filter(case=case).exclude(assigned=self.request.user).first()
                    ticket = Ticket(title=f"Case Transfer Request for {case.vu_vuid}",
                                    submitter_email=self.request.user.email,
                                    queue = get_case_case_queue(case),
                                    case = case,
                                    description = f"Case Request Transfer Reason: {form.cleaned_data['reason']}\r\n\r\n"\
                                    f"Link to case: {settings.SERVER_NAME}{case_url}\r\n"\
                                    f"Accept Transfer: {settings.SERVER_NAME}{case_accept_url}")
                    if ca:
                        ticket.assigned_to = ca.assigned
                    ticket.save()
                    fup = FollowUp(ticket=ticket,
                                   title=f"Case Transfer Requested. Request to transfer to {new_group.name}",
                                   comment="See ticket description for link to accept.",
                                   user=self.request.user)
                    fup.save()

                    cp = CaseParticipant.objects.update_or_create(case=case,
                                       user_name=new_group.groupsettings.contact.vendor_name,
                                       defaults = {'group':True,
                                                   'added_by': self.request.user,
                                                   'coordinator': True, 'status': "Lead Requested"})

                    
                    messages.success(
                        self.request,
                        "Your request has been sent."
                    )
                    return redirect("vince:case", case.id)
                else:
                    #this is most likely the person assigned to the case
                    #trying to hand off to another team
                    new_queue = QueuePermissions.objects.filter(queue__queue_type=1, group__in=[new_group], group_read=True, group_write=True).first()
                    if new_queue == None:
                        new_queue = QueuePermissions.objects.filter(queue__queue_type=2, group__in=[new_group], group_read=True, group_write=True).first()
                    if new_queue:
                        ticket = Ticket(title=f"Case Transfer Request for {case.vu_vuid}",
                                        submitter_email=self.request.user.email,
                                        case = case,
                                        queue = new_queue.queue,
                                        description = f"Case Request Transfer Reason: {form.cleaned_data['reason']}\r\n\r\n"\
                                        f"Link to case: {settings.SERVER_NAME}{case_url}\r\n\r\n"\
                                        f"Accept Transfer: {settings.SERVER_NAME}{case_accept_url}")
                        ticket.save()
                        fup = FollowUp(ticket=ticket,
                                       title=f"Case Transfer Requested. Request to transfer to {new_group.name}",
                                       comment="See ticket description for link to accept.",
                                       user=self.request.user)
                        fup.save()

                        cp = CaseParticipant.objects.update_or_create(case=case,
                                         user_name=new_group.groupsettings.contact.vendor_name,
                                          defaults = {'group':True,
                                                      'added_by': self.request.user,
                                          'coordinator': True, 'status': "Lead Suggested"})

                        #make sure this new_group has permissions to at least read the case first
                        cp = CasePermissions.objects.update_or_create(case=case,
                                                                      group=new_group,
                                                                      defaults={'group_read':True,
                                                                                'group_write':False,
                                                                                'publish':False})

                        messages.success(
                            self.request,
                            "Your request has been sent."
                        )
                        return redirect("vince:case", case.id)

        messages.error(
            self.request,
            f"Your request could not be processed. {form.errors}"
        )

        return redirect("vince:case", case.id)
        
    
class CaseView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = VulnerabilityCase
    login_url = "vince:login"
    template_name = 'vince/case.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(CaseView, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        try:
            context['cr'] = context['case'].case_request.caserequest
            if context['cr'].vrf_id:
                context['vrf_url'] = download_vrf(context['cr'].vrf_id)
                vc_cr = VTCaseRequest.objects.filter(vrf_id=context['cr'].vrf_id).first()
                if vc_cr:
                    context['vincecomm_link'] = reverse("vinny:cr_report", args=[vc_cr.id])
        except:
            context['ticket'] = context['case'].case_request
            if context['ticket']:
                context['vrf_url'] = download_vrf(context['ticket'].vrf_id)
            
        context['ticket_list'] = Ticket.objects.filter(case=context['case'])
        #context['ticketsjs'] = [ obj.as_dict() for obj in context['ticket_list'] ]
        users = CaseAssignment.objects.filter(case=context['case'])
        context['assigned_users'] = [ u.assigned.usersettings.preferred_username for u in users]
        context['assignable'] = [ u.usersettings.preferred_username for u in User.objects.filter(is_active=True, groups__name='vince')]
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        context['case_tags'] = [tag.tag for tag in context['case'].casetag_set.all()]
        context['case_available_tags'] = [tag.tag for tag in TagManager.objects.filter(tag_type=3).filter(Q(team__in=user_groups)|Q(team__isnull=True)).exclude(tag__in=context['case_tags']).order_by('tag').distinct('tag')] 
        context['casepage']=1
        context['reminders'] = VinceReminder.objects.filter(case=context['case'], alert_date__lte=datetime.today()).order_by('-alert_date')
        context['allow_edit'] = True
        # need this for task reassignment
        context['assignable_users'] = User.objects.filter(is_active=True, groups__name='vince')
        context['assignable_usersjs'] = [{0: 'Unassigned'}] + [{obj.id:obj.usersettings.preferred_username} for obj in context['assignable_users']]
        ca = Action.objects.select_related('caseaction').filter(caseaction__case=context['case'], caseaction__action_type__in=[0,1,9])

        ta = Action.objects.select_related('followup').filter(followup__ticket__case=context['case'])
        activity = ca | ta
        activity = activity.order_by('-date')
        #ticket_activity = FollowUp.objects.filter(ticket__case=context['case']).order_by('-date')
        tartifacts = Artifact.objects.select_related('ticketartifact').filter(ticketartifact__ticket__in=context['ticket_list'])
        cartifacts = Artifact.objects.select_related('caseartifact').filter(caseartifact__case=context['case'])
        context['artifacts']=tartifacts|cartifacts
        context['artifacts']=context['artifacts'].order_by('-date_added')
        context['artifactsjs'] = [ obj.as_dict() for obj in context['artifacts'] ]
        context['artifact_form'] = AddArtifactForm()
        try:
            context['vulnote'] = context['case'].vulnote
            context['revisions'] = VulNoteRevision.objects.filter(vulnote = context['case'].vulnote).order_by('-created')[:4]
            if context['vulnote'].ticket_to_approve:
                # get all approval tickets
                context['approvaltickets'] = Ticket.objects.filter(case=context['case'], title__icontains="vulnerability note for publishing")
                if context['vulnote'].approved:
                    context['approved_by'] = VulNoteReview.objects.filter(vulnote__vulnote__case=context['case'], approve=True).distinct('reviewer').values_list('reviewer__usersettings__preferred_username', flat=True)


        except:
            # vulnote doesn't exist
            pass

        context['vuls'] = Vulnerability.casevuls(context['case'])
        context['vulsjs'] = [obj.as_dict() for obj in context['vuls']]
        context['vendors'] = VulnerableVendor.casevendors(context['case']).order_by('contact__vendor_name')
        context['vendorgroups'] = VulnerableVendor.casevendors(context['case']).exclude(from_group__isnull=True).distinct('from_group')
        logger.debug(context['vendorgroups'])
        context['participants'] = CaseParticipant.objects.filter(case=context['case']).order_by('user_name')
        context['participantsjs'] = [obj.as_dict() for obj in context['participants']]

        vc_case = Case.objects.filter(vince_id=context['case'].id).first()
        if vc_case:
            vc_activity = VendorAction.objects.filter(case=vc_case)
            posts = Post.objects.search(case=vc_case)
            messages = Message.objects.search(case=vc_case)
            case_activity = chain(activity, vc_activity, posts, messages)
        else:
            case_activity = chain(activity)
        context['activity'] = sorted(case_activity,
                                     key=lambda instance: instance.created,
                                     reverse=True)[:10]

        # this is all done asych now...
        vc_case_participants = CaseMember.objects.filter(case=vc_case, participant__isnull=False)
        form = CaseCommunicationsFilterForm()
        form.fields['vendor'].choices = [
            (u.id, u.contact.vendor_name) for u in context['vendors']]
        logger.debug(form.fields['vendor'].choices)
        form.fields['participants'].choices = [
            (u.id, u.participant.vinceprofile.vince_username) for u in vc_case_participants]
        context['form'] = form

        #is this case in transfer mode?
        cr = CaseParticipant.objects.filter(case=context['case'], status__in=["Lead Requested", "Lead Suggested"]).first()
        if cr:
            # get ticket                                                                        
            context['transfer'] = Ticket.objects.filter(case=context['case'],
                                                title__icontains="Case Transfer Request",
                                                        submitter_email = cr.added_by.email,
                                                        status=Ticket.OPEN_STATUS).first()
            


        if not(context['case'].lotus_notes):
            context['vc_case'] = Case.objects.filter(vince_id=context['case'].id).first()

        return context


class NotificationView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    login_url = "vince:login"
    model = VendorNotification
    template_name = 'vince/notification.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vendor.case)
        return False

    def get_queryset(self):
        vendor= get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
        return VendorNotification.objects.filter(vendor=vendor).order_by('-notify_date')

    def get_context_data(self, **kwargs):
        context = super(NotificationView, self).get_context_data(**kwargs)
        vendor= get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
        context['vendor'] = vendor
        context['official_emails'] = vendor.contact.get_official_emails()
        context['notifications'] = VendorNotification.objects.filter(vendor=vendor).order_by('-notify_date')
        context['case'] = vendor.case
        return context

class ApproveAllStatements(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/approve_all.html'
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        return False

    def get_context_data(self, **kwargs):
        context = super(ApproveAllStatements, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['vendors'] = VulnerableVendor.casevendors(context['case']).order_by('vendor')
        return context

    def post(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        vendors = VulnerableVendor.casevendors(case)
        send_email = []
        change_made = False
        for vendor in vendors:
            if not vendor.approved:
                change_made = True
                vendor.approved = True
                vendor.user_approved=self.request.user
                vendor.save()
            #loop through vendor status to approve
            status = VendorStatus.objects.filter(vendor=vendor)
            for s in status:
                if s.approved == False:
                    if s.user:
                        if vendor.contact.id not in send_email:
                            send_email.append(vendor.contact.id)
                    s.approved=True
                    s.user_approved=self.request.user
                    s.save()
                    change_made = True

        comment = f"Approved all statements for vendors for case {case.vutitle}"
        action = CaseAction(case = vendor.case,
                            title = "Approved All Statements",
                            date = timezone.now(),
                            user = self.request.user,
                            comment = comment,
                            action_type=1)
        action.save()
        messages.success(
            self.request,
            _("All statements have been successfully approved."))

        if send_email:
            logger.warning("This would send vendor approval emails")
            #send_vendor_approval_emails(send_email, case)

        if change_made:
            case.changes_to_publish = True
            case.save()

        return redirect("vince:case", case.id)


class NotifyVendor(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    template_name = 'vince/notify_vendor.html'
#    form_class = ChooseVendorForm
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

class RedirectVinny(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/redirect.html'
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RedirectVinny, self).get_context_data(**kwargs)
        next_url = self.request.GET.get('next')
        context['action'] = next_url
        logger.debug("redirecting to: " + next_url)
        return context

class VinnyTokens(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        return JsonResponse({'ACCESS_TOKEN': self.request.session.get('ACCESS_TOKEN'),
                             'REFRESH_TOKEN': self.request.session.get('REFRESH_TOKEN')}, status=200)

class TokenLogin(GetUserMixin, generic.TemplateView):
    template_name = 'vince/index.html'

    def post(self, request, *args, **kwargs):
        logger.debug("in tokenlogin")
        if (token_verify(self.request.POST['access_token'])):
            request.session['ACCESS_TOKEN'] = self.request.POST['access_token']
            request.session['REFRESH_TOKEN'] = self.request.POST['refresh_token']
            #request.session.save()
            groups = self.get_token_groups()
            logger.debug(f"token has groups {groups}")
            if groups:
                if settings.COGNITO_ADMIN_GROUP in groups:
                    user = self.get_user()
                    request.session['timezone'] = user.timezone
                    user = authenticate(self.request, username=user.email)
                    if user:
                        auth_login(request, user)
                        if cognito_check_track_permissions(request):
                            if is_in_group_vincetrack(user):
                                return JsonResponse({'response': 'success'}, status=200)
                        logout(request)
        return JsonResponse({'response': 'Unauthorized', 'error': 'Unauthorized access'}, status=401)


class PushNotification(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = "vince/confirmpush.html"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            notification = get_object_or_404(VendorNotificationContent, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, notification.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(PushNotification, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(VendorNotificationContent, id=self.kwargs['pk'])
        return context

    def post(self, request, *args, **kwargs):
        notification = get_object_or_404(VendorNotificationContent, id=self.kwargs['pk'])
        case = notification.case
        notification.published=True
        notification.published_date=timezone.now()
        notification.save()
        update_vinny_post(case, notification)

        messages.success(
            self.request,
            _("Your post was successfully published."))

        return HttpResponseRedirect(reverse('vince:case', args=[case.id]) + '#posts')


class DeletePostView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = "vince/confirm_delete_post.html"
    
    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            notification = get_object_or_404(VendorNotificationContent, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, notification.case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(DeletePostView, self).get_context_data(**kwargs)
        notification = get_object_or_404(VendorNotificationContent, id=self.kwargs['pk'])
        if notification.published:
            context['error'] = 1
        context['post'] = notification
        return context

    def post(self, request, *args, **kwargs):
        notification = get_object_or_404(VendorNotificationContent, id=self.kwargs['pk'])

        if notification.published:
            messages.error(
                self.request,
                _("You can not remove a published post from this view.  Remove in VINCEComm."))
            
            return HttpResponseRedirect(reverse('vince:case', args=[notification.case.id]) + '#posts')

        case = notification.case
        notification.delete()
        messages.success(
            self.request,
            _("Your post was successfully removed."))

        return HttpResponseRedirect(reverse('vince:case', args=[case.id]) + '#posts')
         
    
class WritePostCRView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    form_class = NewPostForm
    template_name = 'vince/notifycr.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(WritePostCRView, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['cr'] = CaseRequest.objects.filter(case=self.kwargs['pk']).first()
        if 'notify_id' in self.kwargs:
            context['notify_id'] = self.kwargs['notify_id']
            notification = VendorNotificationContent.objects.filter(id=self.kwargs['notify_id']).first()
            if notification:
                form = NewPostForm(instance=notification)
                context['form'] = form
        return context

class WritePost(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    form_class = NewPostForm
    template_name = 'vince/notify.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        else:
            return False

    def form_valid(self, form):
        logger.debug("IN FORM AVALID")
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        if 'notify_id' in self.kwargs:
            notification = VendorNotificationContent.objects.filter(id=self.kwargs['notify_id']).first()
            if notification.version != int(self.request.POST['version']):
                form._errors.setdefault("version", ErrorList([
                    u'Someone beat you to editing this notification. View the most recent version and retry.']))
                return super().form_invalid(form)
            notification.content = form.cleaned_data['content']
            notification.version = notification.version + 1
            notification.user = self.request.user
            # set published mode to False
            notification.published = False
            notification.save()
            title = "Edited Post Draft"
        else:
            #are there other notifications?
            notifs = VendorNotificationContent.objects.filter(case=case).count()

            notification = VendorNotificationContent(content = form.cleaned_data['content'],
                                                     case=case,
                                                     user = self.request.user,
                                                     post=notifs)
            notification.save()
            title = "Created Post Draft"

        action = CaseAction(case = case,
                            notification=notification,
                            title = title,
                            user = self.request.user,
                            date = timezone.now(),
                            comment="",
                            action_type=1)
        action.save()

        artifacts = list(map(int, self.request.POST.getlist('artifacts[]')))
        # record the artifacts that have been added to the notification
        arts =  get_all_artifacts(case)
        for artifact in arts:
            if artifact.id in artifacts:
                artifact.added_to_post = True
            else:
                artifact.added_to_post = False
            artifact.save()

        vincefiles = list(map(int, self.request.POST.getlist('vincefiles[]')))
        for f in vincefiles:
            vf = VinceFile.objects.filter(id=f).first()
            if vf:
                vf.post = notification
                vf.save()
                
        formvuls = list(map(int, self.request.POST.getlist('vuls[]')))
        logger.debug(formvuls)
        vuls = Vulnerability.casevuls(case)
        for vul in vuls:
            if vul.id in formvuls:
                vul.added_to_post = True
            else:
                vul.added_to_post = False
            vul.save()


        return HttpResponseRedirect(reverse('vince:case', args=[case.id]) + '#posts')

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(WritePost, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['artifacts'] = get_all_artifacts(context['case'])
        context['vuls'] = Vulnerability.casevuls(context['case'])
        if 'notify_id' in self.kwargs:
            notification = VendorNotificationContent.objects.filter(id=self.kwargs['notify_id']).first()
            context['edit'] = True
            context['notify_id'] = self.kwargs['notify_id']
            if notification:
                context['files'] = VinceFile.objects.filter(case=context['case'], post=notification)
                form = NewPostForm(instance=notification)
                context['form'] = form
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)



class TagUser(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/usertags.html'
    login_url = 'vince:login'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
            return has_case_write_access(self.request.user, case)
        else:
            return False

    def get(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
        users = CaseAssignment.objects.filter(case=case)
        assignments = []
        for u in users:
            assignments.append(u.assigned.usersettings.vince_username)
        assignable_users = [ u.usersettings.preferred_username for u in User.objects.filter(is_active=True, groups__name='vince')]
        logger.debug(assignable_users);
        return JsonResponse({'response': 'success', 'case_assigned_to': assignments, 'assignable_users': assignable_users}, status=200)

    def post(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
        logger.debug(f"{self.__class__.__name__} post: {request.POST}")
        if (int(request.POST['state']) == 1):
            #get case
            user = User.objects.filter(usersettings__preferred_username=request.POST['tag']).first()
            if user:
                ca = CaseAction(case=case,
                                title=f"User {user.usersettings.preferred_username} assigned to case",
                                user=self.request.user, action_type=1)
                ca.save()
                #do this after the case action, so the assignee doesn't get 2 emails
                assignment = CaseAssignment(assigned=user,
                                            case=case)
                assignment.save()
            else:
                return JsonResponse({'error': 'User does not exist'}, status=401)

            #is this user a part of one of the caseparticipants - otherwise add them
            contacts = user.groups.exclude(groupsettings__contact__isnull=True).values_list('groupsettings__contact__id', flat=True)
            cps = CaseParticipant.objects.filter(case=case).filter(Q(user_name=user.email)|Q(contact__in=contacts))
            logger.debug("CHECK CASE PARTICIPANTS")
            logger.debug(cps)
            if not cps:
                #this user isn't a part of any of the CaseParticipants, so add them now
                cp, created = CaseParticipant.objects.update_or_create(case=case,
                                                              user_name=user.email,
                                                              defaults = {'coordinator':True,
                                                                          'added_by':self.request.user,
                                                                          'added_to_case':timezone.now(),
                                                                          'status':"Notified"})
                add_participant_vinny_case(case, cp)
                    
                    
            send_updatecase_mail(ca, user)

        else:
            # delete user from case
            user = User.objects.filter(usersettings__preferred_username=request.POST['tag']).first()
            if user:
                ca = CaseAction(case=case,
                                title=f"User {user.usersettings.preferred_username} removed from case assignment",
                                user=self.request.user, action_type=1)
                ca.save()
                assignment = CaseAssignment.objects.filter(assigned=user, case=case)
                if assignment:
                    assignment.delete()
            else:
                return JsonResponse({'error': 'User does not exist'}, status=401)

            #was this user a one off assignment (ie not a part of the team of coordinators?
            cp = CaseParticipant.objects.filter(case=case, user_name=user.email, coordinator=True).first()
            if cp:
                remove_participant_vinny_case(case, cp)
                cp.delete()

        return JsonResponse({'response': 'success'}, status=200)


class ChangeParticipantType(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/case_participants.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(CaseParticipant, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        participant = get_object_or_404(CaseParticipant, id=self.kwargs['pk'])
        participant.coordinator = self.request.POST.get('coordinator')
        cm = CaseMember.objects.filter(vince_id = participant.id).first()
        if cm:
            cm.coordinator = participant.coordinator
            cm.save()
        participant.save()
        return JsonResponse({'response': 'success', 'case_id':participant.case.id}, status=200)

class AddParticipantToCase(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/case_participants.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            if 'pk' in self.kwargs:
                case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            if self.request.POST:
                if 'case_id' in self.request.POST:
                    case = get_object_or_404(VulnerabilityCase, id=self.request.POST['case_id'])
            return has_case_write_access(self.request.user, case)
        return False

    def get_context_data(self, **kwargs):
        context = super(AddParticipantToCase, self).get_context_data(**kwargs)
        if 'pk' in self.kwargs:
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            context['participants'] = CaseParticipant.objects.filter(case=case)
            context['case'] = case
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        case = get_object_or_404(VulnerabilityCase, id=request.POST['case_id'])
        users = request.POST.getlist('users[]')

        for user in users:
            if user.startswith('Group:'):
                groupname = user[7:]
                logger.debug(groupname)
                group = ContactGroup.objects.filter(name=groupname).first()
                members = GroupMember.objects.filter(group__name=groupname)
                for member in members:
                    print(member.contact)
                    if member.contact:
                        cp = CaseParticipant.objects.update_or_create(case = case,
                                                                      group=True,
                                                                      user_name=member.contact.vendor_name,
                                                                      defaults = {'added_by': self.request.user})
                ca = CaseAction(case=case, title=f"Added Group {groupname} to Case",
                                user=self.request.user, action_type=1)
                ca.save()
                groupdups = GroupMember.objects.filter(group=group).values_list('group_member', flat=True)
                duplicates = GroupDuplicate.objects.filter(group__in=groupdups).values_list('group', flat=True)
                #these are the subgroups
                groupmembers = ContactGroup.objects.filter(id__in=duplicates)
                for subgroup in groupmembers:
                    members = GroupMember.objects.filter(group__name=subgroup.name)
                    for member in members:
                        print(member.contact)
                        if member.contact:
                            cp = CaseParticipant.objects.update_or_create(case = case,
                                                                          group=True,
                                                                          user_name=member.contact.vendor_name,
                                                                          defaults = {'added_by': self.request.user})
                    ca = CaseAction(case=case, title=f"Added Group {subgroup.name} to Case",
                                    user=self.request.user, action_type=1)
                    ca.save()


            else:
                #search vincecomm user:
                vc_user = User.objects.using('vincecomm').filter(username=user).first()
                if vc_user:
                    cp = CaseParticipant.objects.update_or_create(case = case,
                                                                  user_name=user,
                                                                  defaults = {
                                                                      'added_by':self.request.user})
                    ca = CaseAction(case=case, title=f"Added Participant {vc_user.username} to Case",
                                    user=self.request.user, action_type=1)
                    ca.save()
                else:
                    #search contacts
                    contact = Contact.objects.filter(vendor_name=user).first()
                    if contact:
                        cp = CaseParticipant.objects.update_or_create(case = case,
                                                                      user_name=user,
                                                                      contact=contact,
                                                                      defaults = {
                                                                          'group':True,
                                                                          'added_by':self.request.user})
                        ca = CaseAction(case=case, title=f"Added Participant Group {user} to Case",
                                        user=self.request.user, action_type=1)
                        ca.save()
                    else:
                        # this is a new user we are inviting
                        cp = CaseParticipant.objects.update_or_create(case = case,
                                                                      user_name=user,
                                                                      defaults= {
                                                                          'added_by':self.request.user})
                        ca = CaseAction(case=case, title=f"Invited New Participant {user} to Case",
                                        user=self.request.user, action_type=1)
                        ca.save()


        return JsonResponse({'response': 'success'}, status=200)

class NotifyVendorsListView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/include/vendors.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        return False

    def get_context_data(self, **kwargs):
        context = super(NotifyVendorsListView, self).get_context_data(**kwargs)
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['vendors'] = VulnerableVendor.casevendors(case=case).order_by('vendor')
        return context


class ChangeVendorNotifyDate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vendor.case)
        return False

    def post(self, request, *args, **kwargs):
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
        logger.debug(self.request.POST)
        new_date = self.request.POST.get('new_date')
        if new_date:
            vendor.contact_date = new_date
            vendor.save()

        return JsonResponse({'status': 'done'}, status = 200)

class ConfirmVendorNotifyDate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/confirm_notify_date.html"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vendor.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
        context = {}
        context['vendor'] = vendor
        context['new_date'] = self.request.POST.get("new_date")
        first_notify_date = VendorNotification.objects.filter(vendor=vendor).order_by('notify_date')
        logger.debug(first_notify_date)
        if first_notify_date:
            context['first_notify_date'] = first_notify_date[0]

        return render(request, self.template_name, context)

def add_vendor_to_case(case, contact, user, group=None):
    alert_tags = TagManager.objects.filter(tag_type=2, alert_on_add=True).values_list('tag', flat=True)
    old_vendor = VulnerableVendor.objects.filter(case=case,
                                                 contact=contact).first()
    if old_vendor == None:
        if contact.active:
            vv = VulnerableVendor(case=case,
                                  contact=contact,
                                  added_by=user,
                                  vendor=contact.vendor_name)
            if group:
                vv.from_group=group
            vv.save()

            # is this vendor tagged?
            if contact.contacttag_set.count() > 0:
                ctags = contact.contacttag_set.values_list('tag', flat=True)
                alert = list(set(ctags) & set(alert_tags))
                if alert:
                    #cut a ticket with dependency
                    queue = get_case_case_queue(case)
                    ticket = Ticket(title = f"Tagged Vendor {contact.vendor_name} added to case",
                                    created = timezone.now(),
                                    status = Ticket.OPEN_STATUS,
                                    queue = queue,
                                    assigned_to = user,
                                    submitter_email = user.email,
                                    case = case,
                                    description = f"Tagged Vendor {contact.vendor_name} added to Case by by {user.usersettings.preferred_username} - investigate before notifying. TAGS: {alert}")
                    ticket.save()
                    dep = CaseDependency.objects.update_or_create(case=case, depends_on=ticket)
                    vv.tagged = ticket
                    vv.save()
        else:
            # don't add inactive vendors
            return False
    elif old_vendor:
        if old_vendor.deleted:
            old_vendor.deleted=False
            if group:
                old_vendor.from_group=group
            old_vendor.save()
            # is this vendor tagged?
            if contact.contacttag_set.count() > 0:
                logger.debug(old_vendor.tagged)
                if old_vendor.tagged:
                    logger.debug("JUST SETTING THIS TICKET TO OPEN!")
                    # this vendor was already tagged, just repopen it
                    old_vendor.tagged.status=Ticket.OPEN_STATUS
                    old_vendor.tagged.save()
                    return True
                ctags = contact.contacttag_set.values_list('tag', flat=True)
                alert = list(set(ctags) & set(alert_tags))
                if alert:
                    #cut a ticket with dependency
                    queue = get_case_case_queue(case)
                    ticket = Ticket(title = f"Tagged Vendor {contact.vendor_name} added to case",
                                    created = timezone.now(),
                                    status = Ticket.OPEN_STATUS,
                                    queue = queue,
                                    submitter_email = user.email,
                                    assigned_to = user,
                                    case = case,
                                    description = f"Tagged Vendor {contact.vendor_name} added to Case by {user.usersettings.preferred_username} - investigate before notifying. TAGS: {alert}")
                    ticket.save()
                    dep = CaseDependency.objects.update_or_create(case=case, depends_on=ticket)
                    old_vendor.tagged = ticket
                    old_vendor.save()
            return True
        # vendor is already a part of the case
        return False
    return True




def get_vendors_in_subgroup(group):
    contacts = []
    groupdups = GroupMember.objects.filter(group=group).values_list('group_member', flat=True)
    duplicates = GroupDuplicate.objects.filter(group__in=groupdups).values_list('group', flat=True)
    groupmembers = ContactGroup.objects.filter(id__in=duplicates)
    for subgroup in groupmembers:
        members = GroupMember.objects.filter(group__name=subgroup.name)
        for member in members:
            if member.contact:
                contacts.append(member.contact)
            else:
                contacts.extend(get_vendors_in_subgroup(member.group))
    return contacts


class CaseVendors(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/casevendors.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        return False

    def get_context_data(self, **kwargs):
        context = super(CaseVendors, self).get_context_data(**kwargs)
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['vendors'] = VulnerableVendor.casevendors(case).order_by('vendor')
        context['vendorsjs'] = [obj.as_dict() for obj in context['vendors']]

        zero_user_vendors = 0
        #update dictionary to show which vendor group has active users
        for vjs in context['vendorsjs']:
            cid = vjs['contact_id']
            vc_contact = VinceCommContact.objects.using('vincecomm').filter(vendor_id=cid).first()
            if vc_contact:
                groupcontact = GroupContact.objects.using('vincecomm').filter(contact=vc_contact).first()
                if groupcontact:
                    count = User.objects.using('vincecomm').filter(groups=groupcontact.group).count()
                    if count == 0:
                        zero_user_vendors += 1
                    vjs.update({'users':count})
                    continue
            vjs.update({'users': 0})
            zero_user_vendors += 1

        context['zero_user_vendors'] = zero_user_vendors

        context['case'] = case
        return context

class AddVendorToCase(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/addvendor.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            if self.request.POST:
                case = get_object_or_404(VulnerabilityCase, id=self.request.POST['case_id'])
                return has_case_write_access(self.request.user, case)
            return True
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        case = get_object_or_404(VulnerabilityCase, id=request.POST['case_id'])
        vendors = request.POST.getlist('vendors[]')
        error = False
        contacts_added = []
        contacts_rejected = []
        for vendor in vendors:
            if vendor.startswith('Group:'):
                groupname = vendor[7:]
                logger.debug(groupname)
                group = ContactGroup.objects.filter(name=groupname).first()
                members = GroupMember.objects.filter(group__name=groupname)
                for member in members:
                    print(member.contact)
                    if member.contact:
                        if (add_vendor_to_case(case, member.contact, self.request.user, group)):
                            contacts_added.append(member.contact.vendor_name)
                        else:
                            contacts_rejected.append(member.contact.vendor_name)
                more_contacts = get_vendors_in_subgroup(group)
                for contact in more_contacts:
                    if (add_vendor_to_case(case, contact, self.request.user, group)):
                        contacts_added.append(contact.vendor_name)
                    else:
                        contacts_rejected.append(contact.vendor_name)
                        
            else:
                contact = Contact.objects.filter(vendor_name=vendor)
                if not contact:
                    error = vendor
                for c in contact:
                    if (add_vendor_to_case(case, c, self.request.user)):
                        contacts_added.append(c.vendor_name)
                    else:
                        contacts_rejected.append(c.vendor_name)
        contactsstr = ", ".join(contacts_added)
        ca = CaseAction(case=case, title=f"Added {len(contacts_added)} Vendors to Case",
                        comment = f"{contactsstr}",
                        user=self.request.user,
                        action_type=1)
        ca.save()
        if error:
            return JsonResponse({'status':'false', 'message': f'Could not find matching vendor name {error}.'}, status=400)

        if contacts_rejected:
            return JsonResponse({'status':'false', 'message': f'Will not add the following vendors due to inactive status or previously added to the case: {(", ").join(contacts_rejected)}'}, status=400)
        return JsonResponse({'response': 'success'}, status=200)

class VendorVulStatement(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    template_name = 'vince/include/statement.html'
    login_url = "vince:login"
    form_class=VendorVulStatementForm

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['vendor_id'])
            return has_case_write_access(self.request.user, vendor.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = VendorVulStatementForm(request.POST)

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        logger.debug("IN VENDOR VUL STMT")
        logger.debug(self.request.POST)
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['vendor_id'])
        vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        status = VendorStatus.objects.filter(vul=vul, vendor=vendor).first()
        if status:
            if status.references != form.cleaned_data["references"]:
                status.references = form.cleaned_data["references"]
                status.user = self.request.user.username
                vendor.case.changes_to_publish = True
                vendor.case.save()
            if status.statement != form.cleaned_data["statement"]:
                status.statement = form.cleaned_data["statement"]
                status.user = self.request.user.username
                vendor.case.changes_to_publish = True
                vendor.case.save()
            status.save()
        else:
            status = VendorStatus(vul=vul,
                                  vendor=vendor,
                                  user=self.request.user.username,
                                  status=VendorStatus.UNKNOWN_STATUS,
                                  references=form.cleaned_data["references"],
                                  statement=form.cleaned_data["statement"],
                                  approved=True,
                                  user_approved=self.request.user)
            status.save()
            vendor.case.changes_to_publish = True
            vendor.case.save()

        # now modify statement in vincecomm
        #update_status(status, self.request.user)

        messages.success(
            self.request,
            _("Got it! Your statement has been recorded."))
        return JsonResponse({'response': 'success'}, status=200)

    def get_context_data(self, **kwargs):
        context = super(VendorVulStatement, self).get_context_data(**kwargs)
        logger.debug("IN HERE")
        logger.debug(self.kwargs)
        vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        status = VendorStatus.objects.filter(vul=vul, vendor=self.kwargs['vendor_id']).first()
        if status:
            initial = {'statement': status.statement, 'references':status.references}
        else:
            initial = {}
        form = VendorVulStatementForm(initial=initial)
        context['form'] = form
        context['title'] = "Provide Statement"
        context['action'] = reverse('vince:getvulstmt', args=[self.kwargs['vendor_id'], self.kwargs['pk']])

        return context


def update_status(vendor, request):
    logger.debug(request.POST)
    affected = request.POST.getlist('affected')
    unknown = request.POST.getlist('unknown')
    unaffected = request.POST.getlist('unaffected')
    # get vc user:
    vcuser = User.objects.using('vincecomm').filter(username=request.user.username).first()
    if affected:
        for vul in affected:
            logger.debug(int(vul))
            vul_obj = Vulnerability.objects.filter(id=int(vul)).first()
            status = VendorStatus.objects.update_or_create(vendor=vendor, vul=vul_obj,
                                                           defaults={'status':1, 'user_approved':request.user, 'approved':True,
                                                                     'user':request.user.username})
            cv = CaseVulnerability.objects.filter(vince_id=int(vul)).first()
            member = get_casemember_from_vc(vendor, vul_obj.case)
            logger.debug(cv)
            if member:
                status = CaseMemberStatus.objects.update_or_create(member=member, vulnerability=cv,
                                                                   defaults={'status':1, 'user':vcuser})
    if unknown:
        for vul in unknown:
            vul_obj = Vulnerability.objects.filter(id=int(vul)).first()
            status = VendorStatus.objects.update_or_create(vendor=vendor, vul=vul_obj,
                                                           defaults={'status':3, 'user_approved':request.user, 'approved':True,
                                                                     'user':request.user.username})
            member = get_casemember_from_vc(vendor, vul_obj.case)
            cv = CaseVulnerability.objects.filter(vince_id=int(vul)).first()
            if member:
                status = CaseMemberStatus.objects.update_or_create(member=member, vulnerability=cv,
                                                                   defaults={'status':3, 'user':vcuser})
    if unaffected:
        for vul in unaffected:
            vul_obj = Vulnerability.objects.filter(id=int(vul)).first()
            status = VendorStatus.objects.update_or_create(vendor=vendor, vul=vul_obj,
                                                           defaults={'status':2, 'user_approved':request.user, 'approved':True,
                                                                     'user':request.user.username})
            cv = CaseVulnerability.objects.filter(vince_id=int(vul)).first()
            member = get_casemember_from_vc(vendor, vul_obj.case)
            if member:
                status = CaseMemberStatus.objects.update_or_create(member=member, vulnerability=cv,
                                                                   defaults={'status':2, 'user':vcuser})


class EditVendorStatusView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    template_name = 'vince/editvendorstatus.html'
    model = VulnerableVendor
    form_class = StatementForm

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vendor.case)
        return False

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        logger.debug(self.request.POST)
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
        update_status(vendor, self.request)
        change = True
        old_references = None
        old_statement = None
        old_addendum = None
        nochanges = all([vendor.references == form.cleaned_data["references"],
                         vendor.statement == form.cleaned_data["statement"],
                         vendor.addendum == form.cleaned_data["addendum"]])
        if nochanges:
            change = False
        else:
            old_statement = vendor.statement
            old_references = vendor.references
            old_addendum = vendor.addendum
            
        vendor.references = form.cleaned_data["references"]
        vendor.statement = form.cleaned_data["statement"]
        vendor.addendum = form.cleaned_data["addendum"]
        vendor.statement_date = form.cleaned_data['statement_date']
        if form.cleaned_data['share']:
            vendor.share = True

        #auto approve
        vendor.approved = True
        vendor.user_approved = self.request.user
        vendor.save()

        if not(vendor.case.lotus_notes):
            vcuser = User.objects.using('vincecomm').filter(username=self.request.user).first()
            member = get_casemember_from_vc(vendor, vendor.case)
            if member:
                stmt, created = CaseStatement.objects.update_or_create(member=member, case=member.case,
                                                                       defaults={'references': form.cleaned_data["references"],
                                                                                 'statement': form.cleaned_data["statement"],
                                                                                 "addendum": form.cleaned_data["addendum"]})
                if created:
                    if stmt.statement:
                        va = VendorAction(member=member, user=vcuser,
	                                  case=member.case,
                                          title=f"Coordinator created case statement")
                        va.save()
                        vs = VendorStatusChange(action=va, field="statement", new_value=stmt.statement)
                        vs.save()
                    if stmt.references:
                        va = VendorAction(member=member, user=vcuser,
                                          case=member.case,
                                          title=f"Coordinator added case references")
                        va.save()
                        vs = VendorStatusChange(action=va, field="references", new_value=stmt.references)
                        vs.save()
                    if stmt.addendum:
                        va = VendorAction(member=member, user=vcuser,
                                          case=member.case,
                                          title=f"Coordinator added addendum")
                        va.save()
                        vs = VendorStatusChange(action=va, field="addendum", new_value=stmt.addendum)
                        vs.save()
                            
                elif change:
                    #reset share if we made a change
                    stmt.share = False
                    stmt.save()
                    if old_statement != stmt.statement:
                        va = VendorAction(member=member, user=vcuser,
                                          case=member.case,
                                          title=f"Coordinator updated case statement")
                        va.save()
                        vs = VendorStatusChange(action=va, field="statement", old_value=old_statement, new_value=stmt.statement)
                        vs.save()
                    if old_references != stmt.references:
                        va = VendorAction(member=member, user=vcuser,
                                          case=member.case,
                                          title=f"Coordinator updated references")
                        va.save()
                        vs = VendorStatusChange(action=va, field="references", old_value=old_references, new_value=stmt.references)
                        vs.save()
                    if old_addendum != stmt.addendum:
                        va = VendorAction(member=member, user=vcuser,
                                          case=member.case,
                                          title=f"Coordinator updated addendum")
                        va.save()
                        vs = VendorStatusChange(action=va, field="addendum", old_value=old_addendum, new_value=stmt.addendum)
                        vs.save()

        vendor.case.changes_to_publish = True
        vendor.case.save()

        messages.success(
            self.request,
            _("Got it! The status and statement have been updated."))
        return redirect("vince:vendorstatus", vendor.id)


    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = StatementForm(request.POST)

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(EditVendorStatusView, self).get_context_data(**kwargs)
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
        context['case'] = vendor.case
        context['vuls'] = Vulnerability.casevuls(vendor.case)
        context['status'] = VendorStatus.objects.filter(vul__in=context['vuls'], vendor=vendor)
        if context['status']:
            context['date_added'] = context['status'].order_by('date_added')[0].date_added
            context['date_modified'] = context['status'].order_by('-date_modified')[0].date_modified
            context['initial_user'] = context['status'].order_by('date_added')[0].user
            context['modified_user'] = context['status'].order_by('-date_modified')[0].user

        initial={'statement':vendor.statement, 'references':vendor.references,
                 'share':vendor.share, 'addendum':vendor.addendum,
                 'statement_date':vendor.statement_date}

        context['form'] = StatementForm(initial=initial)
        context['vendor'] = vendor
        return context


class VendorStatusChangesView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    login_url = "vince:login"
    template_name = "vince/vendorstatuschanges.html"
    model = VulnerableVendor

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vendor.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(VendorStatusChangesView, self).get_context_data(**kwargs)

        vendor = VulnerableVendor.objects.filter(id=self.kwargs['pk']).first()

        member = get_casemember_from_vc(vendor, vendor.case)

        #vincecomm_models
        actions = VendorAction.objects.filter(case=member.case).filter(member=member).values_list('id', flat=True)
        context['activity'] = VendorStatusChange.objects.filter(action__in=actions).order_by("-action__created")
        context['case'] = vendor.case

        return context


class VendorStatusView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    login_url = 'vince:login'
    template_name = 'vince/vendorstatus.html'
    model = VulnerableVendor

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vendor.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(VendorStatusView, self).get_context_data(**kwargs)
        vendor = VulnerableVendor.objects.filter(id=self.kwargs['pk']).first()
        context['vuls'] = Vulnerability.casevuls(vendor.case)
        context['status'] = VendorStatus.objects.filter(vul__in=context['vuls'], vendor=vendor)
        if context['status']:
            context['date_added'] = context['status'].order_by('date_added')[0].date_added
            context['date_modified'] = context['status'].order_by('-date_modified')[0].date_modified
            context['initial_user'] = context['status'].order_by('date_added')[0].user
            context['modified_user'] = context['status'].order_by('-date_modified')[0].user
        context['case'] = vendor.case
        return context

class VendorStatusModalView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    login_url = 'vince:login'
    template_name = 'vince/vendorstatusmodal.html'
    model = VulnerableVendor

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vendor.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(VendorStatusModalView, self).get_context_data(**kwargs)
        vendor = VulnerableVendor.objects.filter(id=self.kwargs['pk']).first()
        context['vendor'] = vendor
        context['vuls'] = Vulnerability.casevuls(vendor.case)
        context['status'] = VendorStatus.objects.filter(vul__in=context['vuls'], vendor=vendor)
        if context['status']:
            context['date_added'] = context['status'].order_by('date_added')[0].date_added
            context['date_modified'] = context['status'].order_by('-date_modified')[0].date_modified
            context['initial_user'] = context['status'].order_by('date_added')[0].user
            context['modified_user'] = context['status'].order_by('-date_modified')[0].user
        context['case'] = vendor.case
        return context


class ConfirmRemoveParticipant(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/remove_participant.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            cp = get_object_or_404(CaseParticipant, id=self.kwargs['cp'])
            return has_case_write_access(self.request.user, cp.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(ConfirmRemoveParticipant, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(CaseParticipant, id=self.kwargs['cp'])
        context['action'] = reverse('vince:rmparticipant', args=[self.kwargs['cp']])
        return context

    def post(self, request, *args, **kwargs):
        cp = get_object_or_404(CaseParticipant, id=self.kwargs['cp'])
        self.case = cp.case.id
        ca = CaseAction(case=cp.case, title="Removed Participant from Case",
                        comment="Participant %s removed from case" % cp.user_name,
                        user=self.request.user, action_type=1)
        ca.save()
        remove_participant_vinny_case(cp.case, cp)
        cp.delete()
        messages.success(
            self.request,
            _("Participant successfully removed from case."))
        return HttpResponseRedirect(reverse('vince:case', args=[self.case]) + '#participants')


class RemoveParticipantFromCase(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name='vince/notmpl.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            cp = get_object_or_404(CaseParticipant, id=self.kwargs['cp'])
            return has_case_write_access(self.request.user, cp.case)
        return False

    def get(self, request, *args, **kwargs):
        cp = get_object_or_404(CaseParticipant, id=self.kwargs['cp'])
        logger.debug("HEREEEEEEEE")

        self.case = cp.case.id
        ca = CaseAction(case=cp.case, title="Removed Participant from Case",
                        comment="Participant %s removed from case" % cp.user_name,
                        user=self.request.user, action_type=1)
        ca.save()
        remove_participant_vinny_case(cp.case, cp)

        cp.delete()
        messages.success(
	    self.request,
            _("Participant successfully removed from case."))
        return JsonResponse({'status':'success'}, status=200)


class NotifyParticipant(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    form_class = NotificationForm
    template_name = 'vince/notify_participant.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            cp = get_object_or_404(CaseParticipant, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, cp.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        case = get_object_or_404(CaseParticipant, id=self.kwargs['pk'])
        form = NotificationForm(self.request.POST)
        templates = EmailTemplate.objects.filter(body_only=True)
        form.fields['email_template'].choices = [('', '--------')] + [(q.id, q.template_name) for q in templates]

        if form.is_valid():
            try:
                form.save(cp=case)
            except:
                logger.debug(traceback.format_exc())
                messages.error(
                    request,
                    _(f"Invalid Email address: SMTP Recipients Refused {case.user_name}"))
            return HttpResponseRedirect(reverse('vince:case', args=[case.case.id])+"#participants")
        else:
            messages.error(
                request,
                _(f"Invalid Request {form.errors}"))
        return HttpResponseRedirect(reverse('vince:case', args=[case.case.id])+"#participants")

    def get_context_data(self, **kwargs):
        context = super(NotifyParticipant, self).get_context_data(**kwargs)
        context['cp'] = get_object_or_404(CaseParticipant, id=self.kwargs['pk'])
        templates = EmailTemplate.objects.filter(locale="en", body_only=True)
        default_tmpl = EmailTemplate.objects.filter(template_name='default_participant').first()
        initial = {'title': f"{context['cp'].case.vu_vuid}: Invitation to Participate in Vulnerability Coordination"}

        if context['cp'].case.template:
            initial['email_body'] = context['cp'].case.template.participant_email
        elif default_tmpl:
            initial['email_body'] = default_tmpl.plain_text
            initial['title'] =  f"{context['cp'].case.vu_vuid}: {default_tmpl.subject}"

        context['form'] = NotificationForm(initial=initial)
        if default_tmpl:
            templates = templates.exclude(id=default_tmpl.id)
            context['form'].fields['email_template'].choices = [(default_tmpl.id, default_tmpl.template_name)] + [(q.id, q.template_name) for q in templates]
        else:
            context['form'].fields['email_template'].choices = [('', '--------')] + [(q.id, q.template_name) for q in templates]

        context['title'] = f"Notify Participant {context['cp'].user_name}"
        context['action'] = reverse('vince:notify_participant', args=[self.kwargs['pk']])
        if context['cp'].case.case_request:
            cr = CaseRequest.objects.filter(id=context['cp'].case.case_request.id).first()
            if cr:
                if cr.share_release == False:
                    context['warning'] = True

        return context

class ConfirmRemoveAllVendorsFromCase(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/remove_all_vendors.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser:
            return True
        return False

    def get_context_data(self, **kwargs):
        context = super(ConfirmRemoveAllVendorsFromCase, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['action'] = reverse('vince:rmallvendors', args=[self.kwargs['pk']])
        return context

    def post(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        allvendors = VulnerableVendor.objects.filter(case=case)
        for vendor in allvendors:
            if vendor.contact_date:
                vendor.deleted = True
                vendor.save()
            else:
                vendor.delete()
            remove_vendor_vinny_case(case, vendor.contact, self.request.user)
        ca = CaseAction(case=case, title=f"All vendors removed from case",
                        user=self.request.user,
                        action_type=1)
        ca.save()
        messages.success(
	    self.request,
            _("All vendors successfully removed from case."))
        return HttpResponseRedirect(reverse('vince:editvendorlist', args=[case.id]))

class ConfirmRemoveVendorFromCase(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/remove_vendor.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['vendor'])
            return has_case_write_access(self.request.user, vendor.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(ConfirmRemoveVendorFromCase, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(VulnerableVendor, id=self.kwargs['vendor'])
        context['action'] = reverse('vince:rmvendorconfirm', args=[self.kwargs['vendor']])
        return context

    def post(self, request, *args, **kwargs):
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['vendor'])
        case = vendor.case
        vendor_name = vendor.contact.vendor_name
        try:
            if vendor.contact_date:
                #this vendor has already been contacted so just deleted = True
                vendor.deleted = True
                vendor.save()
            else:
                vendor.delete()
        except:
            # vulnote doesn't exist.
            vendor.delete()
            
        ca = CaseAction(case=case, title=f"Removed Vendor {vendor_name} from Case",
                        user=self.request.user,
                        action_type=1)
        ca.save()
        remove_vendor_vinny_case(case, vendor.contact, self.request.user)
        #messages.success(
	#    self.request,
        #    _("Vendor successfully removed from case."))
        return JsonResponse({'status':'success'}, status=200)
    #return HttpResponseRedirect(reverse('vince:editvendorlist', args=[case.id]))


class RemoveVendorFromCase(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['vendor'])
            return has_case_write_access(self.request.user, vendor.case)
        return False

    def dispatch(self, request, *args, **kwargs):
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['vendor'])
        case = vendor.case
        if vendor.case.published or vendor.case.publicdate:
            vendor.deleted = True
            vendor.save()
        else:
            vendor.delete()
        remove_vendor_vinny_case(case, vendor.contact, self.request.user)
        messages.success(
	    self.request,
            _("Vendor successfully removed from case."))
        return redirect("vince:editvendorlist", case.id)

class NotifyVendorFormView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = "vince:login"
    template_name="vince/notify_vendor.html"
    form_class=VendorNotificationForm

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        vendors = self.request.POST.getlist('vendors[]')
        logger.debug(vendors)
        vendors = VulnerableVendor.objects.filter(id__in=vendors).order_by('vendor')
        initial = {'subject': f"{case.vu_vuid}: New Vulnerability Report"}
        if case.template:
            initial['email_body'] = case.template.vendor_email
        else:
            initial['email_body'] = settings.STANDARD_VENDOR_EMAIL
        form = VendorNotificationForm(initial=initial)
        templates = EmailTemplate.objects.filter(body_only=True)
        vendors_seen = vendors.filter(seen=True)
        form.fields['email_template'].choices = [('', '--------')] + [(q.id, q.template_name) for q in templates]
        return render(request, self.template_name, {'vendors': vendors, 'vn_form': form, 'case': case, 'vendors_seen':vendors_seen})

"""
THIS IS WHERE THE OFFICIAL NOTIFICATION HAPPENS
"""
class EditVendorCaseList(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = "vince:login"
    template_name="vince/vendors.html"
    form_class=VendorNotificationForm

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        logger.debug("IN EDITVENDORCASELIST")
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        form = VendorNotificationForm(self.request.POST)
        templates = EmailTemplate.objects.filter(body_only=True)
        form.fields['email_template'].choices = [('', '--------')] + [(q.id, q.template_name) for q in templates]
        if form.is_valid():
            logger.debug("form is valid")
            vendors = self.request.POST.get('vendors')
            logger.debug(vendors)
            vendors = vendors.split(',')
            logger.debug(vendors)
            context = {'case': case.vuid, 'user': self.request.user.get_username() }
            email = form.save(user=self.request.user)

            contacts = []
            contact_names = []
            for vendor in vendors:
                vendor = VulnerableVendor.objects.filter(contact=vendor, case=case).first()
                add_vendor_vinny_case(case, vendor.contact, self.request.user)
                if vendor.contact_date == None:
                    vendor.contact_date = timezone.now()
                    vendor.save()
                #contacts.append(vendor.contact.id)
                contact_names.append(vendor.contact.vendor_name)
                new_notification = VendorNotification(vendor = vendor,
                                                      emails = ",".join(vendor.contact.get_official_emails()),
                                                      notification=email,
                                                      user=self.request.user)
                new_notification.save()
                #signal on post save that will trigger sns to vinceworker, that will
                #send the email notification to the vendor contacts

            #TODO - change this
            #send_vendor_email_notification(contacts, case, form.cleaned_data['subject'], form.cleaned_data['email_body'])


            comment = "Notified the following vendors of the case: " + "\n ".join(contact_names)
            ca = CaseAction(case=case, title=f"Notified Vendors of Case",
                            user=self.request.user,
                            action_type=1, comment=comment)
            ca.save()

            return JsonResponse({'response': 'success'}, status=200)
        else:
            logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
            return super().form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(EditVendorCaseList, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['vendors'] = VulnerableVendor.casevendors(context['case']).order_by('vendor')
        initial = {'subject': f"{context['case'].vu_vuid}: New Vulnerability Report"}
        if context['case'].template:
            initial['email_body'] = context['case'].template.vendor_email
        else:
            initial['email_body'] = settings.STANDARD_VENDOR_EMAIL
        context['form'] = VendorNotificationForm(initial=initial)
        return context



class AddTicketDependency(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    template_name = "vince/ticket_add_dependency.html"
    form_class = TicketDependencyForm

    def	test_func(self):
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        return is_in_group_vincetrack(self.request.user) and has_queue_write_access(self.request.user, ticket.queue)

    def post(self, request, *args, **kwargs):
        ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        form = TicketDependencyForm(request.POST)
        if form.is_valid():
            ticketdependency = form.save(commit=False)
            ticketdependency.ticket = ticket
            if ticketdependency.ticket != ticketdependency.depends_on:
                ticketdependency.save()
            return HttpResponseRedirect(reverse('vince:ticket', args=[ticket.id]))

    def get_context_data(self, **kwargs):
        context = super(AddTicketDependency, self).get_context_data(**kwargs)
        context['form'] = TicketDependencyForm()
        context['ticket'] = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
        context['action'] = reverse("vince:adddep", args=[self.kwargs['ticket_id']])
        return context

class RemoveCaseArtifact(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = "vince/delete_artifact.html"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            artifact = get_object_or_404(CaseArtifact, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, artifact.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(RemoveCaseArtifact, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(CaseArtifact, id=self.kwargs['pk'])
        context['action'] = reverse('vince:rmcase_artifact', args=[self.kwargs['pk']])
        return context

    def post(self, request, *args, **kwargs):
        artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
        # is this artifact public?
        case_id = artifact.get_related_case().id
        attachment = artifact.get_related_attachment()
        ca = CaseAction(case=artifact.get_related_case(),
                        user=self.request.user,
                        title=f"deleted artifact {artifact.title}",
                        action_type=1)
        ca.save()
        if attachment:
            if attachment.public:
                vinny_case = Case.objects.filter(vince_id = artifact.get_related_case().id).first()
                if vinny_case:
                    # this is public so need to remove from vincecomm
                    vc_attach = VinceCommCaseAttachment.objects.filter(vince_id=attachment.id,
                                                                       action__case=vinny_case).first()
                    if vc_attach:
                        vc_attach.delete()

        artifact.delete()
        return redirect("vince:case", case_id)

class RemoveTicketArtifact(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = "vince/delete_artifact.html"

    def	test_func(self):
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        return is_in_group_vincetrack(self.request.user) and has_queue_write_access(self.request.user, ticket.queue)

    def get_context_data(self, **kwargs):
        context = super(RemoveTicketArtifact, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(Artifact, id=self.kwargs['artifact'])
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        context['action'] = reverse('vince:rmartifact', args=[self.kwargs['pk'], self.kwargs['artifact']])
        return context

    def post(self, request, *args, **kwargs):
        artifact = get_object_or_404(Artifact, id=self.kwargs['artifact'])
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        fup = FollowUp(title=f'deleted artifact {artifact.title}',
                       ticket=ticket, user=self.request.user)
        fup.save()
        artifact.delete()
        return redirect("vince:ticket", ticket.id)


class MakeTicketArtifactPublic(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/share_artifact.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
            if artifact.get_related_ticket():
                ticket = artifact.get_related_ticket()
                return has_queue_write_access(self.request.user, ticket.queue)
            elif artifact.get_related_case():
                return has_case_write_access(self.request.user, artifact.get_related_case())
        return False

    def get_context_data(self, **kwargs):
        context = super(MakeTicketArtifactPublic, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(Artifact, id=self.kwargs['pk'])
        context['action'] = reverse('vince:maketktpublic', args=[self.kwargs['pk']])
        context['public'] = context['object'].get_related_attachment().public
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
        case = artifact.get_related_case()
        return make_artifact_public(request, artifact, case)

class MakeArtifactPublic(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/share_artifact.html'

    def get_context_data(self, **kwargs):
        context = super(MakeArtifactPublic, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(Artifact, id=self.kwargs['pk'])
        context['action'] = reverse('vince:makepublic', args=[self.kwargs['pk']])
        context['public'] = context['object'].get_related_attachment().public
        return context

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
            if artifact.get_related_ticket():
                ticket = artifact.get_related_ticket()
                return has_queue_write_access(self.request.user, ticket.queue)
            elif artifact.get_related_case():
                return has_case_write_access(self.request.user, artifact.get_related_case())
        else:
            return False

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        artifact = get_object_or_404(CaseArtifact, id=self.kwargs['pk'])
        case = artifact.case
        return make_artifact_public(request, artifact, case)


def make_artifact_public(request, artifact, case):
    attachment = artifact.get_related_attachment()

    case_id = 0
    if case:
        case_id = case.id
    else:
        ticket = artifact.get_related_ticket()
        if ticket:
            if ticket.case:
                case_id = ticket.case.id
                case = ticket.case
    if case_id == 0:
        messages.error(
            request,
            _("Can't find related case for this artifact"))
        if ticket:
            return redirect('vince:ticket', ticket.id)
        else:
            return redirect('vince:dashboard')

    vinny_case = Case.objects.filter(vince_id = case_id).first()
    if attachment.public:
        # remove it
        vcattach = VinceCommCaseAttachment.objects.filter(action__case=vinny_case,
                                                          vince_id=attachment.id)
        for rm_case in vcattach:
            #this will actually remove the file, then the vinceattachment, and
            # by cascade the vincecommcaseattachment
            if rm_case.file:
                rm_case.file.file.delete(save=False)
                rm_case.file.delete()
            else:
                rm_case.delete()

            attachment.public=False
            attachment.save()
            ca = CaseAction(case=case,
                            title="Removed artifact from VinceComm",
                            date=timezone.now(),
                            comment="Removed artifact",
                            user = request.user,
                            artifact=artifact,
                            action_type=1)
            ca.save()
        if len(vcattach) == 0:
            attachment.public = False
            attachment.save()
            messages.error(
                request,
                _("That artifact isn't available in vincecomm"))
            return redirect('vince:case', case_id)
        messages.success(
            request,
            _("Artifact successfully removed"))
    else:
        # addit
        if attachment:

            copy_source = {'Bucket': settings.PRIVATE_BUCKET_NAME,
                           'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+str(attachment.file.name)
	    }
            #copy file into s3 bucket
            s3 = boto3.resource('s3', region_name=settings.AWS_REGION)
            bucket = s3.Bucket(settings.VINCE_SHARED_BUCKET)
            try:
                bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(attachment.uuid))
            except ClientError as e:
                error_code = e.response['Error']['Code']
                logger.debug(error_code)
                if error_code == "InvalidRequest":
                    #This file already exists in VinceComm. just ignore
                    pass
                else:
                    return JsonResponse({'status': 'success', 'text': f"There was an error uploading your file: {e.response['Error']['Code']} {e.response['Error']['Message']}"})

            action = VendorAction(title="Added File", user=User.objects.using('vincecomm').filter(username=request.user.email).first(), case=vinny_case)
            action.save()

            att = VinceAttachment(
                file=str(attachment.uuid),
                filename=attachment.filename,
                mime_type=attachment.mime_type,
                size=attachment.size,
            )
            att.save(using='vincecomm')

            #rename file
            copy_source = {'Bucket': settings.VINCE_SHARED_BUCKET,
                           'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+ str(attachment.uuid)
            }
            bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(att.uuid))
            #assign to new key and save

            att.file = str(att.uuid)
            att.save()
            #delete the old one
            s3.Object(settings.VINCE_SHARED_BUCKET, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(attachment.uuid)).delete()

            add_case = VinceCommCaseAttachment(action=action,
                                               file=att,
                                               vince_id=attachment.id)
            if add_case:
                add_case.save()

                ca = CaseAction(case=case,
                                title="Artifact is now public",
                                date=timezone.now(),
                                comment=f"{request.user.usersettings.preferred_username} added artifact to VINCEComm Case",
                                user = request.user,
                                artifact=artifact,
                                action_type=1)
                ca.save()

            attachment.public = True
            attachment.save()

        else:
            messages.error(
                request,
                _("That artifact isn't available in vincecomm"))
            return redirect('vince:case', case_id)

        messages.success(
            request,
            _("Artifact successfully shared"))
    return redirect("vince:case", case_id)

class CaseArtifacts(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/include/artifacts.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case'])
            return has_case_read_access(self.request.user, case)
        return False

    def get_context_data(self, **kwargs):
        context = super(CaseArtifacts, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['case'])
        context['artifacts']= get_all_artifacts(context['case'])
        context['form'] = AddArtifactForm()
        context['show_ticket_info'] = True
        return context


class EditArtifactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    form_class = EditArtifactForm
    template_name = 'vince/edit_artifact.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
            if artifact.get_related_ticket():
                ticket = artifact.get_related_ticket()
                return has_queue_write_access(self.request.user, ticket.queue)
            elif artifact.get_related_case():
                return has_case_write_access(self.request.user, artifact.get_related_case())
        return False

    def form_valid(self, form):
        artifact = form.save()
        newtags = self.request.POST.getlist('taggles[]')
        #get all tags:
        oldtags = list(ArtifactTag.objects.filter(artifact=artifact).values_list('tag', flat=True))
        title = "Modifed artifact details"
        newt = False
        rmt = False
        for tag in newtags:
            if tag in oldtags:
                continue
            else:
                ntag = ArtifactTag(artifact=artifact,
                                  tag = tag,
                                  user = self.request.user)
                newt = True
                ntag.save()
        #remove
        for tag in oldtags:
            if tag not in newtags:
                otag = ArtifactTag.objects.filter(artifact=artifact,
                                                  tag = tag)
                rmt = True
                otag.delete()
        if newt:
            title = "Added tag(s), " + title
        if rmt:
            title = title + ", removed tag(s)"

        ticket = TicketArtifact.objects.filter(artifact_ptr=artifact).first()
        if ticket:
            followup = FollowUp(
                ticket=ticket.ticket,
                title="Edited artifact",
                comment=title,
                user=self.request.user,
                artifact=artifact,
            )
            followup.save()

            referer = self.request.META.get('HTTP_REFERER')
            if referer:
                if 'case' in referer and ticket.ticket.case:
                    # this is coming from case view so get all case artifacts
                    tartifacts = get_all_artifacts(ticket.ticket.case)
                else:
                    tartifacts = Artifact.objects.select_related('ticketartifact').filter(ticketartifact__ticket=ticket.ticket)
            else:
                tartifacts = Artifact.objects.select_related('ticketartifact').filter(ticketartifact__ticket=ticket.ticket)
            artifactsjs = [ obj.as_dict() for obj in tartifacts ]
            return JsonResponse({'success': True, 'artifacts': artifactsjs}, status=200)
        else:
            case = CaseArtifact.objects.filter(artifact_ptr=artifact).first()
            ca = CaseAction(case=case.case,
                            title="Edited artifact",
                            date=timezone.now(),
                            comment=title,
                            user = self.request.user,
                            artifact=artifact,
                            action_type=1)
            ca.save()
            artifacts = get_all_artifacts(case.case)
            logger.debug(artifacts)
            artifactsjs = [ obj.as_dict() for obj in artifacts ]
            return JsonResponse({'success': True, 'artifacts': artifactsjs}, status=200)


    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
        form = EditArtifactForm(request.POST, instance=artifact)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(EditArtifactView, self).get_context_data(**kwargs)
        artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
        form = EditArtifactForm(instance=artifact)
        atags = ArtifactTag.objects.filter(artifact=artifact)
        context['tags'] = [tag.tag for tag in atags]
        ticket = TicketArtifact.objects.filter(artifact_ptr=artifact).first()
        if ticket:
            context['ticket'] = ticket.ticket
        else:
            case = CaseArtifact.objects.filter(artifact_ptr=artifact).first()
            context['case'] = case.case
        context['form'] = form
        context['action'] = reverse('vince:editartifact', args=[self.kwargs['pk']])
        context['title'] = "Edit artifact"
        return context

class AddCaseDependency(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    template_name = "vince/ticket_add_dependency.html"
    form_class = CaseDependencyForm

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
            return has_case_write_access(self.request.user, case)
        return False

    def post(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
        form = CaseDependencyForm(request.POST)
        if form.is_valid():
            casedependency = form.save(commit=False)
            casedependency.case = case
            if casedependency.case != casedependency.depends_on:
                casedependency.save()
            ca = CaseAction(case=case, title="Added Dependency",
                            user=self.request.user, action_type=1)
            ca.save()
            return HttpResponseRedirect(reverse('vince:case', args=[case.id]))

    def get_context_data(self, **kwargs):
        context = super(AddCaseDependency, self).get_context_data(**kwargs)
        context['case'] = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
        initial = {}
        form = CaseDependencyForm()
        form.fields['depends_on'].choices = [('', '--------')] + [
            (q.id, q.title) for q in Ticket.objects.filter(case=context['case'])]
        context['form'] = form
        context['action'] = reverse("vince:addcasedep", args=[self.kwargs['case_id']])
        return context

class DeleteTicketDependency(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    template_name = "vince/ticket_rm_dependency.html"
    form_class = TicketDependencyForm

    def	test_func(self):
        ticket = get_object_or_404(self.request.user, id=self.kwargs['ticket_id'])
        return is_in_group_vincetrack(self.request.user) and has_queue_write_access(self.request.user, ticket.queue)

    def post(self, request, *args, **kwargs):
        dep = get_object_or_404(TicketDependency, ticket_id=self.kwargs['ticket_id'], id=self.kwargs['dep_id'])
        dep.delete()
        return HttpResponseRedirect(reverse('vince:ticket', args=[self.kwargs['ticket_id']]))

    def get_context_data(self, **kwargs):
        context = super(DeleteTicketDependency, self).get_context_data(**kwargs)
        dep = get_object_or_404(TicketDependency, ticket_id=self.kwargs['ticket_id'], id=self.kwargs['dep_id'])
        context['form'] = TicketDependencyForm()
        context['dependency'] = dep
        context['ticket'] = Ticket.objects.filter(id = self.kwargs['ticket_id']).first()
        return context

class DeleteCaseDependency(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    template_name = "vince/ticket_rm_dependency.html"
    form_class = CaseDependencyForm

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
            return has_case_write_access(self.request.user, case)
        return False

    def post(self, request, *args, **kwargs):
        dep = get_object_or_404(CaseDependency, case_id=self.kwargs['case_id'], id=self.kwargs['dep_id'])
        dep.delete()
        case= VulnerabilityCase.objects.filter(id = self.kwargs['case_id']).first()
        ca = CaseAction(case=case, title="Removed Dependency",
                        user=self.request.user, action_type=1)
        ca.save()
        return HttpResponseRedirect(reverse('vince:case', args=[self.kwargs['case_id']]))

    def get_context_data(self, **kwargs):
        context = super(DeleteCaseDependency, self).get_context_data(**kwargs)
        dep = get_object_or_404(CaseDependency, case_id=self.kwargs['case_id'], id=self.kwargs['dep_id'])
        context['dependency'] = dep
        context['case'] = VulnerabilityCase.objects.filter(id = self.kwargs['case_id']).first()
        logger.debug("return context")
        return context


#### CONTACT MANAGER STUFF #######
def _add_activity(user, action, contact, text):
    # type: (User, int, Contact, str) -> None
    activity = Activity(user=user, action=action, contact=contact, text=text)
    activity.save()

def _add_group_activity(user, action, group, text):
    activity = GroupActivity(user=user, action=action, group=group, text=text)
    activity.save()

class ContactAssociationListView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/verifycontacts.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)
    
    def get_context_data(self, **kwargs):
        context = super(ContactAssociationListView, self).get_context_data(**kwargs)

        context['object_list'] = ContactAssociation.objects.filter(complete=False)
        return context

class CompletedContactAssociationListView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/contact_assoc_list.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CompletedContactAssociationListView, self).get_context_data(**kwargs)

        context['object_list'] = ContactAssociation.objects.filter(complete=True).order_by('-ticket__modified')
        return context


class RestartContactAssociation(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/restart_contact.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RestartContactAssociation, self).get_context_data(**kwargs)
        context['contact_request'] = get_object_or_404(ContactAssociation, id=self.kwargs['pk'])
        return context

    def post(self, request, *args, **kwargs):
        req = get_object_or_404(ContactAssociation, id=self.kwargs['pk'])
        logger.debug(self.request.POST)
        ticket=req.ticket
        fup = FollowUp(title="Contact association failed. Restarting contact association process.",
                       user = self.request.user,
                       ticket = ticket)
        fup.save()
        req.complete = True
        req.approval_requested=False
        req.restart=True
        #remove ticket from this request so we can start again
        req.save()
        ticket.status = Ticket.REOPENED_STATUS
        ticket.save()
        
        messages.success(
            self.request,
            "Success.  Please retry to verify contact."
        )
        return redirect("vince:ticket", ticket.id)
    

class CompleteContactAssociation(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/complete_contact.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CompleteContactAssociation, self).get_context_data(**kwargs)
        context['contact_request'] = get_object_or_404(ContactAssociation, id=self.kwargs['pk'])
        return context

    def post(self, request, *args, **kwargs):
        req = get_object_or_404(ContactAssociation, id=self.kwargs['pk'])
        logger.debug(self.request.POST)
        ticket = req.ticket
        if self.request.POST.get('remove'):
            #this user couldn't be verified
            ticket.status = Ticket.CLOSED_STATUS
            ticket.save()
            
            fup = FollowUp(title="User could not be verified. Ticket is CLOSED.",
                           user = self.request.user,
                           ticket = ticket)
            fup.save()
            req.approval_requested = False
            req.complete = True
            req.save()
            return JsonResponse({'status':'success'}, status=200)
        # is this user in the authorizer role?
        role = UserRole.objects.filter(role="Authorizer").first()
        if role:
            #then something
            #is this user in the role?
            if UserAssignmentWeight.objects.filter(role=role, user=self.request.user).exists() or self.request.user.is_superuser:
                #make sure this user isn't the same person that initiated the request
                if (self.request.user == req.initiated_by):
                    if not(self.request.user.is_superuser):
                        return JsonResponse({'error': 'This process requires 2-person validation. Since you are the user that initiated this process, you cannot authorize it.'}, status=401)
                
                #get this user's name
                vc_user = User.objects.using('vincecomm').filter(email=req.user).first()
                if vc_user :
                    if vc_user.first_name or vc_user.last_name:
                        full_name = f"{vc_user.first_name} {vc_user.last_name}"
                    else:
                        full_name = vc_user.vinceprofile.preferred_username
                else:
                    full_name = "Unknown"

                if req.contact.active == False:
                    req.contact.active = True
                    req.contact.save()
                    _add_activity(self.request.user, 3, req.contact, "changed status to ACTIVE through contact association process")
                    
                #then approve
                ec, created = EmailContact.objects.update_or_create(contact=req.contact,
                                                      email=req.user,
                                                      defaults = {'user_added': self.request.user, 'name': full_name, 'email_list':False})
                #search vc_contact
                vccontact = VinceCommContact.objects.filter(vendor_id = req.contact.id).first()
                VinceCommEmail.objects.update_or_create(contact=vccontact,
                                                        email=req.user,
                                                        defaults={'email_list':False,
                                                                 'name':full_name})
                _add_activity(self.request.user, 3, req.contact, f"added email {req.user} through contact association tool")
                if vc_user:
                    _add_group_permissions(req.user, self.request.user)

                    #does this contact already have a groupadmin?
                    ga = GroupAdmin.objects.filter(contact=req.contact).first()
                    if ga == None:
                        #add group admin
                        ga = GroupAdmin.objects.update_or_create(contact=req.contact,
                                                                 email=ec)
                        _add_groupadmin_perms(ec)
                        _add_groupadmin(ec, req.contact)

                        fup = FollowUp(
                            ticket = req.ticket,
                            user=self.request.user,
                            title="Contact Association Approved and Complete",
                            comment = f"{req.user} has been added to {req.contact.vendor_name} and made group administrator"
                        )
                        fup.save()
                    else:
                        # this contact already has a group admin so let group admin promote user if needed
                        fup = FollowUp(
                            ticket = req.ticket,
                            user=self.request.user,
                            title="Contact Association Approved and Complete",
                            comment = f"{req.user} has been added to {req.contact.vendor_name}"
                        )
                        fup.save()
                else:
                    # no user, but email added
                    fup = FollowUp(
			ticket = req.ticket,
                        user=self.request.user,
	                title="Contact Association Approved and Complete",
			comment = f"{req.user} has been added to {req.contact.vendor_name}"
                    )
                    fup.save()

                req.complete=True
                req.authorized_by = self.request.user
                req.ticket.resolution = "Contact Association Approved and Complete"
                req.ticket.status = Ticket.CLOSED_STATUS
                req.ticket.save()
                req.save()
                return JsonResponse({'status':'success'}, status=200)
            else:
                raise PermissionDenied()
        else:
            return JsonResponse({'error': 'You are not an authorizer. You are not permitted to perform this action.'}, status=401)
                
    
class ContactRequestAuth(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/contactrequest.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ContactRequestAuth, self).get_context_data(**kwargs)
        context['contact_request'] = get_object_or_404(ContactAssociation, id=self.kwargs['pk'])
        return context

    def post(self, request, *args, **kwargs):
        req = get_object_or_404(ContactAssociation, id=self.kwargs['pk'])
        ticket = req.ticket
        if ticket == None:
            raise Http404

        if self.request.POST.get('remove'):
            #this user couldn't be verified
            ticket.status = Ticket.CLOSED_STATUS
            ticket.save()

            fup = FollowUp(title="User could not be verified",
                           user = self.request.user,
                           ticket = ticket)
            fup.save()
            req.complete = True
            req.save()
            return JsonResponse({'status':'success'}, status=200)
        
        role = UserRole.objects.filter(role="Authorizer").first()
        if role:
            assignment = auto_assignment(role.id, exclude=req.initiated_by)
            if assignment:
                request.POST = {
                    'owner': assignment.id,
                    'new_status': Ticket.OPEN_STATUS,
                    'comment': 'Requesting Authorization for Contact Association',
                    'auto': 1
                }
                kwargs['ticket_id'] = ticket.id
                req.approval_requested=True
                req.save()
                return update_ticket(request, ticket.id)
            else:
                return JsonResponse({'error': 'No available users for this role'}, status=401)
        else:
            return JsonResponse({'error': 'No Authorizer Role available'}, status=401)


class MessageAdminAddUser(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/msgadmin.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(MessageAdminAddUser, self).get_context_data(**kwargs)
        contact = get_object_or_404(Contact, id=self.kwargs['pk'])
        context['contact'] = contact
        admins = list(GroupAdmin.objects.filter(contact=contact).values_list('email__email', flat=True))
        num_admins = len(admins)
        admins = ", " .join(admins)
        if num_admins:
            if num_admins > 1:
                context['text'] = f"There are {num_admins} admins for this contact: {admins}."
            else:
                context['text'] = f"There is {num_admins} admin for this contact: {admins}."
            tmpl = EmailTemplate.objects.filter(template_name='vendor_admin_user_request').first()
            if tmpl:
                team_sig = get_team_sig(self.request.user)
                context['msg_body'] = tmpl.plain_text.replace('[VENDOR]', contact.vendor_name).replace('[team_signature]', team_sig)
            else:
                context['msg_body'] = "A 'vendor_admin_user_request' template has not been created. Please add a template or fill in the message to send the admin"

        return context

    def post(self,request,*args, **kwargs):
        logger.debug(self.request.POST)
        contact = get_object_or_404(Contact, id=self.kwargs['pk'])
        sender = User.objects.using('vincecomm').filter(email=self.request.user.email).first()
        #get emails                                                                                                                                                                                 
        admins = list(GroupAdmin.objects.filter(contact=contact).values_list('email__email', flat=True))
        users = User.objects.using('vincecomm').filter(email__in=admins).values_list('id', flat=True)
        if users:
            msg = Message.new_message(sender, users, None, "VINCE Vendor User Request", self.request.POST['msg'])
            user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            if user_groups:
                msg.thread.from_group=user_groups[0].groupsettings.contact.vendor_name
            msg.thread.save()
            vq = get_vendor_queue(self.request.user)
            ticket=Ticket(title="VINCE Vendor User Request",
                          created=timezone.now(),
                          status=Ticket.CLOSED_STATUS,
                          queue=vq,
                          description=self.request.POST['msg'],
                          submitter_email=self.request.user.email,
                          assigned_to=self.request.user)
            ticket.save()
            fup = FollowUp(title=f"Sent message to {contact.vendor_name} admins: {admins}",
                           comment=self.request.POST.get('msg'), ticket=ticket,
                           user=self.request.user)
            fup.save()                                                                                                                                                                
            tm = TicketThread(thread=msg.thread.id,
                              ticket=ticket.id)

            tm.save()
            fm = FollowupMessage(followup=fup,
                                 msg=msg.id)
            fm.save() 

        messages.success(
            self.request,
            f"Message sent successfully. Refer to ticket {ticket.ticket_for_url}."
        )
        return redirect("vince:contact", contact.id)
        
class ContactAdminLookup(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/adminlookup.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)
    
    def get_context_data(self, **kwargs):
        context = super(ContactAdminLookup, self).get_context_data(**kwargs)
        context['ticket'] = get_object_or_404(Ticket, id=self.kwargs['pk'])
        # is this ticket already in the Contact Association process?
        ca = ContactAssociation.objects.filter(ticket=context['ticket']).first()
        if ca:
            context['ca'] = ca
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"InitContactForm Post: {self.request.POST}")
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        #search for Contact:
        if self.request.POST.get('msg'):
            contact = Contact.objects.filter(vendor_name = self.request.POST['vendor']).first()
            sender = User.objects.using('vincecomm').filter(email=self.request.user.email).first()
            #get emails
            admins = list(GroupAdmin.objects.filter(contact=contact).values_list('email__email', flat=True))
            users = User.objects.using('vincecomm').filter(email__in=admins).values_list('id', flat=True)
            if users:
                msg = Message.new_message(sender, users, None, "VINCE Vendor User Request", self.request.POST['msg'])
                user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
                if user_groups:
                    msg.thread.from_group=user_groups[0].groupsettings.contact.vendor_name
                msg.thread.save()

                fup = FollowUp(title=f"Sent message to {contact.vendor_name} admins: {admins}",
                               comment=self.request.POST.get('msg'), ticket=ticket,
                               user=self.request.user)
                fup.save()
                tm = TicketThread(thread=msg.thread.id,
                                  ticket=ticket.id)
                
                tm.save()
                fm = FollowupMessage(followup=fup,
                                     msg=msg.id)
                fm.save()

                ticket.status = Ticket.CLOSED_STATUS
                ticket.save()

            return JsonResponse({'ticket': reverse("vince:ticket", args=[ticket.id])}, status=200)

        if self.request.POST.get('vendor'):
            contact = Contact.objects.filter(vendor_name = self.request.POST['vendor']).first()
            if contact:
                #get admins
                admins = list(GroupAdmin.objects.filter(contact=contact).values_list('email__email', flat=True))
                num_admins = len(admins)
                admins = ", " .join(admins)
                action_link = None
                if num_admins:
                    if num_admins > 1:
                        text = f"There are {num_admins} admins for this contact: {admins}."
                    else:
                        text = f"There is {num_admins} admin for this contact: {admins}."
                    msg_link = reverse("vince:msgadmin", args=[ticket.id])
                    tmpl = EmailTemplate.objects.filter(template_name='vendor_admin_user_request').first()
                    if tmpl:
                        team_sig = get_team_sig(self.request.user)
                        msg_body = tmpl.plain_text.replace('[EMAIL]', self.request.POST.get('email')).replace('[VENDOR]', contact.vendor_name).replace('[team_signature]', team_sig)
                    else:
                        msg_body = "A 'vendor_admin_user_request' template has not been created. Please add a template or fill in the message to send the admin"
                else:
                    text = f"A group admin has not been named for {contact.vendor_name}."
                    action_link = reverse("vince:initcontactverify", args=[contact.id])+"?tkt="+str(ticket.id)
                    msg_link = None
                    msg_body = None
                    
                return JsonResponse({'text':text, "action_link": action_link, "msg_link":msg_link, 'contact_link': reverse("vince:contact", args=[contact.id]), 'email_link': reverse("vince:initcontactverify", args=[contact.id])+"?tkt="+str(ticket.id), 'msg_body':msg_body}, status=200)
            return JsonResponse({'error':"No such vendor"}, status=401)

    
        
class ContactVerifyInit(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = "vince:login"
    template_name = "vince/initcontactverify.html"
    form_class = InitContactForm
    
    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ContactVerifyInit, self).get_context_data(**kwargs)
        #do we have a user verficiation template?
        initial = {}
        if self.kwargs.get('pk'):
            contact = get_object_or_404(Contact, id=self.kwargs.get('pk'))
            initial['contact'] = contact.vendor_name
            #get emails for this contact
            emails = contact.get_emails()
            if emails:
                #initial['email'] = ",".join(emails)
                context['emails'] = emails
            if self.request.GET.get('email'):
                initial['user'] = self.request.GET.get('email')
            if self.request.GET.get('bypass'):
                context['emails'] = [self.request.GET.get('email')]
                initial['internal'] = True
                messages.warning(self.request,
                                 _(f"You have requested internal verification for this user. Please provide justification in the email field."))
                
        if self.request.GET.get('tkt'):
            initial['ticket'] = self.request.GET["tkt"]
            ticket = get_object_or_404(Ticket, id=self.request.GET['tkt'])
            initial['user'] = ticket.submitter_email

            # is this ticket already in the Contact Association process?
            ca = ContactAssociation.objects.filter(ticket=ticket).first()
            if ca:
                context['ca'] = ca
            
        tmpl = EmailTemplate.objects.filter(template_name='user_verification').first()
        if tmpl:
            team_sig = get_team_sig(self.request.user)
            initial['email_body'] = tmpl.plain_text.replace('[team_signature]', team_sig)
            logger.debug(team_sig)
            initial['subject'] = tmpl.subject
            if context.get('ca'):
                context['form'] = InitContactForm(initial=initial, instance=context['ca'])
            else:
                context['form'] = InitContactForm(initial=initial)
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"InitContactForm Post: {self.request.POST}")

        if self.request.POST.get('ca'):
            ca = get_object_or_404(ContactAssociation, id=self.request.POST.get('ca'))
            form = InitContactForm(request.POST, instance=ca)
        else:
            form = InitContactForm(request.POST)

        if form.is_valid():
            
            contact = form.cleaned_data['contact']
            #check to make sure this user isn't already a part of the contact
            if EmailContact.objects.filter(contact = contact,
                                           email = self.request.POST['user'],
                                           email_list=False).exists():
                form._errors.setdefault("user", ErrorList([
		    u"Email already exists for this contact"
	        ]))
                messages.error(
                    self.request,
		    _(f'Email already exists for this contact'))
                return render(request, self.template_name, {'form': form, 'emails': contact.get_emails()})
            
            if VinceCommEmail.objects.filter(contact__vendor_id=contact.id, email=self.request.POST['user'],
                                             email_list=False).exists():
                form._errors.setdefault("user", ErrorList([
                    u"Email already exists for this contact in VINCEComm. Check Contact Updates and Approve"
                ]))
                messages.error(
                    self.request,
		    _(f'Email already exists for this contact in VINCEComm.'))
                return render(request, self.template_name, {'form': form, 'emails':contact.get_emails()})

            #make sure all emails are legit
            emails = self.request.POST.getlist('email')
            logger.debug(emails)
            for email in emails:
                email = email.strip()
                if EmailContact.objects.filter(contact=contact,
                                               email__iexact=email).exists():
                    continue
                else:
                    if (self.request.POST.get('internal')):
                        continue
                    form._errors.setdefault("email", ErrorList([
                        f"Invalid email ({email}) for this contact."
                    ]))
                    messages.error(
                        self.request,
                        _(f'Invalid verification email for this contact. Verification emails must be added to contact before initiating process.'))
                    return render(request, self.template_name, {'form': form, 'emails':contact.get_emails()})
            
            return self.form_valid(form)
        else:
            logger.debug(form.errors)
            return self.form_invalid(form)

    def form_invalid(self, form):
        if self.kwargs.get('ca'):
            ca = get_object_or_404(ContactAssociation, id=self.kwargs.get('ca'))
        else:
            ca = None
            
        return render(self.request, self.template_name,
                      {'form': form,
                       'ca': ca})
                       
    def form_valid(self, form):

        assoc = form.save()
        assoc.complete=False
        assoc.restart=False
        assoc.initiated_by=self.request.user
        assoc.email = ",".join(self.request.POST.getlist('email'))
        assoc.save()

        if form.cleaned_data['ticket']:
            ticket = form.cleaned_data['ticket']
            if ticket.assigned_to == None:
                ticket.assigned_to = self.request.user
                ticket.save()
        else:
            ticket = Ticket(title=f"Contact Verification Process Initiated for {form.cleaned_data['user']}",
                            description=f"{form.cleaned_data['email_body']}",
                            status = Ticket.CLOSED_STATUS,
                            queue = get_vendor_queue(self.request.user),
                            submitter_email = form.cleaned_data['user'],
                            assigned_to=self.request.user)
            ticket.save()
            assoc.ticket = ticket
            assoc.save()


        if form.cleaned_data['internal'] == False:
            title = f"Sent email to {assoc.email} with subject {form.cleaned_data['subject']} to attempt to verify {form.cleaned_data['user']} works for {form.cleaned_data['contact'].vendor_name}."
            body = form.cleaned_data['email_body']
            if len(title) > 299:
                #title too long for followup, add important info to comment instead
                title = f"Sent email to attempt to verify {form.cleaned_data['user']} works for {form.cleaned_data['contact'].vendor_name}."
                body = f"Email sent to {assoc.email}\r\nSubject:{form.cleaned_data['subject']}\r\nBody:{body}"
                
            fup = FollowUp(ticket=ticket,
                           title=title,
                           comment=body,
                           user=self.request.user)
            fup.save()
            
            subject = f"[{ticket.queue.slug}-{ticket.id}] {form.cleaned_data['subject']}"

            emails = self.request.POST.getlist('email')
            
            send_regular_email_notification(emails, subject, form.cleaned_data['email_body'])
            
            messages.success(
                self.request,
                "Your email has been sent."
            )
        else:

            fup = FollowUp(ticket=ticket,
                           title=f"Internal verification request to associate {form.cleaned_data['user']} with the {form.cleaned_data['contact'].vendor_name} contact.",
                           comment=form.cleaned_data['email_body'],
                           user=self.request.user)
            fup.save()
            
            #if it's internal - keep it open so it can be assigned to an authorizer
            ticket.status = Ticket.OPEN_STATUS
            ticket.save()
           
        return redirect("vince:ticket", ticket.id)
    

class ContactsSearchView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    template_name = 'vince/searchcontacts.html'
    login_url = "vince:login"
    model = Contact

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ContactsSearchView, self).get_context_data(**kwargs)
        if 'q' in self.request.GET:
            context['query'] = self.request.GET.get('q')

        tag = self.request.GET.get('tag')
        if tag:
            context['query'] = tag
            
        context['contactpage']=1
        ca = Activity.objects.all()
        ga = GroupActivity.objects.all()
        res = chain(ca, ga)
        qs = sorted(res,
                    key=lambda instance: instance.action_ts,
                    reverse=True)
        context['activity_list'] = qs[:30]
        context['show_contact'] = True
        return context



class ContactsResults(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Contact
    login_url = "vince:login"
    template_name = 'vince/contactsresults.html'

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ContactsResults, self).get_context_data(**kwargs)
        context['contactpage']=1
        return context

    def get(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} get: {self.request.GET}")
        search_term = self.request.GET.get('search_vector', None)
        search_query = process_query(search_term, False)
        search_tags = process_query_for_tags(search_term)
        sort_type = self.request.GET.get('sort', 1)
        facet = self.request.GET.get('facet', 'All')

        contact_results = []
        group_results = []
        vince_results = []

        if search_query:
            if facet == "All":
                vince_results = VinceProfile.objects.using('vincecomm').filter(Q(user__first_name__icontains=search_term) | Q(user__last_name__icontains=search_term) | Q(preferred_username__icontains=search_term) | Q(user__email__icontains=search_term))
                user_contacts = list(vince_results.values_list('user__email', flat=True))
                logger.debug(user_contacts)
                email_contacts = EmailContact.objects.filter(contact__vendor_type="Contact", email__in=user_contacts).values_list('contact__id', flat=True)
                email_results = EmailContact.objects.filter(Q(email__icontains=search_term) | Q(name__icontains=search_term)).exclude(contact__id__in=email_contacts).values_list('contact', flat=True)
                emails = Contact.objects.filter(id__in=email_results)
                logger.debug(email_contacts)
                contact_results = Contact.objects.search(search_query).exclude(id__in=email_contacts)
                ctags = ContactTag.objects.filter(tag__in=search_tags).values_list('contact__id', flat=True)
                if ctags:
                    ctags = Contact.objects.filter(id__in=ctags)
                    contact_results = contact_results | emails | ctags
                else:
                    contact_results = contact_results | emails
                group_results = ContactGroup.objects.filter(Q(name__icontains=search_term) | Q(srmail_peer_name__icontains=search_term))

            elif facet == "Groups":
                group_results = ContactGroup.objects.filter(Q(name__icontains=search_term) | Q(srmail_peer_name__icontains=search_term))
            elif facet == "Contacts":
                email_results = EmailContact.objects.filter(Q(email__icontains=search_term) | Q(name__icontains=search_term)).values_list('contact', flat=True)
                emails = Contact.objects.filter(id__in=email_results)
                contact_results = Contact.objects.search(search_query)
                ctags =	ContactTag.objects.filter(tag__in=search_tags).values_list('contact__id', flat=True)
                if ctags:
                    ctags = Contact.objects.filter(id__in=ctags)
                    contact_results = contact_results | emails | ctags
                else:
                    contact_results = contact_results | emails
                    
            elif facet == "VINCE":
                vince_results = VinceProfile.objects.using('vincecomm').filter(Q(user__first_name__icontains=search_term) | Q(user__last_name__icontains=search_term) | Q(preferred_username__icontains=search_term) | Q(user__email__icontains=search_term))
        else:
            if facet == "All":
                # just get recent
                contact_results = Contact.objects.all()
                group_results = ContactGroup.objects.all()
                vince_results = []
            elif facet == "Groups":
                group_results = ContactGroup.objects.all()
            elif facet == "Contacts":
                contact_results = Contact.objects.all()

        results = chain(contact_results, group_results, vince_results)
        if int(sort_type) == 1:
            qs = sorted(results,
                        key=lambda instance: instance.modified,
                        reverse=True)
        else:
            qs = sorted(results,
                        key=lambda instance: instance.name,
                        reverse=False)


        page = self.request.GET.get('page', 1)
        paginator = Paginator(qs, 15)

        return render(request, self.template_name, {'object_list': paginator.page(page), 'total': len(qs) })

class CreateGroupView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView, FormMixin):
    model = ContactGroup
    login_url = "vince:login"
    template_name = 'vince/newgroup.html'
    form_class = GroupForm

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CreateGroupView, self).get_context_data(**kwargs)
        if 'pk' in self.kwargs:
            vendorrecord = VendorRecord.objects.filter(id=self.kwargs['pk']).first()
            context['vendors'] = VendorRecord.objects.filter(vuid = vendorrecord.vuid).values_list('vendor', flat=True)
            context['vulnote'] = VulNote.objects.filter(idnumber = vendorrecord.idnumber).first()
            context['form'] = self.form_class(initial={'name':vendorrecord.vuid})

        context['contacts'] = Contact.objects.all().order_by('vendor_name')
        context['groups'] = ContactGroup.objects.all().order_by('name')
        context['contactpage']=1
        return context


    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return render(self.request, 'vince/newgroup.html',
                      {'form': form,
                       'errors': form.errors,
                       'contacts': Contact.objects.order_by('vendor_name'),
                       'groups': ContactGroup.objects.all().order_by('name')})

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        logger.debug("VALID FORM")
        if group_name_exists(self.request.POST['name']):
            return render(self.request, 'vince/newgroup.html',
                          {'form': form,
                           'errors': "Group Name already exists.",
                           'contacts': Contact.objects.order_by('vendor_name'),
                           'groups': ContactGroup.objects.all().order_by('name'),
                           'name_error':True})

            if srmail_name_exists(self.request.POST['srmail_peer_name']):
                return render(self.request, 'vince/newgroup.html',
                              {'form': form,
                               'errors': "SRMail Peer name already exists",
                               'srmail_error': True,
                               'contacts': Contact.objects.order_by('vendor_name'),
                               'groups': ContactGroup.objects.all().order_by('name')})

        contactlist = self.request.POST.getlist('group_select[]')
        if len(contactlist) == 0:
            return render(self.request, 'vince/newgroup.html',
                          {'form': form,
                           'errors': "Please add contacts and/or groups",
                           'contacts': Contact.objects.order_by('vendor_name'),
                           'groups': ContactGroup.objects.all().order_by('name')})

        newgroup = ContactGroup(name=self.request.POST['name'],
                         description=self.request.POST['description'],
                         srmail_peer_name=self.request.POST['srmail_peer_name'],
                         group_type=self.request.POST['group_type'],
                         status = self.request.POST['status'],
                         comment = self.request.POST['comment'],
                         user_added=self.request.user)
        newgroup.save()
        # add the duplicate group hack
        dupgroup = GroupDuplicate(group=newgroup)
        dupgroup.save()

        added=0
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        logger.debug(self.request.POST['group_select[]'])

        for group in contactlist:
            logger.debug(group)
            contact = Contact.objects.filter(vendor_name=group).first()
            if contact:
                newmember=GroupMember(group=newgroup,
                                      contact=contact,
                                      user_added=self.request.user,
                                      member_type=contact.vendor_type)
                newmember.save()
                if newmember.id:
                    added = added + 1
                    text = "Added %s to group %s" % (contact.vendor_name, newgroup.name)
                    _add_activity(self.request.user, 4, contact, text)
                else:
                    logger.debug("NOT ADDED")
            else:
                logger.debug("this is a group")
                contact = ContactGroup.objects.filter(name=group).first()
                if contact:
                    groupdup = GroupDuplicate.objects.filter(group=contact).first()
                    newmember = GroupMember(group=newgroup,
                                            group_member=groupdup,
                                            user_added=self.request.user,
                                            member_type="Group")
                    newmember.save()
                    if newmember.id:
                        text = "Added %s to group %s" % (group, newgroup.name)
                        _add_group_activity(self.request.user, 2, groupdup.group, text)
                        added=added+1

        logger.debug("added %d members" % added)

        update_srmail_file()
        messages.warning(
            self.request,
            _(f"Updating SRMAIL file due to new group."))

        text = "created group %s" % newgroup.name
        _add_group_activity(self.request.user, 1, newgroup, text)
        return redirect("vince:group", newgroup.id)


    
class AddContactToGroupView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url="vince:login"
    template_name="vince/addcontacttogroup.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        contact = get_object_or_404(Contact, id=self.kwargs.get('pk'))
        group = get_object_or_404(ContactGroup, name=self.request.POST.get('group'))
        if self.request.POST.get('rm'):
            #remove contact from group
            member = GroupMember.objects.filter(group=group, contact=contact).first()
            if member:
                member.delete()
                text = "removed %s from '%s' group" % (contact.vendor_name, group.name)
                _add_group_activity(self.request.user, 3, group, text)
                _add_activity(self.request.user, 5, contact, text)
                update_srmail_file()
            else:
                return JsonResponse({'error': 'Contact is not in Group'}, status=403)
        else:
        
            newmember=GroupMember(group=group,
                                  contact=contact,
                                  user_added=self.request.user,
                                  member_type=contact.vendor_type)
            newmember.save()
            text = "added %s to '%s' group" % (contact.vendor_name, group.name)
            _add_activity(self.request.user, 4, contact, text)
            _add_group_activity(self.request.user, 2, group, text)
            update_srmail_file()
            
        return JsonResponse({'message': 'success'}, status=200)


    
class RemoveContactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Contact
    login_url = "vince:login"
    template_name = 'vince/delete_contact.html'

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RemoveContactView, self).get_context_data(**kwargs)
        context['contact'] = get_object_or_404(Contact, id=self.kwargs['pk'])
        context['cases'] = VulnerableVendor.objects.filter(contact=context['contact'])
        if len(context['cases'])> 0:
            context['requires_admin'] = True
        context['vinny_contact'] = VinceCommContact.objects.filter(vendor_id=context['contact'].id).first()
        return context

    def post(self, request, *args, **kwargs):
        if not(self.request.user.is_superuser):
            messages.error(
                self.request,
                _("User must be an administrator to perform this action"))
            return HttpResponseRedirect(reverse('vince:searchcontacts'))
        contact = get_object_or_404(Contact, id=self.kwargs['pk'])
        vinny_contact = VinceCommContact.objects.filter(vendor_id=contact.id).first()
        #remove group
        vinny_group = Group.objects.using('vincecomm').filter(name=vinny_contact.vendor_name).first()
        contact.delete()
        if vinny_contact:
            vinny_contact.delete()
        if vinny_group:
            vinny_group.delete()
        messages.success(
            self.request,
            _("Contact successfully removed."))

        return HttpResponseRedirect(reverse('vince:searchcontacts'))

class RemoveGroupView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = ContactGroup
    login_url = "vince:login"
    template_name = "vince/delete_group.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RemoveGroupView, self).get_context_data(**kwargs)
        context['contactgroup'] = get_object_or_404(ContactGroup, id=self.kwargs['pk'])
        return context

    def post(self, request, *args, **kwargs):
        contact = get_object_or_404(ContactGroup, id=self.kwargs['pk'])
        contact.delete()
        messages.success(
            self.request,
            _("Group successfully removed."))

        return HttpResponseRedirect(reverse('vince:searchcontacts'))

class ContactActivity(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    model = Activity
    login_url = "vince:login"
    template_name = "vince/include/alt_contact_activity.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_queryset(self):
        return Activity.objects.filter(contact=self.kwargs['pk']).order_by('-action_ts')

class CreateContactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView, FormMixin):
    model = Contact
    login_url = "vince:login"
    template_name = 'vince/newcontact.html'
    form_class = ContactForm

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def form_invalid(self, form):
        logger.debug("INVALID FORM")
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")

        return render(self.request, 'vince/newcontact.html',
                      {'form': form,
                       })

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        logger.debug("VALID FORM")
        vendor_name = self.request.POST['vendor_name'].strip()
        group = False
        vendor_type = self.request.POST['vtype']
        if (vendor_type == "Group"):
            group = True
            if group_name_exists(vendor_name):
                error_str = "Group already exists with this name."
                return JsonResponse({'error': error_str}, status=401)
        else:
            old_contact = Contact.objects.filter(vendor_name__iexact=vendor_name).first()

            if old_contact:
                error_str = "Contact already exists with this vendor name."
                return JsonResponse({'error': error_str,
                                     'oldid': old_contact.id}, status=401)

        srmail_peer = vendor_name.lower().replace(" ", "_").replace("'", "")
        srmail_peer = srmail_peer.translate({ord(i):None for i in '"@+.,;'})

        if srmail_name_exists(srmail_peer):
            srmail_peer = f"{srmail_peer}_1"


        if group:
            newgroup = ContactGroup(name=vendor_name,
                                    description=f"New group added by {self.request.user.usersettings.preferred_username}",
                                    srmail_peer_name=srmail_peer,
                                    status="Inactive",
                                    comment = self.request.POST['comment'],
                                    user_added=self.request.user)
            newgroup.save()
            # add the duplicate group hack                                                                
            dupgroup = GroupDuplicate(group=newgroup)
            dupgroup.save()
            update_srmail_file()
            text = "created group %s" % newgroup.name
            _add_group_activity(self.request.user, 1, newgroup, text)
            return JsonResponse({'new': reverse("vince:group", args=[newgroup.id])}, status=200)

        if vendor_type == "User":
            vendor_type = "Contact"
        
        
        contact = Contact(vendor_name = vendor_name,
                          vendor_type=vendor_type,
                          srmail_peer = srmail_peer,
                          countrycode = self.request.POST['countrycode'],
                          lotus_id = 0,
                          location = self.request.POST['location'],
                          active = False,
                          comment = self.request.POST['comment'],
                          user_added=self.request.user)

        contact.save()

        if contact:
            _add_activity(self.request.user, 1, contact, f"created new contact ({contact.vendor_type})")


        messages.warning(
            self.request,
            _(f"Contact will remain inactive until email is added.  Add new email(s) to activate contact."))
            
        return JsonResponse({'new':reverse("vince:contact", args=[contact.id])}, status=200)

    def get_context_data(self, **kwargs):
        context = super(CreateContactView, self).get_context_data(**kwargs)
        context['form'] = self.form_class()
        context['contactpage']=1
        return context


class GroupDetailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = ContactGroup
    login_url = "vince:login"
    template_name = "vince/group.html"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(GroupDetailView, self).get_context_data(**kwargs)
        group = ContactGroup.objects.filter(id=self.kwargs['pk']).first()
        context['members'] = GroupMember.objects.filter(group=group).exclude(contact__isnull=True).values_list('contact', flat=True)
        context['group_members'] = GroupMember.objects.filter(group=group).exclude(contact__isnull=True).order_by('contact')
        # the groups in the group - give the list of groupduplicates
        groupdups = GroupMember.objects.filter(group=group).values_list('group_member', flat=True)
        duplicates = GroupDuplicate.objects.filter(group__in=groupdups).values_list('group', flat=True)
        context['groupmembers'] = ContactGroup.objects.filter(id__in=duplicates)
        context['group'] = group
        context['contactpage']=1
        context['activity'] = GroupActivity.objects.filter(group=group).order_by('-action_ts')
        context['cases'] = VulnerableVendor.objects.filter(from_group=group).order_by('case').distinct('case')
        context['inactive_contacts'] = context['members'].filter(contact__active=False).count()
        return context

class GroupEditView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView, FormMixin):
    model = ContactGroup
    login_url = "vince:login"
    template_name = "vince/editgroup.html"
    form_class = GroupForm

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(GroupEditView, self).get_context_data(**kwargs)
        context['contacts'] = Contact.objects.all().order_by('vendor_name')
        context['groups'] = ContactGroup.objects.all().order_by('name')
        group = ContactGroup.objects.filter(id=self.kwargs['pk'])
        context['form'] = self.form_class(initial=group.values()[0])
        # the contacts in the group
        context['contactpage']=1
        context['members'] = GroupMember.objects.filter(group=group[0]).exclude(contact__isnull=True).values_list('contact', flat=True)
        context['group_members'] = GroupMember.objects.filter(group=group[0]).exclude(contact__isnull=True).order_by('contact')

        # the groups in the group - give the list of groupduplicates
        groupdups = GroupMember.objects.filter(group=group[0]).values_list('group_member', flat=True)
        duplicates = GroupDuplicate.objects.filter(group__in=groupdups).values_list('group', flat=True)
        context['groupmembers'] = ContactGroup.objects.filter(id__in=duplicates)
        context['group'] = group.first()
        context['inactive_contacts'] = context['members'].filter(contact__active=False).count()
        return context


    def get(self, request, *args, **kwargs):
        group = ContactGroup.objects.filter(id=self.kwargs['pk']).first()
        if self.request.GET.get('activate'):
            #does this group have members?
            members = GroupMember.objects.filter(group=group).count()
            if members:
                group.status="Active"
                group.save()
                _add_group_activity(self.request.user, 4, group, f"activated {group.name} group")
            else:
                messages.error(
                    self.request,
                    _(f"You cannot activate a group without members."))

            return redirect("vince:group", group.id)
        elif self.request.GET.get('deactivate'):
            group.status="Inactive"
            group.save()
            _add_group_activity(self.request.user, 4, group, f"deactivated {group.name} group")
            return redirect("vince:group", group.id)
        return super().get(request, *args, **kwargs)
    

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        logger.debug("INVALID FORM!!!")

        group = ContactGroup.objects.filter(id=self.kwargs['pk'])
        members = GroupMember.objects.filter(group=group[0]).exclude(contact__isnull=True).values_list('contact', flat=True)
        # the groups in the group - give the list of groupduplicates
        groupdups = GroupMember.objects.filter(group=group[0]).values_list('group_member', flat=True)
        duplicates = GroupDuplicate.objects.filter(group__in=groupdups).values_list('group', flat=True)
        groupmembers = ContactGroup.objects.filter(id__in=duplicates)
        group = group.first()
        return render(self.request, 'vince/editgroup.html',
                      {'form': form,
                       'errors': form.errors,
                       'errorstr': self.error,
                       'contacts': Contact.objects.order_by('vendor_name'),
                       'groups': ContactGroup.objects.all().order_by('name'),
                       'group': group,
                       'groupmembers': groupmembers,
                       'members': members
                      })
    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        logger.debug("VALID FORM")
        current_group = ContactGroup.objects.filter(id=self.kwargs['pk']).first()
        if current_group.version != int(self.request.POST['version']):
            error_str = "Someone beat you to editing this group. View the most recent details and retry editing this group."
            group = ContactGroup.objects.filter(id=self.kwargs['pk'])
            members = GroupMember.objects.filter(group=group[0]).exclude(contact__isnull=True).values_list('contact', flat=True)
            # the groups in the group - give the list of groupduplicates
            groupdups = GroupMember.objects.filter(group=group[0]).values_list('group_member', flat=True)
            duplicates = GroupDuplicate.objects.filter(group__in=groupdups).values_list('group', flat=True)
            groupmembers = ContactGroup.objects.filter(id__in=duplicates)
            group = group.first()
            return render(self.request, 'vince/editgroup.html',
                          {'form': self.form_class(initial=ContactGroup.objects.filter(id=self.kwargs['pk']).values()[0]),
                           'collision': error_str,
                           'contacts': Contact.objects.order_by('vendor_name'),
                           'groups': ContactGroup.objects.all().order_by('name'),
                           'group': group,
                           'groupmembers': groupmembers,
                           'members': members
                          })

        initial_members = GroupMember.objects.filter(group=current_group).count()
        if current_group.name != self.request.POST['name']:
            if group_name_exists(self.request.POST['name']):
                self.error = "Group name already exists"
                return form.invalid(self.form)
            _add_group_activity(self.request.user, 4, current_group, 'modified group name')
            current_group.name = self.request.POST['name']
            current_group.save()
        if current_group.description != self.request.POST['description']:
            _add_group_activity(self.request.user, 4, current_group, 'modified group description')
            current_group.description = self.request.POST['description']
            current_group.save()
        if current_group.comment != self.request.POST['comment']:
            _add_group_activity(self.request.user, 4, current_group, 'modified comment')
            current_group.comment = self.request.POST['comment']
            current_group.save()

        # who are the current members in this group:
        members = GroupMember.objects.filter(group=self.kwargs['pk']).exclude(contact__isnull=True).values_list('contact', flat=True)
        contacts = Contact.objects.filter(id__in=members).values_list('vendor_name', flat=True)
        # the groups in the group - give the list of groupduplicates
        groupdups = GroupMember.objects.filter(group=self.kwargs['pk']).values_list('group_member', flat=True)
        duplicates = GroupDuplicate.objects.filter(group__in=groupdups).values_list('group', flat=True)
        groupmembers = ContactGroup.objects.filter(id__in=duplicates).values_list('name', flat=True)
        allmembers = list(contacts)+list(groupmembers)
        logger.debug(allmembers)
        added=0
        contactlist = self.request.POST.getlist('group_select[]')
        for group in contactlist:
            if group in allmembers:
                continue
            contact = Contact.objects.filter(vendor_name=group).first()
            if contact:
                newmember=GroupMember(group=current_group,
                                      contact=contact,
                                      user_added=self.request.user,
                                      member_type=contact.vendor_type)
                newmember.save()
                if newmember.id:
                    added = added + 1
                    text = "added %s to %s group" % (contact.vendor_name, current_group.name)
                    _add_activity(self.request.user, 4, contact, text)
                else:
                    logger.debug("NOT ADDED")
            else:
                logger.debug("this is a group")
                contact = ContactGroup.objects.filter(name=group).first()
                if contact:
                    groupdup = GroupDuplicate.objects.filter(group=contact).first()
                    newmember = GroupMember(group=current_group,
                                            group_member=groupdup,
                                            user_added=self.request.user,
                                            member_type="Group")
                    newmember.save()
                    if newmember.id:
                        text = "added %s to %s group" % (groupdup.group.name, current_group.name)
                        _add_group_activity(self.request.user, 2, groupdup.group, text)
                        added=added+1
            text = "Added %s to group" % group
            _add_group_activity(self.request.user, 2, current_group, text)

        logger.debug("added %d members" % added)
        removed = 0
        for group in allmembers:
            if group not in contactlist:
                #remove this contact
                contact = Contact.objects.filter(vendor_name=group).first()
                if contact:
                    grouptorm = GroupMember.objects.filter(group=current_group, contact=contact)
                    grouptorm.delete()
                    removed += 1
                    text = "removed %s from %s group" % (group, current_group.name)
                    _add_group_activity(self.request.user, 3, current_group, text)
                    _add_activity(self.request.user, 5, contact, text)
                else:
                    # this is a group - remove it
                    grouptorm = ContactGroup.objects.filter(name=group).first()
                    if grouptorm:
                        groupdup = GroupDuplicate.objects.filter(group=grouptorm).first()
                        grouprm = GroupMember.objects.filter(group=current_group, group_member=groupdup).first()
                        if grouprm:
                            grouprm.delete()
                            text = "removed %s from %s group" % (group, current_group.name)
                            _add_group_activity(self.request.user, 3, current_group, text)
                            _add_group_activity(self.request.user, 3, grouptorm, text)
                            removed += 1

        if added or removed:
            update_srmail_file()
            messages.warning(
                self.request,
                _(f"Updating SRMAIL file due to group membership changes."))
            #get number of members:
            members = GroupMember.objects.filter(group=current_group).count()
            if (initial_members == 0) and members:
                #activate group now that we have members
                current_group.status="Active"
                current_group.save()

        logger.debug("Removed %d members" % removed)
        current_group.version = current_group.version + 1
        current_group.save()
        return redirect("vince:group", current_group.id)

class ApproveContactInfoChangeView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    model = ContactInfoChange
    login_url = "vince:login"
    template_name = "vince/contact_changes.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_queryset(self):
        return ContactInfoChange.objects.filter(contact__vendor_id=self.kwargs['pk']).order_by('-action__created')

    def get_context_data(self, **kwargs):
        context = super(ApproveContactInfoChangeView, self).get_context_data(**kwargs)
        context['contactpage']=1
        context['vccontact'] = VinceCommContact.objects.filter(vendor_id=self.kwargs['pk']).first()
        context['contact'] = Contact.objects.filter(id=self.kwargs['pk']).first()
        fields = 'email', 'email_type', 'name'
        vcemails = set(VinceCommEmail.objects.filter(contact=context['vccontact']).values_list(*fields))
        emails = set(EmailContact.objects.filter(contact=context['contact']).values_list(*fields))
        context['emails'] = emails
        context['emaildiff'] = diff(emails, vcemails)
        fields = 'country_code', 'phone', 'phone_type', 'comment'
        vcphones = set(VinceCommPhone.objects.filter(contact=context['vccontact']).order_by('version').values_list(*fields))
        phones = set(PhoneContact.objects.filter(contact=context['contact']).values_list(*fields))
        context['phones'] = phones
        context['phonediff'] = diff(phones, vcphones)
        fields = 'url',	'description'
        vcphones = set(VinceCommWebsite.objects.filter(contact=context['vccontact']).values_list(*fields))
        phones = set(Website.objects.filter(contact=context['contact']).values_list(*fields))
        context['sites'] = phones
        context['webdiff'] = diff(phones, vcphones)
        fields = 'pgp_key_id', 'pgp_key_data', 'pgp_email'
        vcphones = set(VinceCommPgP.objects.filter(contact=context['vccontact']).values_list(*fields))
        phones = set(ContactPgP.objects.filter(contact=context['contact']).values_list(*fields))
        context['keys'] = phones
        context['pgpdiff'] = diff(phones, vcphones)
        fields = 'country', 'address_type', 'street', 'street2', 'city', 'state', 'zip_code'
        vcphones = set(VinceCommPostal.objects.filter(contact=context['vccontact']).values_list(*fields))
        phones = set(PostalAddress.objects.filter(contact=context['contact']).values_list(*fields))
        context['postals'] = phones
        context['postaldiff'] = diff(phones, vcphones)

        return context

class ViewAndApproveChangesView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/preview_contact.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ViewAndApproveChangesView, self).get_context_data(**kwargs)
        context['contactpage']=1
        context['vccontact'] = VinceCommContact.objects.filter(vendor_id=self.kwargs['pk']).first()
        context['contact'] = Contact.objects.filter(id=self.kwargs['pk']).first()
        return context

    def post(self, request, *args, **kwargs):
        vccontact = VinceCommContact.objects.filter(vendor_id=self.kwargs['pk']).first()
        contact = Contact.objects.filter(id=self.kwargs['pk']).first()
        fields = 'email', 'email_type', 'name'
        vcemails = list(VinceCommEmail.objects.filter(contact=vccontact).values_list(*fields))
        emails = list(EmailContact.objects.filter(contact=contact).values_list(*fields))
        emaildiff = diff(emails, vcemails)
        error = False
        if emaildiff:
            groupadmin = list(GroupAdmin.objects.filter(contact=contact).values_list('email__email', flat=True))
            logger.debug(groupadmin)
            email_list = []
            vc_emails = VinceCommEmail.objects.filter(contact=vccontact)
            for email in vc_emails:
                email_list.append(EmailContact(contact=contact,
                                               email=email.email,
                                               email_type=email.email_type,
                                               name=email.name,
                                               user_added=self.request.user,
	                                       email_function=email.email_function,
                                               status = email.status,
                                               email_list = email.email_list))
            try:
                with transaction.atomic():
                # Replace the old with the new
                    EmailContact.objects.filter(contact=contact.id).delete()
                    EmailContact.objects.bulk_create(email_list)
            except IntegrityError:
                messages.error(self.request,
                               _(f"Error saving Email information"))
                error = True

            if groupadmin:
                logger.debug(groupadmin)
                for ga in groupadmin:
                    logger.debug(f"looking for {ga}")
                    ec = EmailContact.objects.filter(contact=contact, email=ga).first()
                    if ec:
                        logger.debug("adding new groupadmin")
                        new_group_admin = GroupAdmin.objects.update_or_create(contact=contact, email=ec)
                    else:
                        # remove this email's groupadmin privs
                        vinny_email_contact = VinceCommEmail.objects.filter(email=ga, contact=vccontact).first()
                        current = VinceCommGroupAdmin.objects.filter(email=vinny_email_contact, contact=vinny_email_contact).first()
                        if current:
                            current.delete()
                        #is this user a groupadmin of any other vendors, if not remove groupadmin group privs
                        gadmin = VinceCommGroupAdmin.objects.filter(email__email=ga)
                        if gadmin == None:
                            groupadmin = Group.objects.using('vincecomm').filter(name='vince_group_admin').first()
                            user = User.objects.using('vincecomm').filter(username = ga).first()
                            if user:
                                groupadmin.user_set.remove(user)

                        messages.warning(
                            self.request,
                            _(f"The email {ga} has been removed. Please reassign a new group admin."))
            # make sure group admins are in sync
            vc_admins = VinceCommGroupAdmin.objects.filter(contact=vccontact)
            for ad in vc_admins:
                trad = GroupAdmin.objects.filter(contact=contact, email__email=ad.email.email).first()
                if trad:
                    continue
                else:
                    ec = EmailContact.objects.filter(contact=contact,email=ad.email.email).first()
                    if ec:
                        new_group_admin = GroupAdmin.objects.update_or_create(contact=contact, email=ec)

        fields = 'country_code', 'phone', 'phone_type', 'comment'
        vcphones = list(VinceCommPhone.objects.filter(contact=vccontact).values_list(*fields))
        phones = list(PhoneContact.objects.filter(contact=contact).values_list(*fields))
        phonediff = diff(phones, vcphones)
        if phonediff:
            vc_phones = VinceCommPhone.objects.filter(contact=vccontact)
            phone_lists=[]
            for phone in vc_phones:
                phone_lists.append(PhoneContact(contact=contact,
                                           country_code=phone.country_code,
	                                   phone=phone.phone,
                                           phone_type=phone.phone_type,
                                           comment=phone.comment,
                                           user_added=self.request.user))
            try:
                with transaction.atomic():
                    # Replace the old with the new
                    PhoneContact.objects.filter(contact=contact.id).delete()
                    PhoneContact.objects.bulk_create(phone_lists)
            except IntegrityError:
                messages.error(self.request,
                               _(f"Error saving Phone information"))
                error = True

        fields = 'url', 'description'
        vcphones = list(VinceCommWebsite.objects.filter(contact=vccontact).values_list(*fields))
        phones = list(Website.objects.filter(contact=contact).values_list(*fields))
        webdiff = diff(phones, vcphones)
        if webdiff:
            vcsites = VinceCommWebsite.objects.filter(contact=vccontact)
            site_lists = []
            for site in vcsites:
                site_lists.append(Website(contact=contact,
                                          url=site.url,
                                          description=site.description,
                                          user_added=self.request.user))
            try:
                with transaction.atomic():
                    Website.objects.filter(contact=contact.id).delete()
                    Website.objects.bulk_create(site_lists)
            except:
                messages.error(self.request,
                               _(f"Error saving Website information"))
                error = True

        fields = 'pgp_key_id', 'pgp_key_data'
        vcphones = list(VinceCommPgP.objects.filter(contact=vccontact).values_list(*fields))
        phones = list(ContactPgP.objects.filter(contact=contact).values_list(*fields))
        pgpdiff = diff(phones, vcphones)
        logger.debug(pgpdiff)
        if pgpdiff:
            vcpgp = VinceCommPgP.objects.filter(contact=vccontact)
            pgp_list = []
            for pgp in vcpgp:
                # this field is not stored in vincecomm
                comment = ContactPgP.objects.filter(contact=contact).values_list('pgp_fingerprint', flat=True).order_by('id')
                if comment:
                    comment = comment[0]
                else:
                    comment = ""
                logger.debug(comment)
                pgp_list.append(ContactPgP(contact=contact,
                                           pgp_key_id=pgp.pgp_key_id,
                                           pgp_protocol=pgp.pgp_protocol,
                                           startdate=pgp.startdate,
                                           enddate=pgp.enddate,
                                           pgp_key_data=pgp.pgp_key_data,
                                           pgp_fingerprint=comment,
                                           revoked=pgp.revoked,
                                           pgp_email=pgp.pgp_email,
                                           user=self.request.user))
                logger.debug(pgp_list)
            try:
                with transaction.atomic():
                    ContactPgP.objects.filter(contact=contact.id).delete()
                    ContactPgP.objects.bulk_create(pgp_list)
            except:
                logger.debug(traceback.format_exc())
                messages.error(self.request,
                               _(f"Error saving PGP information"))
                error = True

        fields = 'country', 'address_type', 'street', 'street2', 'city', 'state', 'zip_code'
        vcphones = list(VinceCommPostal.objects.filter(contact=vccontact).values_list(*fields))
        phones = list(PostalAddress.objects.filter(contact=contact).values_list(*fields))
        postaldiff = diff(phones, vcphones)
        if postaldiff:
            vcpostals = VinceCommPostal.objects.filter(contact=vccontact)
            postal_list = []
            for p in vcpostals:
                postal_list.append(PostalAddress(contact=contact,
                                                 country=p.country,
                                                 address_type=p.address_type,
                                                 street=p.street,
                                                 street2=p.street2,
                                                 city=p.city,
                                                 state=p.state,
                                                 zip_code=p.zip_code,
                                                 user_added=self.request.user))
            try:
                with transaction.atomic():
                # Replace the old with the new
                    PostalAddress.objects.filter(contact=contact.id).delete()
                    PostalAddress.objects.bulk_create(postal_list)
            except IntegrityError:
                messages.error(self.request,
                               _(f"Error saving Postal Information"))
                error = True

        if emaildiff or pgpdiff:
            update_srmail_file()
            messages.warning(
                self.request,
                _(f"Updating SRMAIL file due to changes in contact information."))

        if not error:
            #approve changes
            changes = ContactInfoChange.objects.filter(contact=vccontact)
            for change in changes:
                _add_activity(self.request.user, 3, contact, f"approved {change.field} {change.model} modifications")
                change.approved = True
                change.save()

        #update modified date
        contact.modified = timezone.now()
        contact.save()

        return redirect("vince:contact", contact.id)


class RejectChangeView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/reject_contact.html"

    def test_func(self):
    	return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RejectChangeView, self).get_context_data(**kwargs)
        context['contactpage']=1
        context['contact'] = Contact.objects.filter(id=self.kwargs['pk']).first()
        return context

    def post(self, request, *args, **kwargs):
        vccontact = VinceCommContact.objects.filter(vendor_id=self.kwargs['pk']).first()
        contact = Contact.objects.filter(id=self.kwargs['pk']).first()
        fields = 'email', 'email_type', 'name'
        vcemails = list(VinceCommEmail.objects.filter(contact=vccontact).values_list(*fields))
        emails = list(EmailContact.objects.filter(contact=contact).values_list(*fields))
        emaildiff = diff(emails, vcemails)
        if emaildiff:
            email_list = []
            vc_emails = EmailContact.objects.filter(contact=contact)
            for email in vc_emails:
                email_list.append(VinceCommEmail(contact=vccontact,
                                                 email=email.email,
                                                 email_type=email.email_type,
                                                 name=email.name,
                                                 email_function=email.email_function,
                                                 status = email.status,
                                                 email_list = email.email_list))
            try:
                with transaction.atomic():
                # Replace the old with the new
                    VinceCommEmail.objects.filter(contact=vccontact.id).delete()
                    VinceCommEmail.objects.bulk_create(email_list)
            except IntegrityError:
                return HttpResponseServerError()
        fields = 'country_code', 'phone', 'phone_type', 'comment'
        vcphones = list(VinceCommPhone.objects.filter(contact=vccontact).values_list(*fields))
        phones = list(PhoneContact.objects.filter(contact=contact).values_list(*fields))
        phonediff = diff(phones, vcphones)
        if phonediff:
            vc_phones = PhoneContact.objects.filter(contact=contact)
            phone_lists=[]
            for phone in vc_phones:
                phone_lists.append(VinceCommPhone(contact=vccontact,
                                           country_code=phone.country_code,
                                           phone=phone.phone,
                                           phone_type=phone.phone_type,
                                           comment=phone.comment))
            try:
                with transaction.atomic():
                    # Replace the old with the new
                    VinceCommPhone.objects.filter(contact=contact.id).delete()
                    VinceCommPhone.objects.bulk_create(phone_lists)
            except IntegrityError:
                return HttpResponseServerError()
        fields = 'url', 'description'
        vcphones = list(VinceCommWebsite.objects.filter(contact=vccontact).values_list(*fields))
        phones = list(Website.objects.filter(contact=contact).values_list(*fields))
        webdiff = diff(phones, vcphones)
        if webdiff:
            vcsites = Website.objects.filter(contact=contact)
            site_lists = []
            for site in vcsites:
                site_lists.append(VinceCommWebsite(contact=vccontact,
                                                   url=site.url,
                                                   description=site.description))
            try:
                with transaction.atomic():
                    VinceCommWebsite.objects.filter(contact=vccontact.id).delete()
                    VinceCommWebsite.objects.bulk_create(site_lists)
            except:
                return HttpResponseServerError()
        fields = 'pgp_key_id', 'pgp_key_data'
        vcphones = list(VinceCommPgP.objects.filter(contact=vccontact).values_list(*fields))
        phones = list(ContactPgP.objects.filter(contact=contact).values_list(*fields))
        pgpdiff = diff(phones, vcphones)
        if pgpdiff:
            vcpgp = ContactPgP.objects.filter(contact=contact)
            pgp_list = []
            for pgp in vcpgp:
                pgp_list.append(VinceCommPgP(contact=vccontact,
                                             pgp_key_id=pgp.pgp_key_id,
                                             pgp_protocol=pgp.pgp_protocol,
                                             startdate=pgp.startdate,
                                             enddate=pgp.enddate,
                                             pgp_email=pgp.pgp_email,
                                             pgp_key_data=pgp.pgp_key_data,
                                             revoked=pgp.revoked))
            try:
                with transaction.atomic():
                    VinceCommPgP.objects.filter(contact=vccontact.id).delete()
                    VinceCommPgP.objects.bulk_create(pgp_list)
            except:
                return HttpResponseServerError()

        fields = 'country', 'address_type', 'street', 'street2', 'city', 'state', 'zip_code'
        vcphones = list(VinceCommPostal.objects.filter(contact=vccontact).values_list(*fields))
        phones = list(PostalAddress.objects.filter(contact=contact).values_list(*fields))
        postaldiff = diff(phones, vcphones)
        if postaldiff:
            vcpostals = PostalAddress.objects.filter(contact=contact)
            postal_list = []
            for p in vcpostals:
                postal_list.append(VinceCommPostal(contact=vccontact,
                                                   country=p.country,
                                                   address_type=p.address_type,
                                                   street=p.street,
                                                   street2=p.street2,
                                                   city=p.city,
	                                           state=p.state,
                                                   zip_code=p.zip_code))
            try:
                with transaction.atomic():
                # Replace the old with the new
                    VinceCommPostal.objects.filter(contact=vccontact.id).delete()
                    VinceCommPostal.objects.bulk_create(postal_list)
            except IntegrityError:
                return HttpResponseServerError()

        #approve changes
        changes = ContactInfoChange.objects.filter(contact=vccontact)
        for change in changes:
            _add_activity(self.request.user, 3, contact, f"rejected {change.field} {change.model} modifications")
            change.delete()
        return redirect("vince:contact", contact.id)

class ContactCasesView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    model = VulnerableVendor
    login_url = "vince:login"
    template_name = "vince/contact_cases.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ContactCasesView, self).get_context_data(**kwargs)
        context['contactpage']=1
        context['contact'] = self.contact
        old_cases = self.request.GET.get('old')
        if old_cases:
            context['participants'] = self.get_queryset()
            context['old'] = 1
        else:
            vc_contact = VinceCommContact.objects.using('vincecomm').filter(vendor_id=self.kwargs['pk']).first()
            gc = GroupContact.objects.filter(contact=vc_contact).first()
            if gc:
                context['participants'] = CaseMember.objects.filter(group=gc.group).order_by('-case__modified')
        return context

    def get_queryset(self):
        self.contact = get_object_or_404(Contact, id=self.kwargs['pk'])
        return VulnerableVendor.objects.filter(contact=self.kwargs['pk']).order_by('-date_modified')


class RemoveEmailFromContact(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/confirm_rm_email.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RemoveEmailFromContact, self).get_context_data(**kwargs)
        context['contact'] = get_object_or_404(Contact, id=self.kwargs['pk'])
        context['email'] = get_object_or_404(EmailContact, id=self.kwargs['email'])
        context['vcuser'] = User.objects.using('vincecomm').filter(email=context['email'].email).first()
        return context
    
    def post(self, request, *args, **kwargs):
        contact = get_object_or_404(Contact, id=self.kwargs['pk'])
        email = get_object_or_404(EmailContact, id=self.kwargs['email'])

        _add_activity(self.request.user, 3, contact, f"removed email: {email.email}")
	#close any bounces that may be associated with this email
        bn = BounceEmailNotification.objects.filter(email=email.email, action_taken=False)
        for b in bn:
            b.action_taken=True
            b.save()
        #remove group permissions if this user has any
        vinny_contact = VinceCommContact.objects.filter(vendor_id=self.kwargs['pk']).first()
        _remove_group_permissions(email.email, vinny_contact, self.request.user)
        #is this uer a groupadmin?
        cga = GroupAdmin.objects.filter(contact=contact, email__email=email.email)
        if cga:
            _remove_groupadmin(email, contact)
            _remove_groupadmin_perms(email)
        
        #remove address from VINCEComm
        vcemail = VinceCommEmail.objects.filter(email=email.email, contact=vinny_contact).first()

        vcemail.delete()
        
        email.delete()

        #if we've removed all emails, this should contact should deactivate
        all_emails = EmailContact.objects.filter(contact=contact).count()
        if all_emails == 0:
            contact.active=False
            contact.save()
            messages.warning(self.request,
                             _(f"Deactivating contact due to removal of all email addresses."))

        update_srmail_file()
        return redirect("vince:contact", contact.id)

class AddEmailToContact(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/add_email_contact.html"
    form_class = EmailContactForm
    
    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(AddEmailToContact, self).get_context_data(**kwargs)
        context['contact'] = get_object_or_404(Contact, id=self.kwargs['pk'])
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        contact = get_object_or_404(Contact, id=self.kwargs['pk'])
        vinny_contact = VinceCommContact.objects.filter(vendor_id=self.kwargs['pk']).first()
        email_type = self.request.POST.get('email_type')
        email = self.request.POST.get('email')
        email = email.strip()
        
        #make sure email doesn't already exist in this contact?
        
        prev_email = EmailContact.objects.filter(contact=contact, email=email).first()
        if prev_email:
            return JsonResponse({'text':"This email has already been added to this contact."}, status=200)
        #make sure this email is not in the verification process
        prev_email = ContactAssociation.objects.filter(contact=contact, user=email, complete=False)
        if prev_email:
            return JsonResponse({'text':"This user is already in the process of being associated with this vendor."}, status=200)       


        if contact.vendor_type == "Contact":
            #notification only
            email = EmailContact(email=email,
                                 email_list = False,
                                 name=self.request.POST.get('name'),
                                 email_function="TO",
                                 contact=contact)
            email.save()

            vc_email = VinceCommEmail(contact=vinny_contact,
                                      email=email,
                                      email_function="TO",
                                      email_list=False,
                                      name=self.request.POST.get('name'))
            vc_email.save()

            _add_activity(self.request.user, 3, contact, f"added email: {email}")

            messages.success(
                self.request,
                _(f"Email address added to contact."))

            contact.active=True
            contact.save()

            update_srmail_file()
            
            return JsonResponse({'refresh':1}, status=200)
        
        if email_type == "User":
                
            #does this contact have an admin?
            admins = list(GroupAdmin.objects.filter(contact=contact).values_list('email__email', flat=True))
            if self.request.POST.get('msg'):                
                #we're on second post at this point
                users = User.objects.using('vincecomm').filter(email__in=admins).values_list('id', flat=True)
                if users:
                    sender = User.objects.using('vincecomm').filter(email=self.request.user.email).first()
                    msg = Message.new_message(sender, users, None, "VINCE Vendor User Request", self.request.POST['msg'])
                    user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
                    if user_groups:
                        msg.thread.from_group=user_groups[0].groupsettings.contact.vendor_name
                    msg.thread.save()

                    #create Ticket
                    admins = ", " .join(admins)
                    assoc = ContactAssociation(contact=contact,
                                               user=email,
                                               initiated_by=self.request.user,
                                               approval_requested=True,
                                               email=f"Sent message to admins: {admins}")
                    assoc.save()
                    ticket = Ticket(title=f"Contact Verification Process Initiated for {email}",
                                    description=f"Adding user {email} to {contact.vendor_name}",
                                    status = Ticket.CLOSED_STATUS,
                                    queue = get_vendor_queue(self.request.user),
                                    submitter_email = self.request.user.email,
                                    assigned_to=self.request.user)
                    ticket.save()
                    assoc.ticket = ticket
                    assoc.save()

                    
                    fup = FollowUp(title=f"Sent message to {contact.vendor_name} admins: {admins}",
                                   comment=self.request.POST.get('msg'), ticket=ticket,
                                   user=self.request.user)
                    fup.save()
                    tm = TicketThread(thread=msg.thread.id,
                                      ticket=ticket.id)

                    tm.save()
                    fm = FollowupMessage(followup=fup,
                                         msg=msg.id)
                    fm.save()
                    
                    ticket.status = Ticket.CLOSED_STATUS
                    ticket.save()

                    _add_activity(self.request.user, 3, contact, f"started contact verification process for: {email}")

                return JsonResponse({'ticket': reverse("vince:ticket", args=[ticket.id])}, status=200)

            num_admins = len(admins)
            admins = ", " .join(admins)
            action_link = None

            if num_admins:
                if num_admins > 1:
                    text = f"There are {num_admins} admins for this contact: {admins}."
                else:
                    text = f"There is {num_admins} admin for this contact: {admins}."
                text = f"{text} Do you want to send a message to the admin(s) to add this user?"
                #msg_link = reverse("vince:msgadmin")
                tmpl = EmailTemplate.objects.filter(template_name='vendor_admin_user_request').first()
                if tmpl:
                    team_sig = get_team_sig(self.request.user)
                    msg_body = tmpl.plain_text.replace('[EMAIL]', self.request.POST.get('email')).replace('[VENDOR]', contact.vendor_name).replace('[team_signature]', team_sig)
                else:
                    msg_body = "A 'vendor_admin_user_request' template has not been created. Please add a template or fill in the message to send the admin"
                return JsonResponse({'text':text, "action_link": action_link, 'contact_link': reverse("vince:contact", args=[contact.id]), 'email_link': reverse("vince:initcontactverify", args=[contact.id])+f"?email={self.request.POST.get('email')}", 'msg_body':msg_body}, status=200)

            else:
                # no admins - so inititate process....
                #does this contact have any email addresses?
                emails = EmailContact.objects.filter(contact=contact, status=True).count()
                if emails:
                    messages.warning(
                        self.request,
                        _(f"This contact does not have a group admin. Initiate contact verification process to add user."))
                
                    return JsonResponse({'ticket': reverse("vince:initcontactverify", args=[contact.id])+"?email="+email}, status=200)
                else:
                    return JsonResponse({'text':"In order to add a user, you must add an email address to contact to verify this user works for this organization. Try adding a notification-only email address before attempting to verify a user.", 'bypass': reverse("vince:initcontactverify", args=[contact.id])+f"?email={self.request.POST.get('email')}&bypass=1"},  status=200)

        else:
            #notification only
            email = EmailContact(email=email,
                                 email_list = True,
                                 name="Notification-Only",
                                 email_function="TO",
                                 contact=contact)
            email.save()

            vc_email = VinceCommEmail(contact=vinny_contact,
                                      email=email,
                                      email_function="TO",
                                      email_list=True,
                                      name="Notification Email")
            vc_email.save()

            _add_activity(self.request.user, 3, contact, f"added notification-only email: {email}")
            
            messages.success(
                self.request,
                _(f"Notification-only email address added to contact."))

            contact.active=True
            contact.save()

            update_srmail_file()
            
            return JsonResponse({'refresh':1}, status=200)

        
    
class ContactDetailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = Contact
    login_url = "vince:login"
    template_name = "vince/contact.html"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ContactDetailView, self).get_context_data(**kwargs)
        context['contactpage']=1
        logger.debug("IN CONTACT PAGE")
        context['groups'] = [group.group.name for group in GroupMember.objects.filter(contact=self.kwargs['pk'])]
        
        context['activity_list'] = Activity.objects.filter(contact=self.kwargs['pk']).order_by('-action_ts')
        context['cases'] = VulnerableVendor.objects.filter(contact=self.kwargs['pk'], case__lotus_notes=True).order_by('-date_modified')[:20]
        tkt_list = TicketContact.objects.filter(contact=self.kwargs['pk']).values_list('ticket', flat=True)
        context['ticket_list'] = Ticket.objects.filter(pk__in=tkt_list).order_by('-modified')[:50]
        context['assignable_users'] = EmailContact.objects.filter(contact=self.kwargs['pk'], email_list=False, status=True)
        context['contacttags'] = [tag.tag for tag in ContactTag.objects.filter(contact__id=self.kwargs['pk'])]
        context['othertags'] = [tag.tag for tag in TagManager.objects.filter(tag_type=2).exclude(tag__in=context['contacttags']).order_by('tag').distinct('tag')]
        emails = EmailContact.objects.filter(contact__id=self.kwargs['pk']).values_list('email', flat=True)
        context['associations'] = ContactAssociation.objects.filter(contact__id=self.kwargs['pk'], complete=False).exclude(user__in=emails)
        context['vinceusers'] = User.objects.filter(is_active=True, groups__name='vince')
        context['all_groups'] = [group.name for group in ContactGroup.objects.all().exclude(name__in=context['groups'])]
        context['groupadmins'] = [admin.email.email for admin in GroupAdmin.objects.filter(contact=self.kwargs['pk'])]
        vc_contact = VinceCommContact.objects.using('vincecomm').filter(vendor_id=self.kwargs['pk']).first()
        if vc_contact:
            logger.debug("VINCE COMM CONTACT")
            gc = GroupContact.objects.using('vincecomm').filter(contact=vc_contact).first()
            context['vc_contact'] = vc_contact
            if vc_contact.vendor_type != 'Contact' and gc:
                context['participants'] = CaseMember.objects.filter(group=gc.group).order_by('-case__modified')[:20]
                logger.debug(context['participants'])
                context['vince_users'] = list(User.objects.using('vincecomm').filter(groups=gc.group).values_list('username', flat=True))
            elif vc_contact.vendor_type in ['Contact', 'User']:
                #this is prob a contact
                context['vince_users'] = list(User.objects.using('vincecomm').filter(email__in=list(emails)).values_list('username', flat=True))
            #Check on unapproved changes
            changes = ContactInfoChange.objects.filter(contact=vc_contact)
            allchanges = chain(context['activity_list'], changes)
            qs = sorted(allchanges,
                        key=lambda instance: instance.action_ts,
                        reverse=True)
            context['activity_list'] = qs
            context['changes'] = changes.filter(approved=False)

        return context

    def post(self, request, *args, **kwargs):
        contact = get_object_or_404(Contact, id=self.kwargs['pk'])
        if not get_contact_write_perms(self.request.user):
            return JsonResponse({'error': "You are not permitted to perform this action."}, status=500)

        if request.POST.get('del_admin'):
            user = request.POST.get('user')
            cga = GroupAdmin.objects.filter(contact=contact, email__email=user).first()
            if cga:
                _remove_groupadmin(cga.email, contact)
                _remove_groupadmin_perms(cga.email)
                cga.delete()
                _add_activity(self.request.user, 3, contact, f"removed {user} as VinceComm group administrator")
        elif request.POST.get('add_admin'):
            user = request.POST.get('user')
            ec = EmailContact.objects.filter(email=user, contact=contact).first()
            if ec:
                cga, created = GroupAdmin.objects.update_or_create(contact=contact, email=ec)
                _add_groupadmin_perms(ec)
                _add_groupadmin(cga.email, contact)
                _add_activity(self.request.user, 3, contact, f"added {user} as VinceComm group administrator")
            else:
                logger.warning("NO EmailContact with this username")
                return JsonResponse({'error': "This user is not listed in the Emails above.  Please add user's email to this contact."}, status=500)
        elif request.POST.get('add_tag'):
            user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            new_tag = self.request.POST.get('tag').lower()
            if len(new_tag) < 50:
                if TagManager.objects.filter(tag=new_tag, tag_type=2).exists():
                    tag, created = ContactTag.objects.update_or_create(contact=contact, tag=new_tag,
                                                                       defaults={'user':self.request.user})
                    if created:
                        _add_activity(self.request.user, 6, contact, f" tagged contact with {new_tag}")
                else:
                    logger.debug("invalid tag - tag doesn't exist in tag manager")
                    return JsonResponse({'tag': new_tag, 'contact': contact.id, 'error': "Invalid Tag."}, status=401)
            else:
                return JsonResponse({'tag': new_tag, 'error': "Tag is too long. Max 50 characters."}, status=401)
            return JsonResponse({'tag_added': tag.tag, 'contact': contact.id}, status=200)
            
        elif request.POST.get('del_tag'):
            tag = self.request.POST.get('tag')
            try:
                ContactTag.objects.get(tag=tag, contact=contact).delete()
                _add_activity(self.request.user, 6, contact, f" removed tag {tag}")
                return JsonResponse({'tag_deleted': tag, 'contact':contact.id}, status=200)
            except CaseTag.DoesNotExist:
                return JsonResponse({'tag': tag, 'error': f"'{tag}' not assigned to contact"}, status=401)
        return redirect("vince:contact", contact.id)


class ChangeEmailNotifications(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"


    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get(self, request, *args, **kwargs):
        email = get_object_or_404(EmailContact, id=self.kwargs['pk'])
        
        if email.email_function in ["TO", "CC"]:
            email.email_function = "EMAIL"
            email.save()
            _add_activity(self.request.user, 3, email.contact, f"disabled email notifications for {email.email}")
            #change it in VINCECOMM
            vcemail = VinceCommEmail.objects.filter(email=email.email, contact__vendor_id=email.contact.id).first()
            if vcemail:
                vcemail.email_function = "EMAIL"
                vcemail.save()
        else:
            email.email_function = "TO"
            email.save()
            _add_activity(self.request.user, 3, email.contact, f"enabled email notifications for {email.email}")
            #change it in VINCECOMM
            vcemail = VinceCommEmail.objects.filter(email=email.email, contact__vendor_id=email.contact.id).first()
            if vcemail:
                vcemail.email_function = "TO"
                vcemail.save()

        update_srmail_file()
        return redirect("vince:contact", email.contact.id)

    
class EditContact(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView, FormMixin):
    model = Contact
    login_url = "vince:login"
    template_name = 'vince/editcontact.html'
    form_class = ContactForm
    PostalFormSet = inlineformset_factory(Contact, PostalAddress, form=PostalForm, max_num=10, min_num=1, can_delete=True, extra=0)
    PhoneFormSet = inlineformset_factory(Contact, PhoneContact, form=PhoneForm, max_num=10, min_num=1, can_delete=True, extra=0)
    WebFormSet = inlineformset_factory(Contact, Website, form=WebsiteForm, max_num=10, min_num=1, can_delete=True, extra=0)
    PgPFormSet = inlineformset_factory(Contact, ContactPgP, form=ContactPgPForm, max_num=10, min_num=1, can_delete=True, extra=0)
    #EmailFormSet = inlineformset_factory(Contact, EmailContact, form=EmailContactForm, max_num=30, min_num=1, can_delete=True, extra=0)

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)


    def get(self, request, *args, **kwargs):
        contact = Contact.objects.filter(id=self.kwargs['pk']).first()
        if self.request.GET.get('activate'):
            #does this contact have emails?
            emails = EmailContact.objects.filter(contact=contact).count()
            if emails:
                _add_activity(self.request.user, 3, contact, "changed status to ACTIVE")
                contact.active=True
                contact.save()
            else:
                messages.error(
                    self.request,
                    _(f"You cannot activate a contact without email addresses."))

            update_srmail_file()
            return redirect("vince:contact", contact.id)
        elif self.request.GET.get('deactivate'):
            contact.active=False
            contact.save()
            _add_activity(self.request.user, 3, contact, "deactivated contact")

            emails = EmailContact.objects.filter(contact=contact).values_list('email', flat=True)
            vince_users = User.objects.using('vincecomm').filter(email__in=list(emails), is_active=True)

            if vince_users:
                messages.warning(
                    self.request,
                    _(f"You are deactivating a contact with active users. Remove users from this contact if they should not access cases associated with this contact."))

            update_srmail_file()
            return redirect("vince:contact", contact.id)

        return super().get(request, *args, **kwargs)
    
    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        contact = Contact.objects.filter(id=self.kwargs['pk']).first()
        phones = PhoneContact.objects.filter(contact=self.kwargs['pk'])
        postal = PostalAddress.objects.filter(contact=self.kwargs['pk'])
        website = Website.objects.filter(contact=self.kwargs['pk'])
        pgp = ContactPgP.objects.filter(contact=self.kwargs['pk'])
        #email = EmailContact.objects.filter(contact=self.kwargs['pk']).order_by('-email_function')
        forms = {'form': form,
                'postal_formset': self.PostalFormSet(prefix='postal', queryset=postal, instance=contact),
                 'phone_formset': self.PhoneFormSet(prefix='phone', queryset=phones, instance=contact),
                 'web_formset': self.WebFormSet(prefix='web', queryset=website, instance=contact),
                 'pgp_formset': self.PgPFormSet(prefix='pgp', queryset=pgp, instance=contact),
                 'contact': Contact.objects.filter(id=self.kwargs['pk']).first()}
        #'email_formset': self.EmailFormSet(prefix='email', queryset=email, instance=contact)}
        return render(self.request, 'vince/editcontact.html', forms)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        logger.debug("VALID FORM")
        contact = Contact.objects.filter(id=self.kwargs['pk']).first()
        vinny_contact = VinceCommContact.objects.filter(vendor_id=self.kwargs['pk']).first()

        some_changes = False
        
        phones = PhoneContact.objects.filter(contact=self.kwargs['pk'])
        postal = PostalAddress.objects.filter(contact=self.kwargs['pk'])
        website = Website.objects.filter(contact=self.kwargs['pk'])
        pgp = ContactPgP.objects.filter(contact=self.kwargs['pk'])
        #email = EmailContact.objects.filter(contact=self.kwargs['pk'])

        postalformset = self.PostalFormSet(self.request.POST, prefix='postal', queryset=postal, instance=contact)
        phoneformset = self.PhoneFormSet(self.request.POST, prefix='phone', queryset=phones, instance=contact)
        webformset = self.WebFormSet(self.request.POST, prefix='web', queryset=website, instance=contact)
        pgpformset = self.PgPFormSet(self.request.POST, prefix='pgp', queryset=pgp, instance=contact)
        #emailformset = self.EmailFormSet(self.request.POST, prefix='email', queryset=email, instance=contact)

        logger.debug(vinny_contact)

        logger.debug(contact.version)
        logger.debug(self.request.POST['version'])

        if contact.version != int(self.request.POST['version']):
            error_str = "Someone beat you to editing this contact. View the most recent details and retry editing this contact."
            forms = {'form': self.form_class(initial=Contact.objects.filter(id=self.kwargs['pk']).values()[0]), 'collision': error_str,
                     'postal_formset': self.PostalFormSet(prefix='postal', queryset=postal),
                     'phone_formset': self.PhoneFormSet(prefix='phone', queryset=phones),
                     'web_formset': self.WebFormSet(prefix='web', queryset=website),
                     'pgp_formset': self.PgPFormSet(prefix='pgp', queryset=pgp),
                     'contact': Contact.objects.filter(id=self.kwargs['pk']).first()}
            #'email_formset': self.EmailFormSet(prefix='email', queryset=email)}
            return render(self.request, 'vince/editcontact.html', forms)

        groupadmins = []
        gas = GroupAdmin.objects.filter(contact=contact)
        if gas:
            for ga in gas:
                groupadmins.append(ga.email.email)
        """        
        if not(emailformset.is_valid()):
            logger.debug(emailformset.errors)
            if active:
                logger.debug("email is invalid")
                error_str=f"Check required emails {emailformset.errors}"
                forms = {'form': form, 'email_error': error_str,
                         'postal_formset': self.PostalFormSet(prefix='postal', queryset=postal, instance=contact),
                         'phone_formset': self.PhoneFormSet(prefix='phone', queryset=phones, instance=contact),
                         'web_formset': self.WebFormSet(prefix='web', queryset=website, instance=contact),
                         'pgp_formset': self.PgPFormSet(prefix='pgp', queryset=pgp, instance=contact),
                         'contact': Contact.objects.filter(id=self.kwargs['pk']).first(),
                         'email_formset': self.EmailFormSet(prefix='email', queryset=email, instance=contact)}
                return render(self.request, 'vince/editcontact.html', forms)
        """
        
        vinny_postal=[]
        for f in postalformset:
            if f.is_valid():
                cd = f.cleaned_data
                old = cd.get('id')
                if old:
                    nochanges = all([old.country == cd['country'],
                                     old.primary == cd['primary'],
                                     old.address_type == cd['address_type'],
                                     old.street == cd['street'],
                                     old.street2 == cd['street2'],
                                     old.city == cd['city'],
                                     old.state == cd['state'],
                                     old.zip_code == cd['zip_code']])
                    if nochanges and not(cd['DELETE']):
                        vinny_postal.append(VinceCommPostal(contact=vinny_contact,
                                                    country=cd['country'],
                                                    address_type=cd['address_type'],
                                                    street=cd['street'],
                                                    street2=cd['street2'],
                                                    city=cd['city'],
                                                    state=cd['state'],
                                                    zip_code=cd['zip_code']))
                        continue
                    if cd['DELETE']:
                        _add_activity(self.request.user, 3, contact, f"removed address {cd['street']} {cd['city']} {cd['state']} {cd['zip_code']}")
                        old.delete()
                        continue
                    else:
                        _add_activity(self.request.user, 3, contact, f"modified address from {old.street} {old.city}, {old.state} {old.zip_code} {old.country} to {cd['street']} {cd['city']} {cd['state']} {cd['zip_code']} {cd['country']}")
                else:
                    _add_activity(self.request.user, 3, contact, f"added address {cd['street']} {cd['city']} {cd['state']} {cd['zip_code']}")

                vinny_postal.append(VinceCommPostal(contact=vinny_contact,
                                                    country=cd['country'],
                                                    address_type=cd['address_type'],
                                                    street=cd['street'],
                                                    street2=cd['street2'],
                                                    city=cd['city'],
                                                    state=cd['state'],
                                                    zip_code=cd['zip_code']))


                f.save()
                some_changes=True

            else:
                logger.debug(f.errors)

        try:
            with transaction.atomic():
                VinceCommPostal.objects.filter(contact__id=vinny_contact.id).delete()
                VinceCommPostal.objects.bulk_create(vinny_postal)
        except IntegrityError:
            return HttpResponseServerError()

        vinny_phones = []
        for f in phoneformset:
            if f.is_valid():
                cd = f.cleaned_data
                old = cd.get('id')
                if old:
                    nochanges = all([old.country_code == cd['country_code'],
                                     old.phone == cd['phone'],
                                     old.phone_type == cd['phone_type'],
                                     old.comment == cd['comment']
                    ])
                    if nochanges and not(cd['DELETE']):
                        vinny_phones.append(VinceCommPhone(contact=vinny_contact,
                                                           country_code=cd['country_code'],
                                                           phone=cd['phone'],
                                                           phone_type=cd['phone_type'],
                                                           comment=cd['comment']))
                        continue
                    if cd['DELETE']:
                        _add_activity(self.request.user, 3, contact, f"removed phone {cd['country_code']} {cd['phone']} {cd['comment']}")
                        old.delete()
                        continue
                    else:
                        _add_activity(self.request.user, 3, contact, f"modified phone from {old.country_code} {old.phone} {old.phone_type} {old.comment} to {cd['country_code']} {cd['phone']} {cd['phone_type']} {cd['comment']} ")
                else:
                    _add_activity(self.request.user, 3, contact, f"added phone number {cd['country_code']} {cd['phone']} {cd['comment']}")
                f.save()
                vinny_phones.append(VinceCommPhone(contact=vinny_contact,
                                                   country_code=cd['country_code'],
                                                   phone=cd['phone'],
                                                   phone_type=cd['phone_type'],
                                                   comment=cd['comment']))
                some_changes=True
                
            else:
                logger.debug(f.errors)

        try:
            with transaction.atomic():
                # Replace the old with the new
                VinceCommPhone.objects.filter(contact__id=vinny_contact.id).delete()
                VinceCommPhone.objects.bulk_create(vinny_phones)
        except IntegrityError:
            return HttpResponseServerError()

        vinny_webs = []
        for f in webformset:
            if f.is_valid():
                cd = f.cleaned_data
                old = cd.get('id')
                if old:
                    nochanges = all([old.url == cd['url'],
                                     old.description == cd['description']])
                    if nochanges and not(cd['DELETE']):
                        vinny_webs.append(VinceCommWebsite(contact=vinny_contact,
                                                           url=cd['url'],
                                                           description=cd['description']))
                        continue
                    if cd['DELETE']:
                        _add_activity(self.request.user, 3, contact, f"removed web site {old.url} {old.description}")
                        old.delete()
                        continue
                    else:
                        _add_activity(self.request.user, 3, contact, f"modified web site from {old.url} {old.description} to {cd['url']} {cd['description']}")
                else:
                    _add_activity(self.request.user, 3, contact, f"added web site {cd['url']} {cd['description']}")
                f.save()
                vinny_webs.append(VinceCommWebsite(contact=vinny_contact,
                                                   url=cd['url'],
                                                   description=cd['description']))
                some_changes=True
            else:
                logger.debug(f.errors)

        try:
            with transaction.atomic():
                VinceCommWebsite.objects.filter(contact__id=vinny_contact.id).delete()
                VinceCommWebsite.objects.bulk_create(vinny_webs)
        except:
            return HttpResponseServerError()
        """
        email_changes = False
        logger.debug("EMAIL FORMSET")
        vinny_emails = []
        vinny_emails_add = []
        for f in emailformset:
            if f.is_valid():
                cd = f.cleaned_data
                old = cd.get('id')
                if (old):
                    nochanges = all([old.email==cd['email'],
                                     old.email_function==cd['email_function'],
                                     old.name==cd['name'],
                                     old.email_list==cd['email_list'],
                                     old.email_type==cd['email_type'],
                                     old.status == cd['status']])
                    if nochanges and not(cd['DELETE']):
                        vinny_emails.append(VinceCommEmail(contact=vinny_contact,
                                                   email=cd['email'],
                                                   email_type=cd['email_type'],
                                                   name=cd['name'],
                                                   email_function=cd['email_function'],
                                                   status=cd['status'],
                                                   email_list = cd['email_list']))
                        if cd['status'] and cd['email_list']==False:
                            vinny_emails_add.append(cd['email'])
                        continue
                    email_changes=True
                    if (cd['status'] == False) and (old.status != cd['status']):
                        #user update the status to False - check if user and warn
                        check_user = User.objects.using('vincecomm').filter(username__iexact=cd['email']).first()
                        if check_user:
                            messages.warning(
                                self.request,
                                _(f"You updated an active VINCE user's email {cd['email']} to inactive.  This action does not remove this user's access to cases for this Contact.  This can only be done by removing the email entirely or by clicking the user below and using the \"Remove User\" button.")
                            )
                            
                    if cd['DELETE']:
                        # this email has been deleted, don't include it.
                        _add_activity(self.request.user, 3, contact, f"removed email: {old.email}")
                        #close any bounces that may be associated with this email
                        bn = BounceEmailNotification.objects.filter(email=old.email, action_taken=False)
                        for b in bn:
                            b.action_taken=True
                            b.save()
                        #remove group permissions if this user has any
                        _remove_group_permissions(old.email, vinny_contact, self.request.user)
                        old.delete()
                        continue
                    else:
                        _add_activity(self.request.user, 3, contact, f"modified email from {old.email_function}: {old.email} {old.name} {old.email_type} List: {old.email_list} Active: {old.status} to {cd['email_function']}: {cd['email']} {cd['name']} {cd['email_type']} List: {cd['email_list']} Active: {cd['status']}")
                else:
                    _add_activity(self.request.user, 3, contact, f"Added email: {cd['email_function']}: {cd['email']} Active: {cd['status']}")

                f.save()
                vinny_emails.append(VinceCommEmail(contact=vinny_contact,
                                                   email=cd['email'],
                                                   email_type=cd['email_type'],
                                                   name=cd['name'],
                                                   email_function=cd['email_function'],
                                                   status=cd['status'],
                                                   email_list = cd['email_list']))
                if cd['status'] and cd['email_list']==False:
                    vinny_emails_add.append(cd['email'])


        try:
            with transaction.atomic():
                VinceCommEmail.objects.filter(contact__id=vinny_contact.id).delete()
                VinceCommEmail.objects.bulk_create(vinny_emails)
        except:
            return HttpResponseServerError()

        # check permissions on users associated with this contact
        for vemail in vinny_emails_add:
            _add_group_permissions(vemail, self.request.user)
        """

        pgp_updates = False
        vinny_pgp=[]
        for f in pgpformset:
            if f.is_valid():
                cd = f.cleaned_data
                if cd['revoked'] == 'on':
                    revoked=True
                else:
                    revoked=False
                old=cd.get('id')
                if old:
                    if cd['pgp_key_data'] == "" and old.pgp_key_data == None:
                        # make this the same
                        cd['pgp_key_data'] = None
                    nochanges = all([old.pgp_key_id == cd['pgp_key_id'],
                                     old.startdate == cd['startdate'],
                                     old.enddate == cd['enddate'],
                                     old.revoked == revoked,
                                     old.pgp_key_data == cd['pgp_key_data'],
                                     old.pgp_protocol == cd['pgp_protocol'],
                                     old.pgp_email == cd['pgp_email'],
                                    ])

                    if nochanges and not(cd['DELETE']):
                        vinny_pgp.append(VinceCommPgP(contact=vinny_contact,
                                                      pgp_key_id=cd['pgp_key_id'],
                                                      pgp_protocol=cd['pgp_protocol'],
                                                      startdate=cd['startdate'],
                                                      enddate=cd['enddate'],
                                                      pgp_key_data=cd['pgp_key_data'],
                                                      pgp_email=cd['pgp_email'],
                                                      revoked=revoked))
                        continue
                    pgp_updates=True
                    if cd['DELETE']:
                        # Delete this key
                        _add_activity(self.request.user, 3, contact, f"removed pgp key {old.pgp_key_id}")
                        old.delete()
                        continue
                    else:
                        if cd['pgp_key_data']:
                            cd = extract_pgp_info(cd)
                            if cd == None:
                                messages.error(self.request,
                                               f"There was an error in parsing the PGP Key")
                                vinny_pgp.append(VinceCommPgP(contact=vinny_contact,
                                                              pgp_key_id=old.pgp_key_id,
                                                              pgp_protocol=old.pgp_protocol,
                                                              startdate=old.startdate,
                                                              enddate=old.enddate,
                                                              pgp_email=old.pgp_email,
                                                              pgp_key_data=old.pgp_key_data,
                                                              revoked=old.revoked))
                                continue
                        _add_activity(self.request.user, 3, contact, f"modified pgp key {old.pgp_key_id} Email: old.pgp_email {old.startdate} - {old.enddate} Revoked: {old.revoked} to {cd['pgp_key_id']} Email: cd['pgp_email'] {cd['startdate']}-{cd['enddate']} Revoked: {cd['revoked']}")
                else:
                    if cd['pgp_key_data']:
                        cd = extract_pgp_info(cd)
                        if cd == None:
                            messages.error(self.request,
                                               f"There was an error in parsing the PGP Key")
                            continue
                    logger.debug(cd)
                    _add_activity(self.request.user, 3, contact, f"added pgp key {cd['pgp_key_id']}")
                instance = f.save()
                # set values from the extraction
                instance.pgp_key_id = cd['pgp_key_id']
                instance.startdate = cd['startdate']
                instance.enddate = cd['enddate']
                if cd.get('pgp_fingerprint'):
                    f.pgp_fingerprint = cd['pgp_fingerprint']
                instance.save()

                vinny_pgp.append(VinceCommPgP(contact=vinny_contact,
                                              pgp_key_id=cd['pgp_key_id'],
                                              pgp_protocol=cd['pgp_protocol'],
                                              startdate=cd['startdate'],
                                              enddate=cd['enddate'],
                                              pgp_email=cd['pgp_email'],
                                              pgp_key_data=cd['pgp_key_data'],
                                              revoked=revoked))

            else:
                for x in pgpformset.errors:
                    for k,v in x.items():
                        if 'This field is required.' not in v:
                            if "Either PGP Key or ID is required" in v and not(f.cleaned_data.get('pgp_key_data') or f.cleaned_data.get('pgp_key_id')):
                                continue
                            messages.error(self.request,
                                           f"PGP Key Validation Error: {v}")
        try:
            with transaction.atomic():
                VinceCommPgP.objects.filter(contact__id=vinny_contact.id).delete()
                VinceCommPgP.objects.bulk_create(vinny_pgp)
        except:
            return HttpResponseServerError()


        if 'active' in self.request.POST:
            active = True
        else:
            active = False

        if contact.vendor_type != self.request.POST['vtype']:
            # set to true so srmail is recreated
            pgp_updates = True
            _add_activity(self.request.user, 3, contact, f"modified contact type from {contact.vendor_type} to {self.request.POST['vtype']}")
            if self.request.POST['vtype'] == "User":
                contact.vendor_type = "Contact"
            else:
                contact.vendor_type = self.request.POST['vtype']
            contact.save()

            some_changes=True
        vendor_name = self.request.POST['vendor_name'].strip()
        if contact.vendor_name != vendor_name:
            oldvendorcontact = Contact.objects.filter(vendor_name__iexact=vendor_name).first()
            if oldvendorcontact:
                error_str="Vendor Name already exists. Please choose a different Vendor Name"
                return render(self.request, 'vince/editcontact.html',
                              {'form': form,
                               'postal_formset': self.PostalFormSet(prefix='postal'),
                               'phone_formset': self.PhoneFormSet(prefix='phone'),
                               'web_formset': self.WebFormSet(prefix='web'),
                               'contact': contact,
                               'pgp_formset': self.PgPFormSet(prefix='pgp', queryset=pgp, instance=contact),
                               """'email_formset': self.EmailFormSet(prefix='email', queryset=email, instance=contact),"""
                               'error': error_str
                              })
            _add_activity(self.request.user, 3, contact, f"modified contact name from {contact.vendor_name} to {vendor_name}")
            some_changes=True
            contact.vendor_name = vendor_name
            srmail_peer = vendor_name.lower().replace(" ", "_").replace("'", "")
            srmail_peer = srmail_peer.translate({ord(i):None for i in '"@+.,;'})
            contact.srmail_peer = srmail_peer

        if contact.countrycode != self.request.POST['countrycode']:
            _add_activity(self.request.user, 3, contact, "modified country code")
            contact.countrycode = self.request.POST['countrycode']
            some_changes=True
        if contact.location != self.request.POST['location']:
            logger.debug(contact.location)
            logger.debug(self.request.POST['location'])
            _add_activity(self.request.user, 3, contact, f"changed location from {contact.location} to {self.request.POST['location']}")
            contact.location = self.request.POST['location']
            some_changes=True
        if contact.comment != self.request.POST['comment']:
            if not((contact.comment == None) and (self.request.POST['comment'] == '')):
                if self.request.POST['comment'] == "":
                    _add_activity(self.request.user, 3, contact, f"removed comment: {contact.comment}")
                elif contact.comment:
                    _add_activity(self.request.user, 3, contact, f"modified comment from {contact.comment} to {self.request.POST['comment']}")
                else:
                    _add_activity(self.request.user, 3, contact, f"added comment: {self.request.POST['comment']}")
            contact.comment = self.request.POST['comment']
            some_changes=True

        if pgp_updates: #or email_changes
            #rebuild srmail file
            if pgp_updates:
                messages.info(
                    self.request,
                    _(f"SRMAIL file has been recreated"))
            update_srmail_file()

        #bump version
        contact.version = contact.version + 1
        """
        if active and groupadmins:
            for ga in groupadmins:
                ec = EmailContact.objects.filter(contact=contact, email=ga).first()
                if ec:
                    new_group_admin = GroupAdmin.objects.update_or_create(contact=contact,
                                                                          email=ec)
                    #add vincecomm group admin
                    _add_groupadmin(ec, contact)
                else:
                    messages.warning(
                        self.request,
                        _(f"The email {ga} has been removed. Please reassign a new group admin."))
        """
        if some_changes or pgp_updates: # or email_changes:
            contact.save()
            
        return redirect("vince:contact", self.kwargs['pk'])

    def get_context_data(self, **kwargs):
        context = super(EditContact, self).get_context_data(**kwargs)
        context['contactpage']=1
        phones = PhoneContact.objects.filter(contact=self.kwargs['pk'])
        for x in phones:
            #fix phone types!
            if x.phone_type not in PhoneContact.PHONE_TYPE:
                if x.phone_type.lower() == "office":
                    x.phone_type = "Office"
                elif x.phone_type.lower() == "home":
                    x.phone_type = "Home"
                elif x.phone_type.lower() == "fax":
                    x.phone_type = "Fax"
                elif x.phone_type.lower() == "mobile":
                    x.phone_type = "Mobile"
                elif x.phone_type.lower() == "hotline":
                    x.phone_type = "Hotline"
                x.save()
        postal = PostalAddress.objects.filter(contact=self.kwargs['pk'])
        website = Website.objects.filter(contact=self.kwargs['pk'])
        pgp = ContactPgP.objects.filter(contact=self.kwargs['pk'])
        #email = EmailContact.objects.filter(contact=self.kwargs['pk']).order_by('-email_function')
        contact = Contact.objects.filter(id=self.kwargs['pk']).first()
        forms = {'postal_formset': self.PostalFormSet(prefix='postal', queryset=postal, instance=contact),
                 'phone_formset': self.PhoneFormSet(prefix='phone', queryset=phones, instance=contact),
                 'web_formset': self.WebFormSet(prefix='web', queryset=website, instance=contact),
                 'pgp_formset': self.PgPFormSet(prefix='pgp', queryset=pgp, instance=contact)}
        #'email_formset': self.EmailFormSet(prefix='email', queryset=email, instance=contact)}
        context['groups'] = GroupMember.objects.filter(contact=self.kwargs['pk'])
        context['form'] = self.form_class(initial=Contact.objects.filter(id=self.kwargs['pk']).values()[0])
        context['form'].fields['vtype'].choices = [('User', 'User'), ('Vendor', 'Vendor'), ('Coordinator', 'Coordinator')]
        context['form'].fields['vtype'].initial = contact.vendor_type
        context['contact'] = contact

        context.update(forms)

        return context

#### ADMIN / Template / Reports stuff ####

class EmailTemplateMgmtView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/email_templates.html'
    form_class = AddEmailTemplateForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(EmailTemplateMgmtView, self).get_context_data(**kwargs)
        form = AddEmailTemplateForm()
        context['form'] = form
        context['templates'] = EmailTemplate.objects.filter(locale='en', body_only=True)
        context['templatesjs'] = [ obj.as_dict() for obj in context['templates']]
        context['owners'] =  [template.user.usersettings.preferred_username for template in context['templates'].exclude(user__isnull=True).order_by('user').distinct('user')]
        return context


class CaseTemplateMgmtView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = 'vince/case_templates.html'
    form_class = AddCaseTemplateForm
    TaskFormSet = formset_factory(AddCaseTemplateTaskForm, max_num=20, min_num=1, can_delete=False, extra=0)

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CaseTemplateMgmtView, self).get_context_data(**kwargs)
        form = AddCaseTemplateForm()
        readable_queues = TicketQueue.objects.filter(queuepermissions__group__in=self.request.user.groups.all(), queuepermissions__group_read=True).distinct()
        form.fields['queue'].choices = [
            (q.id, q.title) for q in readable_queues]
        context['form'] = form
        context['templates'] = CaseTemplate.objects.all()
        context['templatesjs'] = [ obj.as_dict() for obj in context['templates']]
        context['owners'] =  [template.user.usersettings.preferred_username for template in context['templates'].order_by('user').distinct('user')]
        return context

class EmailTemplateFilterView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
     login_url = 'vince:login'
     template_name = 'vince/include/email_templates.html'

     def test_func(self):
         return is_in_group_vincetrack(self.request.user)

     def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        res = EmailTemplate.objects.filter(locale='en', body_only=True)
        owner_list = self.request.POST.getlist('owner')
        logger.debug(owner_list)
        if owner_list:
            res = res.filter(user__usersettings__preferred_username__in=owner_list)

        if self.request.POST['keyword'] != '':
            wordSearch = self.request.POST['keyword']
            res = res.filter(Q(plain_text__icontains=wordSearch) | Q(template_name__icontains=wordSearch) | Q(subject__icontains=wordSearch))

        templatesjs = [ obj.as_dict() for obj in res]
        return JsonResponse({'templates': templatesjs }, status=200)

class CaseTemplateFilterView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
     login_url = 'vince:login'
     template_name = 'vince/include/case_templates.html'

     def test_func(self):
         return is_in_group_vincetrack(self.request.user)

     def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        res = CaseTemplate.objects.all()
        owner_list = self.request.POST.getlist('owner')
        logger.debug(owner_list)
        if owner_list:
            res = res.filter(user__usersettings__preferred_username__in=owner_list)

        if self.request.POST['keyword'] != '':
            wordSearch = self.request.POST['keyword']
            res = res.filter(Q(description__icontains=wordSearch) | Q(title__icontains=wordSearch) | Q(vendor_email__icontains=wordSearch) | Q(participant_email__icontains=wordSearch))

        templatesjs = [ obj.as_dict() for obj in res]
        return JsonResponse({'templates': templatesjs }, status=200)



class EditCaseTemplateTask(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = 'vince:login'
    template_name = 'vince/case_template_task.html'
    form_class = EditCaseTemplateTaskForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return JsonResponse({'error': form.errors}, status=400)

    def form_valid(self, form):
        casetask = get_object_or_404(CaseTask, id=self.kwargs['pk'])
        task = EditCaseTemplateTaskForm(self.request.POST, instance=casetask)
        task = task.save()
        tasks = CaseTask.objects.filter(template = task.template)
        tasksjs = [ obj.as_dict() for obj in tasks]
        logger.debug(tasksjs)
        return JsonResponse({'success': True, 'tasks': tasksjs}, status=200)

    def get_context_data(self, **kwargs):
        context = super(EditCaseTemplateTask, self).get_context_data(**kwargs)
        casetask = get_object_or_404(CaseTask, id=self.kwargs['pk'])
        context['form'] = EditCaseTemplateTaskForm(instance=casetask)
        context['title'] = "Edit Task"
        context['action'] = reverse('vince:edittask', args=[self.kwargs['pk']])

        return context

class AddCaseTemplateTask(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView, FormMixin):
    login_url = 'vince:login'
    template_name = 'vince/case_template_task.html'
    form_class = AddCaseTemplateTaskForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_form_kwargs(self):
        kwargs = super(AddCaseTemplateTask, self).get_form_kwargs()
        kwargs.update({
            "template": get_object_or_404(CaseTemplate, id=self.kwargs['pk'])
        })
        return kwargs

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return JsonResponse({'error': form.errors}, status=400)

    def form_valid(self, form):
        task = form.save()
        tasks = CaseTask.objects.filter(template = self.kwargs['pk'])
        tasksjs = [ obj.as_dict() for obj in tasks]
        logger.debug(tasksjs)
        return JsonResponse({'success': True, 'tasks': tasksjs}, status=200)

    def get_context_data(self, **kwargs):
        context = super(AddCaseTemplateTask, self).get_context_data(**kwargs)
        context['title'] = "Add Task"
        context['action'] = reverse('vince:casetask', args=[self.kwargs['pk']])
        return context

class NewEmailTemplate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView, FormMixin):
    template_name = 'vince/new_email_template.html'
    login_url = "vince:login"
    form_class = AddEmailTemplateForm

    def get_success_url(self):
        return reverse_lazy('vince:emailtmpls')

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def form_valid(self, form):
        tmpl = form.save()
        tmpl.body_only = True
        tmpl.locale = 'en'
        tmpl.user = self.request.user
        tmpl.save()
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(NewEmailTemplate, self).get_context_data(**kwargs)
        form = AddEmailTemplateForm()
        context['form'] = form
        context['title'] = "Create New Email Template"
        context['action'] = reverse('vince:newemailtmpl')
        return context

class EditEmailTemplate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView, FormMixin):
    login_url = "vince:login"
    template_name = 'vince/new_email_template.html'
    form_class = AddEmailTemplateForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return JsonResponse({'error': form.errors}, status=400)

    def form_valid(self, form):
        email = get_object_or_404(EmailTemplate, id=self.kwargs['pk'])
        form = AddEmailTemplateForm(self.request.POST, instance=email)
        tmpl = form.save()
        return super().form_valid(form)

    def get_success_url(self):
        return reverse_lazy('vince:emailtmpls')

    def get_context_data(self, **kwargs):
        context = super(EditEmailTemplate, self).get_context_data(**kwargs)
        email = get_object_or_404(EmailTemplate, id=self.kwargs['pk'])
        form = AddEmailTemplateForm(instance=email)
        context['form'] = form
        context['title'] = "Edit Email Template"
        context['action'] = reverse('vince:editemailtmpl', args=[self.kwargs['pk']])
        return context

class NewCaseTemplate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView, FormMixin):
    template_name='vince/new_case_template.html'
    login_url = "vince:login"
    form_class = AddCaseTemplateForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(NewCaseTemplate, self).get_context_data(**kwargs)
        form = AddCaseTemplateForm()
        #actually - use writeable queues
        readable_queues = TicketQueue.objects.filter(queuepermissions__group__in=self.request.user.groups.all(), queuepermissions__group_write=True).distinct()
        form.fields['queue'].choices = [
            (q.id, q.title) for q in readable_queues]
        case_queue = get_user_case_queue(self.request.user)
        if case_queue:
            if case_queue in readable_queues:
                form.initial['queue']=case_queue.id
        context['form'] = form
        return context

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        logger.debug("IN FORM AVALID")

        casetemplate = form.save()
        casetemplate.user = self.request.user
        casetemplate.save()
        return redirect("vince:casemgmt")

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = AddCaseTemplateForm(request.POST)
        readable_queues = TicketQueue.objects.filter(queuepermissions__group__in=self.request.user.groups.all(),
                                                     queuepermissions__group_read=True).distinct()
        form.fields['queue'].choices = [
            (q.id, q.title) for q in readable_queues]
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

class CloneCaseTemplate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name='vince/clone_case_template.html'
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        tmpl = get_object_or_404(CaseTemplate, id=self.kwargs['pk'])

        tmpl.pk = None
        tmpl.title = tmpl.title + "_clone"
        tmpl.save()
        #first get all tasks of orig template
        old_tmpl = get_object_or_404(CaseTemplate, id=self.kwargs['pk'])
        tasks = CaseTask.objects.filter(template=old_tmpl)
        for task in tasks:
            task.pk = None
            task.template = tmpl
            task.save()
        return JsonResponse({'success': True, 'url': reverse('vince:edittmpl', args=[tmpl.id])}, status=200)

class CloneEmailTemplate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name='vince/new_email_template.html'
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CloneEmailTemplate, self).get_context_data(**kwargs)
        tmpl = get_object_or_404(EmailTemplate, id=self.kwargs['pk'])
        initial = {}
        initial["template_name"] = tmpl.template_name + "_clone"
        initial["plain_text"] = tmpl.plain_text
        initial["subject"] = tmpl.subject
        context['form'] = AddEmailTemplateForm(initial=initial)
        context['title'] = "Clone Email Template"
        context['action'] = reverse('vince:newemailtmpl')
        return context

class CloneCaseTemplateTask(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name='vince/clone_case_template.html'
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        task = get_object_or_404(CaseTask, id=self.kwargs['pk'])
        task.pk = None
        task.task_title = task.task_title + "_clone"
        task.save()
        # return edit
        context={}
        context['form'] = EditCaseTemplateTaskForm(instance=task)
        context['title'] = "Edit Task"
        context['action'] = reverse('vince:edittask', args=[self.kwargs['pk']])
        return render(self.request, 'vince/case_template_task.html', context)


class DeleteCaseTemplateTask(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name='vince/delete_template_task.html'
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(DeleteCaseTemplateTask, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(CaseTask, id=self.kwargs['pk'])
        context['action'] = reverse('vince:deletetask', args=[self.kwargs['pk']])
        return context

    def post(self, request, *args, **kwargs):
        task = get_object_or_404(CaseTask, id=self.kwargs['pk'])
        tmpl = task.template.id
        if task.template.user != self.request.user:
            raise PermissionDenied()
        task.delete()
        return redirect("vince:edittmpl", tmpl)

class DeleteEmailTemplate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name='vince/delete_email_template.html'
    login_url = "vince:login"

    def test_func(self):
        ct = get_object_or_404(EmailTemplate, id=self.kwargs['pk'])
        #only the user that created this template can delete it (unless superuser)
        if is_in_group_vincetrack(self.request.user):
            if self.request.user.is_superuser:
                return True
            elif self.request.user == ct.user:
                return True
        return False

    def get_context_data(self, **kwargs):
        context = super(DeleteEmailTemplate, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(EmailTemplate, id=self.kwargs['pk'])
        if self.request.user.is_superuser or context['object'].user == self.request.user:
            context['action'] = reverse('vince:deleteemailtmpl', args=[self.kwargs['pk']])
        return context

    def post(self, request, *args, **kwargs):
        tmpl = get_object_or_404(EmailTemplate, id=self.kwargs['pk'])
        if tmpl.user != self.request.user:
            if not(self.request.user.is_superuser):
                raise PermissionDenied()
        tmpl.delete()
        return redirect("vince:emailtmpls")


class DeleteCaseTemplate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name='vince/delete_case_template.html'
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(DeleteCaseTemplate, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(CaseTemplate, id=self.kwargs['pk'])
        context['action'] = reverse('vince:deletetmpl', args=[self.kwargs['pk']])
        return context

    def post(self, request, *args, **kwargs):
        tmpl = get_object_or_404(CaseTemplate, id=self.kwargs['pk'])
        #first get all tasks
        if tmpl.user != self.request.user:
            raise PermissionDenied()
        tasks = CaseTask.objects.filter(template=tmpl)
        for task in tasks:
            task.delete()
        tmpl.delete()
        return redirect("vince:casemgmt")


class EditCaseTemplate(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.UpdateView):
    template_name = 'vince/edit_case_template.html'
    login_url = "vince:login"
    form_class = AddCaseTemplateForm
    model = CaseTemplate

    def	test_func(self):
        ct = get_object_or_404(CaseTemplate, id=self.kwargs['pk'])
        #only the user that created this template can edit it (unless superuser)
        if is_in_group_vincetrack(self.request.user):
            if self.request.user.is_superuser:
                return True
            elif self.request.user == ct.user:
                return True
        return False

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        logger.debug("IN FORM AVALID")

        casetemplate = form.save()
        casetemplate.user = self.request.user
        casetemplate.save()

        return redirect("vince:casemgmt")

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        ct = get_object_or_404(CaseTemplate, id=self.kwargs['pk'])
        form = AddCaseTemplateForm(request.POST, instance=ct)
        readable_queues = TicketQueue.objects.filter(queuepermissions__group__in=self.request.user.groups.all(), queuepermissions__group_read=True).distinct()
        form.fields['queue'].choices = [
            (q.id, q.title) for q in readable_queues]
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(EditCaseTemplate, self).get_context_data(**kwargs)
        tasks = CaseTask.objects.filter(template = self.kwargs['pk'])
        context['tasksjs'] = [ obj.as_dict() for obj in tasks]
        ct = get_object_or_404(CaseTemplate, id=self.kwargs['pk'])
        form = AddCaseTemplateForm(instance=ct)
        readable_queues = TicketQueue.objects.filter(queuepermissions__group__in=self.request.user.groups.all(), queuepermissions__group_read=True).distinct()
        form.fields['queue'].choices = [
            (q.id, q.title) for q in readable_queues]
        context['form'] = form
        return context


class DeleteAttachment(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/ticket_attachment_del.html"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            ticket = get_object_or_404(Ticket, id=self.kwargs['ticket_id'])
            return has_queue_write_access(self.request.user, ticket.queue)
        else:
            return False

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        ticket = get_object_or_404(Ticket, id=self.kwargs["ticket_id"])
        if not _is_my_ticket(request.user, ticket):
            raise PermissionDenied()

        attachment = get_object_or_404(Attachment, id=self.kwargs["attachment_id"])
        comment = "Attachment: %s removed from ticket" % attachment.filename
        attachment.delete()

        followup = FollowUp(
            ticket=ticket,
            user=self.request.user,
            title='Removed attachment',
            comment=comment,
        )
        followup.save()

        return HttpResponseRedirect(reverse('vince:ticket', args=[self.kwargs["ticket_id"]]))

    def get_context_data(self, **kwargs):
        context = super(DeleteAttachment, self).get_context_data(**kwargs)
        ticket = get_object_or_404(Ticket, id=self.kwargs["ticket_id"])
        if not _is_my_ticket(self.request.user, ticket):
            raise PermissionDenied()

        attachment = get_object_or_404(Attachment, id=self.kwargs["attachment_id"])
        context['ticket'] = ticket
        context['attachment'] = attachment
        return context

class ArtifactDetailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = Artifact
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

class ShareArtifactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = Artifact
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
            if artifact.get_related_ticket():
                ticket = artifact.get_related_ticket()
                return has_queue_write_access(self.request.user, ticket.queue)
            elif artifact.get_related_case():
                return has_case_write_access(self.request.user, artifact.get_related_case())
        else:
            return False

    def post(self, request, *args, **kwargs):
        logger.debug("IN SHARE ARTIFACT")
        artifact = get_object_or_404(Artifact, id=self.kwargs['pk'])
        if artifact.get_related_attachment():
            vtattach = artifact.get_related_attachment()

            copy_source = {'Bucket': settings.PRIVATE_BUCKET_NAME,
                           'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+ str(vtattach.file.name)
            }

            #copy file into shared s3 bucket
            s3 = boto3.resource('s3', region_name=settings.AWS_REGION)
            bucket = s3.Bucket(settings.VINCE_SHARED_BUCKET)
            try:
                bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(vtattach.uuid))
            except ClientError as e:
                error_code = e.response['Error']['Code']
                logger.debug(error_code)
                if error_code == "InvalidRequest":
                    #This file already exists most likely in VinceComm. just ignore
                    pass
                else:
                    return JsonResponse({'status': 'success', 'text': f"There was an error uploading your file: {e.response['Error']['Code']} {e.response['Error']['Message']}"})

            att = VinceAttachment(
                file=vtattach.file,
                filename=vtattach.filename,
                mime_type=vtattach.mime_type,
                size=vtattach.size,
            )
            att.save(using='vincecomm')

            #rename file
            copy_source = {'Bucket': settings.VINCE_SHARED_BUCKET,
                           'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+ str(vtattach.uuid)
            }
            bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(att.uuid))

            #assign to new key and save
            att.file.name = str(att.uuid)
            att.save()

            #delete the old one
            s3.Object(settings.VINCE_SHARED_BUCKET, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(vtattach.uuid)).delete()

            vc_case = None
            case = None

            if artifact.get_related_case():
                case = artifact.get_related_case()
                vc_case = Case.objects.filter(vuid=case.vuid).first()
            elif artifact.get_related_ticket():
                ticket = artifact.get_related_ticket()
                if ticket.case:
                    case = ticket.case
                    vc_case = Case.objects.filter(vuid=ticket.case.vuid).first()

            if self.kwargs.get('post'):
                vulnote = False
            else:
                vulnote = True
                
            #save it in VINCEComm
            attach = VinceTrackAttachment(
                file = att,
                vulnote=vulnote,
                case=vc_case)
            
            attach.save(using='vincecomm')

            logger.debug(f"uuid is {att.uuid}")

            vf = VinceFile(user=self.request.user,
                           case = case,
                           filename=att.filename,
                           vulnote = vulnote,
                           comm_id=attach.id)
            vf.save()

            url = reverse("vinny:attachment", args=["track", att.uuid])
            text = f"[{vf.filename}]({url})"

            return JsonResponse({'status': 'success', 'text': text, 'type': 'file', 'image_url': url, 'id':vf.id, 'filename': vf.filename, 'remove_link': reverse('vince:unattachfile', args=[vf.id])}, status=200)

        text = f"### {artifact.title} \r\n {artifact.value}"
        return JsonResponse({'status': 'success', 'text': text})

class VulNoteDiffView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = VulNoteRevision
    pk_url_kwarg = 'revision_id'
    login_url = "vince:login"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def render_to_response(self, context, **response_kwargs):
        revision = self.get_object()
        other_revision = revision.previous_revision
        baseText = other_revision.content if other_revision is not None else ""
        newText = revision.content

        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        diff = differ.compare(
            baseText.splitlines(keepends=True), newText.splitlines(keepends=True)
        )
        other_changes = []

        if not other_revision or other_revision.title != revision.title:
            other_changes.append((_('New title'), revision.title))

        return object_to_json_response(
            {'diff': list(diff), 'other_changes': other_changes}
        )

class VulNoteRevisionPreview(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/include/preview_inline.html"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vulnote.case)
        return False

    @method_decorator(xframe_options_sameorigin)
    def dispatch(self, request, *args, **kwargs):
        self.title = None
        self.content = None
        self.references = None
        self.preview = False
        self.vul_note = get_object_or_404(VulNote, id= self.kwargs['pk'])
        self.revision = get_object_or_404(VulNoteRevision, id=self.kwargs['revision_id'])
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        edit_form = forms.EditVulNote(request, self.vulnote.current_revision, request.POST, preview=True)
        if edit_form.is_valid():
            self.title = edit_form.cleaned_data['title']
            self.content = edit_form.cleaned_data['content']
            self.preview = True
        return super().get(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):

        if self.revision and not self.title:
            self.title = self.revision.title
        if self.revision and not self.content:
            self.content = self.revision.content
        if self.revision and not self.references:
            self.references = self.revision.references.splitlines()
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        kwargs['title'] = self.title
        kwargs['revision'] = self.revision
        kwargs['content'] = self.content
        kwargs['references'] = self.references
        kwargs['preview'] = self.preview
        kwargs['case'] = self.vul_note.case
        logger.debug(f"test {self.vul_note.case.vulnerablevendor_set.all()}")
        kwargs['pubnote'] = VUReport.objects.filter(idnumber=self.vul_note.case.vuid).first()
        return super(VulNoteRevisionPreview, self).get_context_data(**kwargs)

class VulNoteChangeRevision(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.RedirectView):
    permanent = False
    login_url = "vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vulnote.case)
        return False

    def dispatch(self, request, *args, **kwargs):
        self.vulnote = get_object_or_404(VulNote, id= self.kwargs['pk'])
        self.change_revision()

        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, **kwargs):
        return reverse('vince:case', args=[self.vulnote.case.id]) + '#vulnote'


    def change_revision(self):
        revision = get_object_or_404(
            VulNoteRevision,
            id=self.kwargs['revision_id'])
        self.vulnote.current_revision = revision
        self.vulnote.save()
        messages.success(
            self.request,
            _("The article %(title)s is now set to display revision #%(revision_number)d") % {
                'title': revision.title,
                'revision_number': revision.revision_number,
            })



class VulNoteChangeLog(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/changelog.html'
    login_url =	"vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vulnote = get_object_or_404(VulNote, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vulnote.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(VulNoteChangeLog, self).get_context_data(**kwargs)
        context['vulnote'] = get_object_or_404(VulNote, id= self.kwargs['pk'])
        context['case'] = context['vulnote'].case
        context['revisions'] = VulNoteRevision.objects.filter(vulnote = context['vulnote']).order_by('-created')
        return context


class CloneVulnerability(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name='vince/editvul.html'
    login_url = "vince:login"
    CWEFormSet = formset_factory(AddCWEForm, max_num=5, min_num=1, can_delete=True, extra=0)
    #ExploitFormSet = formset_factory(AddExploitForm, max_num=10, min_num=1, can_delete=True, extra=0)
    CVEReferenceFormSet = formset_factory(CVEReferencesForm, max_num=10, min_num=1, can_delete=True, extra=0)

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vul.case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(CloneVulnerability, self).get_context_data(**kwargs)
        vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        case = vul.case
        initial = {}
        initial['case'] = vul.case
        initial['ask_vendor_status'] = vul.ask_vendor_status
        initial['description'] = vul.description
        context['action'] = reverse('vince:addvul', args=[vul.case.id])
        context['title'] = "Clone Vulnerability"
        cve_refs = []
        cve_cwe = []
        cveallocator = CVEAllocation.objects.filter(vul=vul).first()
        if cveallocator:
            if cveallocator.references:
                for x in json.loads(cveallocator.references):
                    if (type(x) is dict):
                        cve_refs.append({'ref_source':x['refsource'], 'reference': x['url']})
                    else:
                        cve_refs.append({'reference': x})
            if cveallocator.cwe:
                for x in json.loads(cveallocator.cwe):
                    cve_cwe.append({'cwe': x})
            if cveallocator.date_public:
                initial['date_public'] = cveallocator.date_public

        context['form'] = AddVulnerabilityForm(initial=initial)

        #forms = {'cwe_formset': self.CWEFormSet(prefix='cwe'), 'exploit_formset':self.ExploitFormSet(prefix='exploit')}
        forms = {'cwe_formset': self.CWEFormSet(prefix='cwe', initial=cve_cwe),  'ref_formset': self.CVEReferenceFormSet(prefix='ref', initial=cve_refs)}
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        context['vul_tags'] = [tag.tag for tag in vul.vulnerabilitytag_set.all()]
        context['allowed_tags'] = [tag.tag for tag in TagManager.objects.filter(tag_type=4).filter(Q(team__in=user_groups)|Q(team__isnull=True)).order_by('tag').distinct('tag')]
        context.update(forms)
        return context


class AddExploitView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = 'vince/edit_exploit.html'
    form_class = AddExploitForm
    model = VulExploit

    def get_success_url(self):
        vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        return reverse('vince:vul', args=[vul.id])

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vul.case)
        else:
            return False

    def form_valid(self, form):
        logger.debug("IN FORM VALID !!!")
        vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])

        cd = form.cleaned_data
        
        ex = VulExploit(vul=vul,
                        user=self.request.user,
                        link=cd['link'],
			notes=cd['notes'],
                        reference_type=cd['reference_type'],
                        reference_date=cd['reference_date'])
        ex.save()

        return super().form_valid(form)
        
    def get_context_data(self, **kwargs):
        context = super(AddExploitView, self).get_context_data(**kwargs)
        context['title'] = "Add Exploit"
        context['action'] = reverse('vince:addexploit', args=[self.kwargs['pk']])
        return context

class RemoveExploitView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = 'vince/rm_exploit.html'

    def get_success_url(self):
        vul = get_object_or_404(VulExploit, id=self.kwargs['pk'])
        return reverse('vince:vul', args=[vul.vul.id])

    def get_context_data(self, **kwargs):
        context = super(RemoveExploitView, self).get_context_data(**kwargs)
        context['vul'] = get_object_or_404(VulExploit, id=self.kwargs['pk'])
        return context
    
    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vul = get_object_or_404(VulExploit, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vul.vul.case)
        else:
            return False

    def post(self, request, *args, **kwargs):
        vul = get_object_or_404(VulExploit, id=self.kwargs['pk'])
        vulid = vul.vul.id
        vul.delete()
        return HttpResponseRedirect(reverse('vince:vul', args=[vulid]))
    
class EditExploitView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.UpdateView):
    login_url = "vince:login"
    template_name = 'vince/edit_exploit.html'
    form_class = AddExploitForm
    model = VulExploit


    def get_success_url(self):
        vul = get_object_or_404(VulExploit, id=self.kwargs['pk'])
        return reverse('vince:vul', args=[vul.vul.id])
    
    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vul = get_object_or_404(VulExploit, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vul.vul.case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(EditExploitView, self).get_context_data(**kwargs)
        context['title'] = "Edit Exploit"
        context['action'] = reverse('vince:editexploit', args=[self.kwargs['pk']])
        return context

    
class ShareExploitView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = 'vince/exploits.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vul = get_object_or_404(VulExploit, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vul.vul.case)
        else:
            return False

    def get(self, request, *args, **kwargs):
        exploit = get_object_or_404(VulExploit, id=self.kwargs['pk'])
        
        if exploit.share:
            exploit.share=False
            title = "Exploit removed from VINCEComm"
            #exists in vincecomm?
            vcvul = CaseVulExploit.objects.filter(vince_id=exploit.id).first()
            if vcvul:
                vcvul.delete()

        else:
            exploit.share=True
            title = "Exploit shared to VINCEComm"
            vcvul = CaseVulnerability.objects.filter(vince_id=exploit.vul.id).first()
            vcexp = CaseVulExploit.objects.update_or_create(vince_id=exploit.id,
                                                            defaults = {'vul':vcvul,
                                                                        'date_added':exploit.date_added,
                                                                        'reference_date':exploit.reference_date,
                                                                        'link':exploit.link,
                                                                        'reference_type':exploit.reference_type,
                                                                        'notes':exploit.notes})
            

        exploit.save()
        
        ca = CaseAction(case=exploit.vul.case,
                        title=title,
                        date=timezone.now(),
                        comment=f"{request.user.usersettings.preferred_username} changed exploit shared status",
                        user = request.user,
                        action_type=1)
        ca.save()
        

        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ShareExploitView, self).get_context_data(**kwargs)
        vul = get_object_or_404(VulExploit, id=self.kwargs['pk'])
        context['exploits'] = VulExploit.objects.filter(vul=vul.vul)
        return context
    
        
    
class EditVul(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = "vince:login"
    form_class = AddVulnerabilityForm
    template_name = 'vince/editvul.html'
    #CWEFormSet = inlineformset_factory(Vulnerability, VulCWE, form=AddCWEForm, max_num=5, min_num=1, can_delete=True, extra=0)
    CWEFormSet = formset_factory(AddCVECWEForm, max_num=5, min_num=1, can_delete=True, extra=0)
    #ExploitFormSet = inlineformset_factory(Vulnerability, VulExploit, form=AddExploitForm, max_num=10, min_num=1, can_delete=True, extra=0)
    CVEReferenceFormSet = formset_factory(CVEReferencesForm, max_num=10, min_num=1, can_delete=True, extra=0)
    
    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vul.case)
        else:
            return False

    def form_valid(self, form):
        logger.debug("IN FORM VALID !!!")
        vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])

        vul.description = form.cleaned_data['description']
        vul.ask_vendor_status = True
        old_cve = vul.cve
        vul.cve = form.cleaned_data['cve']
        logger.debug(vul)
        vul.save()
        errors = []
        #get all tags:
        oldtags = list(VulnerabilityTag.objects.filter(vulnerability=vul).values_list('tag', flat=True))
        tags = self.request.POST.getlist('taggles[]')
        newt =False
        rmt = False
        for tag in tags:
            if tag in oldtags:
                continue
            else:
                tag = VulnerabilityTag(vulnerability=vul,
                                       tag = tag,
                                       user = self.request.user)
                newt=True
                tag.save()
        #remove
        for tag in oldtags:
            if tag not in tags:
                otag = VulnerabilityTag.objects.filter(vulnerability=vul,
                                                       tag=tag)
                otag.delete()
                rmt=True
        
        vul.case.changes_to_publish = True
        vul.case.save()

        
        cweformset = self.CWEFormSet(self.request.POST, prefix='cwe')
        cwes = []
        for f in cweformset:
            if f.is_valid():
                if f.cleaned_data.get('cwe'):
                    cwes.append(f.cleaned_data['cwe'])
            else:
                sterrors = str(f.errors)
                if f.cleaned_data.get('cwe') and sterrors.find("Invalid CWE"):
                    errors.append(f"Problem adding CWE {len(cwes)+1} - not a valid CWE - must start with CWE-")

        """
        vulcwes = VulCWE.objects.filter(vul=vul)
        cweformset = self.CWEFormSet(self.request.POST, prefix='cwe', queryset=vulcwes, instance=vul)
        for f in cweformset:
            if f.is_valid():
                cd = f.cleaned_data
                old = cd.get('id')
                if old:
                    nochanges = all([old.cwe == cd['cwe']])
                    if nochanges and not(cd['DELETE']):
                        continue
                    if cd['DELETE']:
                        old.delete()
                        continue
                x = f.save()
                if not old:
                    x.user = self.request.user
                    x.save()"""

        cverefformset = self.CVEReferenceFormSet(self.request.POST, prefix='ref')
        refs=[]
        for f in cverefformset:
            if f.is_valid():
                refs.append({'refsource': f.cleaned_data['ref_source'], 'url': f.cleaned_data['reference']})
            else:
                logger.debug(f.errors)
                sterrors = str(f.errors)
                if sterrors.find("valid URL") != -1:
                    errors.append(f"Problem adding reference {len(refs)+1} - not a valid URL")

        cve = CVEAllocation.objects.filter(vul=vul).first()
        #is there a CVE model for this vul?

        if cve:
            cve.date_public = form.cleaned_data['date_public']
            cve.description = vul.description
            cve.references = json.dumps(refs)
            cve.cwe = json.dumps(cwes)
            if vul.cve:
                cve.cve_name = vul.vul
            logger.debug(f"saving {cve.cwe}")
            cve.save()
        else:
            if vul.cve:
                cve_name = vul.vul
            else:
                cve_name = "PLACEHOLDER"

            assigner = get_cve_assigner(self.request.user, vul.case)

            cve = CVEAllocation(vul=vul,
                                cve_name=cve_name,
                                description=vul.description,
                                assigner = assigner)
            if refs:
                cve.references=json.dumps(refs)
            if cwes:
                cve.cwe = json.dumps(cwes)
                
            cve.date_public = form.cleaned_data['date_public']
            
            cve.save()

        if old_cve != form.cleaned_data['cve']:

            if old_cve:
                logger.debug(f"CHANGED CVE from {old_cve} to {form.cleaned_data['cve']}")
                # was this previously reserved
                x = f"CVE-{old_cve}"
                cve_res = CVEReservation.objects.filter(cve_id=x).first()
                if cve_res:
                    cve_res.cve_info = None
                    cve_res.save()
                    messages.warning(self.request,
                                     f"Removing link to CVE Reservation {cve_res.cve_id} due to change in CVE")

            # see if we have a matching reservation
            if form.cleaned_data['cve']:
                x = f"CVE-{form.cleaned_data['cve']}"
                cve_res = CVEReservation.objects.filter(cve_id=x).first()
                if cve_res:
                    logger.debug(f"FOUND RESERVATION for {x}")
                    cve_res.cve_info = cve
                    cve_res.save()


        #vulexploits = VulExploit.objects.filter(vul=vul)
        #exploitformset = self.ExploitFormSet(self.request.POST, prefix='exploit', queryset=vulexploits, instance=vul)
        """
        for f in exploitformset:
            if exploitformset.is_valid():
                cd = f.cleaned_data
                old = cd.get('id')
                if old:
                    nochanges = all([old.link == cd['link'],
                                     old.reference_date == cd['reference_date'],
                                     old.notes == cd['notes'],
                                     old.reference_type == cd['reference_type']])
                    if nochanges and not(cd['DELETE']):
                        continue
                    if cd['DELETE']:
                        old.delete()
                        continue

                x = f.save()
                if not old:
                    x.user = self.request.user
                    x.save()
            else:
                logger.debug(f"{self.__class__.__name__} errors: {f.errors}")
        """

        action = CaseAction(case = vul.case,
                            title = "Edited Vulnerability",
                            date = timezone.now(),
                            user = self.request.user,
                            comment=vul.vul,
                            action_type=1)
        action.save()

        if errors:
            errors = ", ".join(errors)
            messages.error(self.request,
                           f"Error processing vulnerability information: {errors}")
        
        if self.request.META.get('HTTP_REFERER') and is_safe_url(self.request.META.get('HTTP_REFERER'),set(settings.ALLOWED_HOSTS),True):
            
            return HttpResponseRedirect(self.request.META.get('HTTP_REFERER') + "#vuls")
        else:
            return redirect("vince:editvuls", vul.case.id)

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug("IN THIS POST")
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        if request.POST.get('add_tag'):
            vul = get_object_or_404(Vulnerability, id=kwargs['pk'])
            user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            tag = self.request.POST.get('tag').lower()
            if len(tag) < 50:
                if TagManager.objects.filter(tag=tag, tag_type=4).filter(Q(team__in=user_groups)|Q(team__isnull=True)).exists():
                    tag, created = VulnerabilityTag.objects.update_or_create(vulnerability=vul, tag=tag,
                                                                             defaults={'user':self.request.user})
                    if created:
                        fup = CaseAction(title=f"Vulnerability {vul.vul} tagged as \"{tag}\"",
                                         case=vul.case,
                                         user=self.request.user)
                        fup.save()
                else:
                    logger.debug("invalid tag - tag doesn't exist in tag manager")
                    return JsonResponse({'tag': tag, 'vul': vul.id, 'error': "Invalid Tag."}, status=401)
            else:
                return JsonResponse({'tag': tag, 'vul': vul.id, 'error': "Tag is too long. Max 50 characters."}, status=401)
            return JsonResponse({'tag_added': tag.tag, 'vul': vul.id}, status=200)

        elif request.POST.get('del_tag'):
            vul = get_object_or_404(Vulnerability, id=kwargs['pk'])
            tag = self.request.POST.get('tag')
            try:
                VulnerabilityTag.objects.get(tag=tag, vulnerability=vul).delete()
                fup = CaseAction(title=f"Removed vulnerability tag \"{tag}\" from {vul.vul}",
                                 case=vul.case,
                                 user=self.request.user)
                fup.save()
                return JsonResponse({'tag_deleted': tag, 'vul':vul.id}, status=200)
            except VulnerabilityTag.DoesNotExist:
                return JsonResponse({'tag': tag, 'vul': vul.id, 'error': f"'{tag}' not assigned to vul"}, status=401)
        
        form = AddVulnerabilityForm(request.POST)

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get(self, request, *args, **kwargs):
        vul = Vulnerability.objects.get(id=self.kwargs['pk'])

        if self.request.GET.get('noask'):
            vul.ask_vendor_status = False
            vul.save()
        elif self.request.GET.get('ask'):
            vul.ask_vendor_status = True
            vul.save()

        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(EditVul, self).get_context_data(**kwargs)
        vul = Vulnerability.objects.get(id=self.kwargs['pk'])
        #is this a clone?
        if vul.cve:
            clones = Vulnerability.objects.filter(cve = vul.cve).count()
            if clones > 1:
                context['show_clone'] = True
        cwes = VulCWE.objects.filter(vul=vul)
        cveallocator = CVEAllocation.objects.filter(vul=vul).first()
        cve_cwe = []
        if cwes:
            for c in cwes:
                #need to convert these to the CVE object
                #lookup CWEDescription
                cwe_description = CWEDescriptions.objects.filter(cwe__istartswith=c.cwe).first()
                if cwe_description:
                    cve_cwe.append({'cwe': cwe_description.cwe})
                else:
                    cve_cwe.append({'cwe': c.cwe})
        #exploits = VulExploit.objects.filter(vul=vul)

        initial={}
        cve_refs = []

        if cveallocator:
            initial['cve_allocator'] = True
            if cveallocator.references:
                for x in json.loads(cveallocator.references):
                    if (type(x) is dict):
                        cve_refs.append({'ref_source':x['refsource'], 'reference': x['url']})
                    else:
                        cve_refs.append({'reference': x})
            if cveallocator.cwe:
                #empty the VulCWE's - they probably were already loaded here
                new_cwes = json.loads(cveallocator.cwe)
                if len(new_cwes):
                    cve_cwe.clear()
                for x in new_cwes:
                    cve_cwe.append({'cwe': x})
            if cveallocator.date_public:
                initial['date_public'] = cveallocator.date_public
        
        form = AddVulnerabilityForm(instance=vul, initial=initial)
        #forms = {'cwe_formset': self.CWEFormSet(prefix='cwe', queryset=cwes, instance=vul), 'exploit_formset':self.ExploitFormSet(prefix='exploit', queryset=exploits, instance=vul)}
        forms = {'cwe_formset': self.CWEFormSet(prefix='cwe', initial=cve_cwe),  'ref_formset': self.CVEReferenceFormSet(prefix='ref', initial=cve_refs)}
        context['form'] = form
        context['title'] = "Edit Vulnerability"
        context['action'] = reverse('vince:editvul', args=[self.kwargs['pk']])
        context['vul'] = vul
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        context['vul_tags'] = [tag.tag for tag in vul.vulnerabilitytag_set.all()]
        context['allowed_tags'] = [tag.tag for tag in TagManager.objects.filter(tag_type=4).filter(Q(team__in=user_groups)|Q(team__isnull=True)).order_by('tag').distinct('tag')]
        context.update(forms)
        return context

def nonesafe_loads(obj):
    if obj is not None:
        return json.loads(obj)

class EditCVEView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.UpdateView):
    login_url = "vince:login"
    form_class = CVEAllocationForm
    model = CVEAllocation
    template_name = 'vince/cveform.html'
    CVEProductFormSet = formset_factory(CVEAffectedProductForm, max_num=10, min_num=1, can_delete=True,
                                        extra=0)
    CVEReferenceFormSet = formset_factory(CVEReferencesForm, max_num=10, min_num=1, can_delete=True,
                                          extra=0)
    #CVEWorkaroundFormSet = formset_factory(CVEWorkaroundForm, max_num=10, min_num=1, can_delete=True,
    #                                       extra=0)
    CWEFormSet = formset_factory(AddCVECWEForm, max_num=5, min_num=1, can_delete=True, extra=0)


    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            cve = get_object_or_404(CVEAllocation, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, cve.vul.case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(EditCVEView, self).get_context_data(**kwargs)
        cve = get_object_or_404(CVEAllocation, id=self.kwargs['pk'])
        products = CVEAffectedProduct.objects.filter(cve = cve)
        context['title'] = f"Edit {cve}"
        context['vul'] = cve.vul
        cve_refs = []
        #cve_works = []
        cve_cwe = []
        if cve.references:
            for x in json.loads(cve.references):
                if (type(x) is dict):
                    cve_refs.append({'ref_source':x['refsource'], 'reference': x['url']})
                else:
                    cve_refs.append({'reference': x})
        #if cve.work_around:
        #    for x in json.loads(cve.work_around):
        #        cve_works.append({'workaround': x})

        
        if cve.cwe:
            new_cwes = json.loads(cve.cwe)
            if len(new_cwes):
                for x in new_cwes:
                    cve_cwe.append({'cwe': x})
            else:
                #are there old cwes?
                cwes = VulCWE.objects.filter(vul=cve.vul)
                for c in cwes:
                    cwe_description = CWEDescriptions.objects.filter(cwe__istartswith=c.cwe).first()
                    if cwe_description:
                        cve_cwe.append({'cwe': cwe_description.cwe})
                    else:
                        cve_cwe.append({'cwe': c.cwe})
                    
        forms = {'prod_formset': self.CVEProductFormSet(prefix='product', initial=products.values() ),
                 'cwe_formset': self.CWEFormSet(prefix='cwe', initial=cve_cwe),
		 'ref_formset': self.CVEReferenceFormSet(prefix='ref', initial=cve_refs)}
        #'wa_formset': self.CVEWorkaroundFormSet(prefix='wa', initial=cve_works)}
        context.update(forms)
        if self.request.META.get('HTTP_REFERER') and self.request.path not in self.request.META.get('HTTP_REFERER'):
            context['cancel_url'] = self.request.META.get('HTTP_REFERER')
        else:
            try:
                if cve.vul.case:
                    context['cancel_url'] = reverse("vince:case", args=[cve.vul.case.id])+"#vuls"
            except:
                context['cancel_url'] = reverse("vince:dashboard")
        return context

    def form_invalid(self, form):
        cve = get_object_or_404(CVEAllocation, id=self.kwargs['pk'])
        
        return render(self.request, 'vince/cveform.html',
                      {'form': form,
                       'vul': cve.vul,
                       'case': cve.vul.case,
                       'prod_formset': self.CVEProductFormSet(self.request.POST, prefix='product'),
                       'cwe_formset': self.CWEFormSet(self.request.POST, prefix='cwe'),
                       'ref_formset': self.CVEReferenceFormSet(self.request.POST, prefix='ref')})
#                       'wa_formset': self.CVEWorkaroundFormSet(prefix='wa', initial=cve_works)})


    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        cve = get_object_or_404(CVEAllocation, id=self.kwargs['pk'])
        form = CVEAllocationForm(request.POST, instance=cve)

        if form.is_valid():
            cveprodformset = self.CVEProductFormSet(self.request.POST, prefix='product')
            if cveprodformset.is_valid():
                return self.form_valid(form)
            else:
                form.add_error(None, "At least one Product is required")
                logger.debug(cveprodformset.errors)
                return self.form_invalid(form)
        else:
            logger.debug(form.errors)
            return self.form_invalid(form)

    def form_valid(self, form):
        cveprodformset = self.CVEProductFormSet(self.request.POST, prefix='product')
        cverefformset = self.CVEReferenceFormSet(self.request.POST, prefix='ref')
        #cvewaformset = self.CVEWorkaroundFormSet(self.request.POST, prefix='wa')
        cweformset = self.CWEFormSet(self.request.POST, prefix='cwe')

        cwes = []
        if cweformset.is_valid():
            for f in cweformset:
                cwes.append(f.cleaned_data['cwe'])
        #was=[]
        #if cvewaformset.is_valid():
        #    for f in cvewaformset:
        #        was.append(f.cleaned_data['workaround'])
        refs=[]
        if cverefformset.is_valid():
            for f in cverefformset:
                refs.append({'refsource': f.cleaned_data['ref_source'], 'url': f.cleaned_data['reference']})

                    # we don't actually use cve description, description is kept with Vulnerability object

        cve = form.save()
        cve.user = self.request.user

        cve.vul.description = form.cleaned_data['description']
        cve.vul.date_public = form.cleaned_data['date_public']
        cve.vul.save()

        #fix reservation
        old_cve = f"CVE-{cve.vul.cve}"
        if old_cve != cve.cve_name:
            #CVE HAS CHANGED!
            cve.vul.cve = cve.cve_name[4:]
            cve.vul.save()
            cve_res = CVEReservation.objects.filter(cve_id=cve.cve_name).first()
            if cve_res:
                cve_res.cve_info = None
                cve_res.save()
                messages.warning(self.request,
                                 f"Removing link to CVE Reservation {cve_res.cve_id} due to change in CVE")
            if cve.cve_name:
                #connect any new reservations
                cve_res = CVEReservation.objects.filter(cve_id=cve.cve_name).first()
                if cve_res:
                    logger.debug(f"FOUND RESERVATION for {cve.cve_name}")
                    cve_res.cve_info = cve
                    cve_res.save()
            
        cve.cwe = json.dumps(cwes)
        #if was:
        #    cve.work_around = json.dumps(was)
        cve.references = json.dumps(refs)
        cve.save()

        prods = []
        if cveprodformset.is_valid():
            for f in cveprodformset:
                cd = f.cleaned_data
                prods.append(CVEAffectedProduct(cve = cve,
                                                name=cd['name'],
                                                version_affected=cd['version_affected'],
                                                version_name=cd['version_name'],
                                                version_value=cd['version_value'],
                                                organization=cd['organization']))
            try:
                with transaction.atomic():
                    CVEAffectedProduct.objects.filter(cve=cve).delete()
                    CVEAffectedProduct.objects.bulk_create(prods)
            except:
                return HttpResponseServerError()
        if self.request.META.get('HTTP_REFERER') and (self.request.path not in self.request.META.get('HTTP_REFERER')) and is_safe_url(self.request.META.get('HTTP_REFERER'),set(settings.ALLOWED_HOSTS),True):
            return HttpResponseRedirect(self.request.META.get('HTTP_REFERER') + "#vuls")
        else:
            return redirect("vince:vul", cve.vul.id)
            

class CVEFormView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = "vince:login"
    form_class = CVEAllocationForm
    template_name = 'vince/cveform.html'
    CVEProductFormSet = formset_factory(CVEAffectedProductForm, max_num=10, min_num=1, can_delete=True,
                                        extra=0)
    CVEReferenceFormSet = formset_factory(CVEReferencesForm, max_num=10, min_num=1, can_delete=True,
                                          extra=0)
    #CVEWorkaroundFormSet = formset_factory(CVEWorkaroundForm, max_num=10, min_num=1, can_delete=True,
    #                                       extra=0)
    CWEFormSet = formset_factory(AddCVECWEForm, max_num=5, min_num=1, can_delete=True, extra=0)

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def form_valid(self, form):
        logger.debug("IN FORM VALID")
        
        cveprodformset = self.CVEProductFormSet(self.request.POST, prefix='product')
        cverefformset = self.CVEReferenceFormSet(self.request.POST, prefix='ref')
        #cvewaformset = self.CVEWorkaroundFormSet(self.request.POST, prefix='wa')
        cweformset = self.CWEFormSet(self.request.POST, prefix='cwe')

        cwes = []
        if cweformset.is_valid():

            for f in cweformset:
                cwes.append(f.cleaned_data['cwe'])
        #was=[]
        #if cvewaformset.is_valid():
        #    for f in cvewaformset:
        #        was.append(f.cleaned_data['workaround'])
        refs=[]
        if cverefformset.is_valid():
            for f in cverefformset:
                refs.append({'refsource': f.cleaned_data['ref_source'], 'url': f.cleaned_data['reference']})


        cve = form.save()
        cve.user = self.request.user

        cve.vul.description = form.cleaned_data['description']
        cve.vul.date_public = form.cleaned_date['date_public']
        cve.vul.save()

        if cwes:
            cve.cwe = json.dumps(cwes)
        #if was:
        #    cve.work_around = json.dumps(was)
        if refs:
            cve.references = json.dumps(refs)
        cve.save()

        #fix reservation
        old_cve = f"CVE-{cve.vul.cve}"
        if old_cve != cve.cve_name:
            #CVE HAS CHANGED!
            cve.vul.cve = cve.cve_name[4:]
            cve.vul.save()
            cve_res = CVEReservation.objects.filter(cve_id=cve.cve_name).first()
            if cve_res:
                cve_res.cve_info = None
                cve_res.save()
                messages.warning(self.request,
                                 f"Removing link to CVE Reservation {cve_res.cve_id} due to change in CVE")
            if cve.cve_name:
                #connect any new reservations
                cve_res = CVEReservation.objects.filter(cve_id=cve.cve_name).first()
                if cve_res:
                    logger.debug(f"FOUND RESERVATION for {x}")
                    cve_res.cve_info = cve
                    cve_res.save()
        
        if cveprodformset.is_valid():
            for f in cveprodformset:
                cd = f.cleaned_data
                prod = CVEAffectedProduct(cve = cve,
                                          name=cd['name'],
                                          version_affected=cd['version_affected'],
                                          version_name=cd['version_name'],
                                          version_value=cd['version_value'],
                                          organization=cd['organization']
                                          )
                prod.save()

        if form.cleaned_data['vul']:
            return redirect("vince:case", form.cleaned_data['vul'].case.id)

        if self.request.META.get('HTTP_REFERER') and is_safe_url(self.request.META.get('HTTP_REFERER'),set(settings.ALLOWED_HOSTS),True):
            return HttpResponseRedirect(self.request.META.get('HTTP_REFERER') + "#vuls")
        else:
            return redirect("vince:vul", cve.vul.id)

    def form_invalid(self, form):
        logger.debug("FORM INVALID")
        vul = get_object_or_404(Vulnerability, id=self.kwargs['vul'])
        return render(self.request, 'vince/cveform.html',
                      {'form': form,
                       'case': vul.case,
                       'vul': vul,
                       'prod_formset': self.CVEProductFormSet(self.request.POST, prefix='product'),
                       'cwe_formset': self.CWEFormSet(self.request.POST, prefix='cwe'),
                       'ref_formset': self.CVEReferenceFormSet(self.request.POST, prefix='ref')})
    #'wa_formset': self.CVEWorkaroundFormSet(prefix='wa')})


    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = CVEAllocationForm(request.POST)

        if form.is_valid():
            cveprodformset = self.CVEProductFormSet(self.request.POST, prefix='product')
            if cveprodformset.is_valid():
                return self.form_valid(form)
            else:
                form.add_error(None, "At least one Product is required")
                logger.debug(cveprodformset.errors)
                return self.form_invalid(form)
        else:
            logger.debug(form.errors)
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(CVEFormView, self).get_context_data(**kwargs)
        initial = {}
        oldcwes = []
        vulnote = []
        logger.debug(self.kwargs)
        if "vul" in self.kwargs:
            initial['vul'] = self.kwargs['vul']
            vul = get_object_or_404(Vulnerability, id=self.kwargs['vul'])
            context['vul'] = vul
            if vul.cve:
                initial['cve_name'] = f"CVE-{vul.cve}"
            else:
                initial['cve_name'] = "PLACEHOLDER"
            initial['description'] = vul.description
            initial['assigner'] = get_cve_assigner(self.request.user, vul.case)
            initial['date_added'] = vul.date_added
            vulcwe = VulCWE.objects.filter(vul=vul)
            for cwe in vulcwe:
                cwe_description = CWEDescriptions.objects.filter(cwe__istartswith=c.cwe).first()
                if cwe_description:
                    oldcwes.append({'cwe': cwe_description.cwe})
                else:
                    oldcwes.append({'cwe': cwe.cwe})
            context['case'] = vul.case
            if vul.case.team_owner.name == settings.ORG_NAME:
                #add vulnote
                vulnote.append({'ref_source': 'CERT-VN', 'reference': settings.KB_SERVER_NAME + reverse("vincepub:vudetail", args=[vul.case.vuid])})
        form = CVEAllocationForm(initial=initial)
            
        forms = {'prod_formset': self.CVEProductFormSet(prefix='product'),
                 'cwe_formset': self.CWEFormSet(prefix='cwe', initial=oldcwes),
                 'ref_formset': self.CVEReferenceFormSet(prefix='ref', initial=vulnote)}
        #'wa_formset': self.CVEWorkaroundFormSet(prefix='wa')}
        context['form'] = form
        context.update(forms)
        if self.request.META.get('HTTP_REFERER'):
            context['cancel_url'] = self.request.META.get('HTTP_REFERER')
        else:
            try:
                if cve.vul.case:
                    context['cancel_url'] = reverse("vince:case", args=[cve.vul.case.id])+"#vuls"
            except:
                context['cancel_url'] = reverse("vince:dashboard")
        return context

class AddVul(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    login_url = "vince:login"
    form_class = AddVulnerabilityForm
    template_name = 'vince/editvul.html'
    CWEFormSet = formset_factory(AddCVECWEForm, max_num=5, min_num=1, can_delete=True, extra=0)
    #ExploitFormSet = formset_factory(AddExploitForm, max_num=10, min_num=1, can_delete=True, extra=0)
    CVEReferenceFormSet = formset_factory(CVEReferencesForm, max_num=10, min_num=1, can_delete=True, extra=0)

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case)
        return False

    def form_valid(self, form):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        vulno = case.vul_incrementer + 1
        vul = Vulnerability(description = form.cleaned_data['description'],
                            cve = form.cleaned_data['cve'],
                            case = case,
                            case_increment = vulno,
                            ask_vendor_status = True,
                            user=self.request.user)
        logger.debug(vul)
        vul.save()
        case.vul_incrementer = vulno
        case.changes_to_publish = True
        case.save()

        tags = self.request.POST.getlist('taggles[]')
        for tag in tags:
            tag = VulnerabilityTag(vulnerability=vul,
                                   tag = tag,
                                   user = self.request.user)
            tag.save()

        errors = []
        cweformset = self.CWEFormSet(self.request.POST, prefix='cwe')
        cwes = []
        for f in cweformset:
            if f.is_valid():
                if f.cleaned_data.get('cwe'):
                    cwes.append(f.cleaned_data['cwe'])
            else:
                sterrors = str(f.errors)
                if f.cleaned_data.get('cwe') and sterrors.find("Invalid CWE"):
                    errors.append(f"Problem adding CWE {len(cwes)+1} - not a valid CWE - must start with CWE-")
                #this is the old way of storing CWE's...
                #cd = f.cleaned_data
                #vc = VulCWE(cwe=cd['cwe'],
                #            vul=vul,
                #            user=self.request.user)
                #vc.save()

        refs=[]
        cverefformset = self.CVEReferenceFormSet(self.request.POST, prefix='ref')
        for f in cverefformset:
            if f.is_valid():
                refs.append({'refsource': f.cleaned_data['ref_source'], 'url': f.cleaned_data['reference']})
            else:
                sterrors = str(f.errors)
                if f.cleaned_data.get('reference') and sterrors.find("valid URL"):
                    errors.append(f"Problem adding reference {len(refs)+1} - not a valid URL")

        #is there a CVE model for this vul?
        if refs or cwes or form.cleaned_data['date_public']:
            cve = CVEAllocation.objects.filter(vul=vul).first()
            if cve:
                cve.references = json.dumps(refs)
                cve.cwe = json.dumps(cwes)
                cve.date_public = form.cleaned_data['date_public']
                cve.save()

            else:
                if vul.cve:
                    cve_name = vul.vul
                else:
                    cve_name = "PLACEHOLDER"

                cve = CVEAllocation(vul=vul,
                                    cve_name=cve_name,
                                    description=vul.description,
                                    assigner = get_cve_assigner(self.request.user, vul.case))
                if refs:
                    cve.references=json.dumps(refs)
                if cwes:
                    cve.cwe = json.dumps(cwes)

                cve.date_public = form.cleaned_data['date_public']
                
                cve.save()

                
        """
        exploitformset = self.ExploitFormSet(self.request.POST, prefix='exploit')
        for f in exploitformset:
            if f.is_valid():
                cd = f.cleaned_data
                logger.debug("adding exploit formset!!!")
                ex = VulExploit(vul=vul,
                                user=self.request.user,
                                link=cd['link'],
                                notes=cd['notes'],
                                reference_type=cd['reference_type'],
                                reference_date=cd['reference_date'])
                ex.save()
            else:
                logger.debug(f"{self.__class__.__name__} errors: {f.errors}")
        """
        action = CaseAction(case = case,
                            title = "Added Vulnerability",
                            date = timezone.now(),
                            user = self.request.user,
                            comment=vul.vul,
                            action_type=1)
        action.save()

        if errors:
            errors = ", ".join(errors)
            messages.error(self.request,
                           f"Error processing vulnerability information: {errors}")
        
        """
        if form.cleaned_data['cve_allocator'] == 'True':
            return redirect("vince:newcve",vul.id)
        """
        if self.request.META.get('HTTP_REFERER') and is_safe_url(self.request.META.get('HTTP_REFERER'),set(settings.ALLOWED_HOSTS),True):
            return HttpResponseRedirect(self.request.META.get('HTTP_REFERER')+"#vuls")

        return redirect("vince:editvuls", case.id)

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = AddVulnerabilityForm(request.POST)

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(AddVul, self).get_context_data(**kwargs)
        form = AddVulnerabilityForm()
        #forms = {'cwe_formset': self.CWEFormSet(prefix='cwe'), 'exploit_formset': self.ExploitFormSet(prefix='exploit')}
        forms = {'cwe_formset': self.CWEFormSet(prefix='cwe'), 'ref_formset': self.CVEReferenceFormSet(prefix='ref')}
        context['form'] = form
        context['title'] = "Add Vulnerability"
        context['action'] = reverse('vince:addvul', args=[self.kwargs['pk']])
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        context['vul_tags'] = []
        context['allowed_tags'] = [tag.tag for tag in TagManager.objects.filter(tag_type=4).filter(Q(team__in=user_groups)|Q(team__isnull=True)).order_by('tag').distinct('tag')]
        context.update(forms)
        return context



class ApproveVendor(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, vendor.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        vendor = get_object_or_404(VulnerableVendor, id=self.kwargs['pk'])
        vendor.approved = True
        vendor.user_approved=self.request.user
        vendor.save()
        send_email = False
        #loop through vendor status to approve
        status = VendorStatus.objects.filter(vendor=vendor)
        for s in status:
            # if this user sent the status in via vince
            if s.approved == False:
                if s.user:
                    send_email = True
                s.approved=True
                s.user_approved=self.request.user
                s.save()
                vendor.case.changes_to_publish = True
                vendor.case.save()

        comment = "Approved all statements for %s" % (vendor.vendor)
        action = CaseAction(case = vendor.case,
                            title = "Approved All Statements",
                            date = timezone.now(),
                            user = self.request.user,
                            comment = comment,
                            action_type=1)
        action.save()
        if vendor.approve_ticket:
            logger.debug("there is a ticket on this vendor statement")
            comment = f"{self.request.user.usersettings.preferred_username} has {comment}"
            f = FollowUp(title="Statements approved and ticket closed.", ticket=vendor.approve_ticket, date=timezone.now(), comment=comment, user=self.request.user)
            f.save()
            vendor.approve_ticket.status = Ticket.CLOSED_STATUS
            vendor.approve_ticket.save()
        if send_email:
            logger.warning("THIS WOULD SEND VENDOR APPROVAL EMAILS.")
            #send_approval_email(vendor.contact, vendor.case)
        return JsonResponse({'success': True, 'link': reverse('vince:case', args=[vendor.case.id]) + '#vendors'}, status=200)

class ApproveVendorStmt(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            vul = get_object_or_404(VendorStatus, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, vul.vendor.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        vul = get_object_or_404(VendorStatus, id=self.kwargs['pk'])
        if not vul.approved:
            vul.approved = True
            vul.user_approved = self.request.user
            vul.save()
            vul.vul.case.changes_to_publish = True
            vul.vul.case.save()
            comment = "Approved %s statement on vul %s" % (vul.vendor.vendor, vul.vul.vul)
            action = CaseAction(case = vul.vul.case,
                                title = "Approved Statement",
                                date = timezone.now(),
                                user = self.request.user,
                                comment = comment,
                                action_type=1)
            if vul.vendor.approve_ticket:
                comment = f"{self.request.user.usersettings.preferred_username} has {comment}"
                f = FollowUp(title="Approved vul-specific statement.", ticket=vul.vendor.approve_ticket, date=timezone.now(), comment=comment, user=self.request.user)
                f.save()

        return JsonResponse({'success': True}, status=200)

class EditVulList(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = 'vince/vuls.html'

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(EditVulList, self).get_context_data(**kwargs)
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['pk'])
        context['case'] = case
        context['vuls'] = Vulnerability.casevuls(case)
        context['vulsjs'] = [obj.as_dict() for obj in context['vuls']]
        return context

class RemoveVulnerability(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = 'vince:login'
    template_name = "vince/remove_vul.html"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
            return has_case_write_access(self.request.user, case)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super(RemoveVulnerability, self).get_context_data(**kwargs)
        context['vul'] = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        context['action'] = reverse("vince:rmvul", args=[context['vul'].case.id, self.kwargs['pk']])
        return context


    def post(self, request, *args, **kwargs):
        case = get_object_or_404(VulnerabilityCase, id=self.kwargs['case_id'])
        vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        action = CaseAction(case = case,
                            title = "Removed Vulnerability from Case",
                            date = timezone.now(),
                            user = self.request.user,
                            comment=vul.description,
                            action_type=1)
        action.save()
        try:
            if case.vulnote.date_published or case.publicdate:
                vul.deleted = True
                vul.ask_vendor_status = False
                vul.save()
            else:
                vul.delete()
        except ObjectDoesNotExist:
            #vul note prob doesn't exist
            vul.delete()

        if self.request.META.get('HTTP_REFERER') and is_safe_url(self.request.META.get('HTTP_REFERER'),set(settings.ALLOWED_HOSTS),True):
            return HttpResponseRedirect(self.request.META.get('HTTP_REFERER') + "#vuls")
        return redirect("vince:editvuls", case.id)



class VulnerabilityDetailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = Vulnerability
    login_url = "vince:login"

    def	test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case.case)
        return False


class VulCVSSView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = VulCVSS
    login_url = "vince:login"
    template_name = "vince/cvss.html"

    
    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        logger.debug(self.kwargs['pk'])
        if int(self.kwargs['pk']) != int(self.request.POST.get('vul')):
            #this was messed with
            raise Http404
        
        vulcvss = VulCVSS.objects.filter(vul__id=self.kwargs['pk']).first()
        if vulcvss:
            form = VulCVSSForm(self.request.POST, instance=vulcvss)
        else:
            form = VulCVSSForm(self.request.POST)
        if form.is_valid():
            vulcvss = form.save()
            vulcvss.scored_by = self.request.user
            vulcvss.severity = self.request.POST.get('severity')
            vulcvss.vector = self.request.POST.get('vector')
            vulcvss.score = self.request.POST.get('score')
            
            vulcvss.save()
        else:
            logger.debug(form.errors)
        
        return JsonResponse({'success': True}, status=200)

    def get_context_data(self, **kwargs):
        context = super(VulCVSSView, self).get_context_data(**kwargs)
        context['vul'] = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        vulcvss = VulCVSS.objects.filter(vul=context['vul']).first()
        if vulcvss:
            context['form'] = VulCVSSForm(instance=vulcvss)
        else:
            context['form'] = VulCVSSForm(initial={'vul':context['vul']})
        return context
    
class RemoveVulSSVCView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = VulSSVC
    login_url = "vince:login"
    template_name = 'vince/confirm_rm_score.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        ssvc = get_object_or_404(VulSSVC, vul__id=self.kwargs['pk'])

        ssvc.delete()
        messages.success(
            self.request,
            _(f"Score has been successfully removed"))

        return redirect("vince:vul", self.kwargs['pk'])

    def get_context_data(self, **kwargs):
        context = super(RemoveVulSSVCView, self).get_context_data(**kwargs)
        context['vul'] = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        context['ssvc'] = get_object_or_404(VulSSVC, vul__id=self.kwargs['pk'])
        context['title'] = "Are you sure you want to remove this SSVC Score?"
        context['action'] = reverse("vince:rmvulssvc", args=[self.kwargs['pk']])
        return context


class RemoveVulCVSSView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = 'vince/confirm_rm_score.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        ssvc = get_object_or_404(VulCVSS, vul__id=self.kwargs['pk'])

        ssvc.delete()

        messages.success(
            self.request,
            _(f"Score has been successfully removed"))
        
        return redirect("vince:vul", self.kwargs['pk'])

    def get_context_data(self, **kwargs):
        context = super(RemoveVulCVSSView, self).get_context_data(**kwargs)
        context['vul'] = get_object_or_404(Vulnerability, id=self.kwargs['pk']) 	
        context['ssvc'] = get_object_or_404(VulCVSS, vul__id=self.kwargs['pk'])
        context['title'] = "Are you sure you want to remove this CCVS score?"
        context['action'] = reverse("vince:rmvulcvss", args=[self.kwargs['pk']])
        return context
        
    
class VulSSVCView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = VulSSVC
    login_url = "vince:login"
    template_name = 'vince/ssvc.html'

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_write_access(self.request.user, case.case)
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)

        exploit = self.request.POST.get('data[choices][0][Exploitation]')
        if exploit == 'none':
            exploit = 0
        elif exploit == 'poc':
            exploit = 1
        else:
            exploit = 2

        automatable = self.request.POST.get('data[choices][1][Automatable]')
        if automatable == 'no':
            automatable = False
        else:
            automatable = True

        tech_impact = self.request.POST.get('data[choices][2][Technical Impact]')
        if tech_impact == 'partial':
            tech_impact = 1
        elif tech_impact == 'total':
            tech_impact = 2
        else:
            tech_impact = 0

        decision = self.request.POST.get('data[choices][4][Decision]')
            
        json_file = self.request.POST.get('file')
        if json_file:
            json_file = json.loads(json_file)
            
        vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
        vulssvc = VulSSVC.objects.update_or_create(vul=vul,
                                                   defaults = {'state': exploit,
                                                               'automatable': automatable,
                                                               'technical_impact': tech_impact,
                                                               'decision':decision,
                                                               'user':self.request.user,
                                                               'last_edit': timezone.now(),
                                                               'json_file': json_file}
                                                   )
        
        return JsonResponse({'message': 'success', 'url':reverse("vince:pendingusers")}, status=200)
    

    
class VulnerabilityView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = Vulnerability
    login_url = "vince:login"
    template_name = "vince/vul.html"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            case = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            return has_case_read_access(self.request.user, case.case)
        return False

    def get_context_data(self, **kwargs):
        context = super(VulnerabilityView, self).get_context_data(**kwargs)
        context['vul'] = get_object_or_404(Vulnerability, id=self.kwargs['pk'])

        context['vendor_list'] = VendorStatus.objects.filter(vul=context['vul']).order_by('vendor__contact__vendor_name')
        vlist = context['vendor_list'].values_list('vendor__id', flat=True)
        logger.debug(vlist)
        context['vendor_unknown_list'] = VulnerableVendor.objects.filter(case=context['vul'].case, deleted=False).exclude(id__in=vlist).order_by('contact__vendor_name')
        context['cveallocation'] = CVEAllocation.objects.filter(vul=context['vul']).first()
        context['exploits'] = VulExploit.objects.filter(vul=context['vul'])
        user_groups= self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        context['vul_tags'] = [tag.tag for tag in context['vul'].vulnerabilitytag_set.all()]
        context['allowed_tags'] = [tag.tag for tag in TagManager.objects.filter(tag_type=4).filter(Q(team__in=user_groups)|Q(team__isnull=True)).order_by('tag').distinct('tag')]
        return context

class VendorStatusListView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name="vince/vendorstatuslist.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VendorStatusListView, self).get_context_data(**kwargs)
        my_cases = CaseAssignment.objects.filter(assigned=self.request.user).distinct().values_list('case', flat=True)
        approval = VendorStatus.objects.filter(vendor__case__in=my_cases, approved=False)
        context['object_list'] = approval
        return context

class IgnoredUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/ignored_users.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(IgnoredUserView, self).get_context_data(**kwargs)
        context['ignored_users'] = User.objects.using('vincecomm').filter(vinceprofile__pending=True, vinceprofile__ignored=True).order_by('-date_joined')
        return context

class AddUserToContactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    template_name = "vince/addusertocontact.html"
    login_url="vince:login"
    form_class=AddUserToContactForm

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        vendors = request.POST.getlist('vendors[]')
        newuser = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        for vendor in vendors:
            contact = Contact.objects.filter(vendor_name=vendor).first()
            if contact:
                #add this user to contact
                logger.debug("Adding user to contact %s" % contact.vendor_name)
                email, created = EmailContact.objects.update_or_create(contact=contact,
                                                              email=newuser.username,
                                                              defaults={'name': newuser.get_full_name(),
                                                                        'user_added':self.request.user})
                vinny_contact = VinceCommContact.objects.filter(vendor_id=contact.id).first()
                vinny_email_contact, created = VinceCommEmail.objects.update_or_create(contact=vinny_contact,
                                                                              email=newuser.username, defaults={'name':newuser.get_full_name(), 'email_list': False})
                _add_activity(self.request.user, 3, email.contact, f"approved user {newuser.username} and added to contact")

                messages.success(
                    self.request,
                    _(f"User has been added to Contact: {vendor}"))

        return JsonResponse({'message': 'success', 'url':reverse("vince:pendingusers")}, status=200)

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(AddUserToContactView, self).get_context_data(**kwargs)
        context['newuser'] = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        return context

    def get_form_kwargs(self):
        kwargs = super(AddUserToContactView, self).get_form_kwargs()
        kwargs.update({
            "user": self.kwargs['pk'],
        })
        return kwargs

class ApproveUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/approve_users.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_read_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ApproveUserView, self).get_context_data(**kwargs)
        context['pending_users'] = User.objects.using('vincecomm').filter(vinceprofile__pending=True, vinceprofile__ignored=False).order_by('-date_joined')
        today = datetime.today()
        date_7 = date_rel_to_today(today, 7)
        date_7_str = date_7.strftime('%Y-%m-%d')
        context['last_week'] = User.objects.using('vincecomm').filter(date_joined__gte=date_7_str, vinceprofile__pending=False).order_by('-date_joined')
        return context

    def post(self, request, *args, **kwargs):
        if not get_contact_write_perms(self.request.user):
            raise PermissionDenied()

        user = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        if user:
            user.vinceprofile.pending=False
            user.vinceprofile.save()
            send_user_approve_notification(user.email)
        else:
            raise Http404
        data = {}
        data['pending_users'] = User.objects.using('vincecomm').filter(vinceprofile__pending=True, vinceprofile__ignored=False).order_by('-date_joined')
        return render(request, 'vince/pending_users.html', data, status=200)


class InitiateMFAReset(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/initiateresetmfa.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(InitiateMFAReset, self).get_context_data(**kwargs)
        context["vc_user"] = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        return context

    def post(self, request, *args, **kwargs):
        user = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        if not user:
            raise Http404

        if self.request.POST.get('ticket_id'):
            ticket_id = self.request.POST['ticket_id']
            if '-' in ticket_id:
                ticket_id = ticket_id.split('-')[1:][0]

            ticket = get_object_or_404(Ticket, id=ticket_id)
            ticket.status = Ticket.OPEN_STATUS
            ticket.save()
        else:
            ticket = Ticket(title = f"Confirm MFA reset for {user.email}",
                            status = Ticket.OPEN_STATUS,
                            submitter_email = user.email,
                            assigned_to = self.request.user,
                            queue = get_user_gen_queue(self.request.user),
                            description=f"User requested MFA reset")
        ticket.save()

        # don't create more of these, if one exists already

        mfatkt = MFAResetTicket.objects.update_or_create(user_id=self.kwargs['pk'],
                                                         ticket=ticket)

        email_template = EmailTemplate.objects.get(template_name="mfa_reset_request")


        notification = VendorNotificationEmail(subject=email_template.subject,
                                               email_body = email_template.plain_text)
        notification.save()

        email = VinceEmail(ticket=ticket,
                           notification=notification,
                           user=self.request.user,
                           email_type=1,
                           to=user.email)
        email.save()

        send_reset_mfa_email(user, ticket, "mfa_reset_request")

        email_content = get_mail_content(ticket, "mfa_reset_request")
        fup = FollowUp(title=f"Email sent to {user.email} confirming MFA reset request.",
                       comment=email_content,
                       ticket=ticket,
                       user=self.request.user)

        fup.save()
        
        messages.success(self.request,
                         _("Reset confirmation email sent. Refer to this ticket. This ticket should remain Open until the reset is complete."))

        return redirect("vince:ticket", ticket.id)

class ResetUserMFAView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/resetmfa.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ResetUserMFAView, self).get_context_data(**kwargs)
        context['vc_user'] = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        data = get_user_details(context['vc_user'].username)
        if data.get('PreferredMfaSetting') == "SMS_MFA":
            attributes = data.get('UserAttributes')
            for x in attributes:
                if x["Name"] == 'phone_number':
                    context['sms'] = x["Value"]
                    break
        return context

    def post(self, request, *args, **kwargs):
        user = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        if not user:
            raise Http404

        data = get_user_details(user.username)
        error = False
        totp = "TOTP"
        if data.get('PreferredMfaSetting') == 'SOFTWARE_TOKEN_MFA':
            logger.debug(f"{user.username} is using softwaretokenmfa")
            try:
                disable_totp_mfa(user.username)
            except Exception as e:
                messages.error(
                    self.request,
                    _("Error with resetting this user's TOTP"))
                error = True
                logger.debug(e)
        else:
            logger.debug(f"{user.username} is using sms mfa")
            totp = "SMS"
            try:
                disable_sms_mfa(user.username)
            except Exception as e:
                logger.debug(e)
                error = True
                messages.error(
                    self.request,
                    _("Error with resetting this user's SMS"))

        if not(error):
            send_courtesy_email("mfa_removed", user)
            messages.success(
                self.request,
                _(f"User {totp} MFA was successfully reset. {user.username} will be prompted to re-associate MFA on next login"))
            user.vinceprofile.multifactor = False
            user.vinceprofile.save()

            # close mfa reset ticket
            reset_tkts = MFAResetTicket.objects.filter(user_id=user.id, ticket__status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS])
            for x in reset_tkts:
                x.ticket.status = Ticket.CLOSED_STATUS
                x.ticket.resolution = f"{self.request.user.usersettings.preferred_username} reset MFA"
                x.ticket.save()
                fup = FollowUp(title=f"{self.request.user.usersettings.preferred_username} reset user's MFA",
                               ticket=x.ticket,
                               user=self.request.user)
                fup.save()

        return redirect("vince:vcuser", self.kwargs['pk'])


class RemoveUserCognitoView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/remove_user.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and get_contact_write_perms(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RemoveUserCognitoView, self).get_context_data(**kwargs)
        context['pending_user'] = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        return context

    def post(self, request, *args, **kwargs):
        user = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        if user:
            user.vinceprofile.ignored=True
            user.vinceprofile.save()

        else:
            raise Http404
        data = {}
        data['pending_users'] = User.objects.using('vincecomm').filter(vinceprofile__pending=True, vinceprofile__ignored=False).order_by('-date_joined')
        return redirect("vince:pendingusers")

class ContactUpdateView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = 'vince/contactupdatelist.html'

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ContactUpdateView, self).get_context_data(**kwargs)
        contacts = ContactInfoChange.objects.filter(approved=False).distinct('contact')
        context['object_list'] = contacts
        return context

class PrintReportsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/printreport.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        if check_misconfiguration(self.request.user):
            return redirect("vince:misconfigured")
        return super().get(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super(PrintReportsView, self).get_context_data(**kwargs)
        year = int(self.kwargs['year'])
        month = int(self.kwargs['month'])
        if month == 0:
            month = 12
            year = year - 1
        elif month > 12:
            month = 1
            year = year	+ 1
        context['year'] = year
        context['monthstr'] = date(year, month, 1).strftime('%B')
        context['month'] = month

        context['teams'] = Group.objects.exclude(groupsettings__contact__isnull=True)
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if self.kwargs.get('pk'):
            context['my_team'] = Group.objects.get(id=self.kwargs.get('pk'))
            context['teams'] = context['teams'].exclude(id=self.kwargs.get('pk'))
        else:
            context['my_team'] = user_groups[0]
            context['teams'] = context['teams'].exclude(id=context['my_team'].id)
            # this team's queues
        my_queues = get_team_queues(context['my_team'])
        context['newnotes'] = VulnerabilityCase.objects.filter(vulnote__date_published__year=year, vulnote__date_published__month=month, team_owner=context['my_team']).exclude(vulnote__date_published__isnull=True)
        context['updated'] = VulnerabilityCase.objects.filter(vulnote__date_last_published__year=year, vulnote__date_last_published__month=month, team_owner=context['my_team']).exclude(vulnote__date_published__isnull=True)
        context['ticket_emails'] = FollowUp.objects.filter(title__icontains="New Email", date__year=year, date__month=month, ticket__queue__in=my_queues).exclude(ticket__case__isnull=False)
        context['case_emails'] = FollowUp.objects.filter(title__icontains="New Email", date__year=year, date__month=month, ticket__queue__in=my_queues).exclude(ticket__case__isnull=True)
        context['case_emails_distinct'] = context['case_emails'].order_by('ticket__case__id').distinct('ticket__case__id').count()
        context['total_emails'] = len(context['ticket_emails']) + len(context['case_emails'])
        context['total_tickets'] = Ticket.objects.filter(queue__in=my_queues, created__year=year, created__month=month).count()
        context['ticket_stats'] = Ticket.objects.filter(queue__in=my_queues, created__year=year, created__month=month).values('queue__title').order_by('queue__title').annotate(count=Count('queue__title')).order_by('-count')
        context['total_closed'] = Ticket.objects.filter(queue__in=my_queues, created__year=year, created__month=month, status=Ticket.CLOSED_STATUS).count()
        context['closed_ticket_stats'] = Ticket.objects.filter(queue__in=my_queues, created__year=year, created__month=month,status=Ticket.CLOSED_STATUS).values('close_reason').order_by('close_reason').annotate(count=Count('close_reason')).order_by('-count')
        new_cases = VulnerabilityCase.objects.filter(created__year=year, created__month=month, team_owner=context['my_team']).order_by('created')
        date_month = date(year, month, 1)
        active_cases = VulnerabilityCase.objects.filter(status = VulnerabilityCase.ACTIVE_STATUS, created__lt=date_month, team_owner=context['my_team'])
        deactive_cases = CaseAction.objects.filter(title__icontains="changed status of case from Active to Inactive", date__month=month, date__year=year, case__team_owner=context['my_team']).select_related('case').order_by('case').distinct('case')
        to_active_cases = CaseAction.objects.filter(title__icontains="changed status of case from Inactive to Active", date__month=month, date__year=year, case__team_owner=context['my_team']).select_related('case').order_by('case').distinct('case')
        context.update({'case_stats': {'new_cases':new_cases,
                                       'active_cases': active_cases,
                                       'deactive_cases': deactive_cases,
                                       'to_active_cases': to_active_cases}})
        context['new_users'] = User.objects.using('vincecomm').filter(date_joined__month=month, date_joined__year=year).count()
        context['total_users'] = User.objects.using('vincecomm').all().count()
        vendor_group_dict = {group.name:group.user_set.count() for group in Group.objects.using('vincecomm').exclude(groupcontact__isnull=True) if group.user_set.count() > 0}
        context['vendors'] = len(vendor_group_dict)
        vendor_groups = Group.objects.using('vincecomm').exclude(groupcontact__isnull=True)
        context['vendor_users'] = User.objects.using('vincecomm').filter(groups__in=vendor_groups).distinct().count()
        context['fwd_reports'] = FollowUp.objects.filter(title__icontains="Successfully forwarded", date__month=month, date__year=year, ticket__queue__in=my_queues)
        return context



class ReportsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/reports.html"

    def	test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        if check_misconfiguration(self.request.user):
            return redirect("vince:misconfigured")
        return super().get(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super(ReportsView, self).get_context_data(**kwargs)
        year = int(self.request.GET.get('year', datetime.now().year))
        month = int(self.request.GET.get('month', datetime.now().month))
        if month == 0:
            month = 12
            year = year - 1
        elif month > 12:
            month = 1
            year = year + 1
        context['year'] = year
        context['monthstr'] = date(year, month, 1).strftime('%B')
        context['month'] = month
        context['teams'] = Group.objects.exclude(groupsettings__contact__isnull=True)
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if self.kwargs.get('pk'):
            context['my_team'] = Group.objects.get(id=self.kwargs.get('pk'))
            context['teams'] = context['teams'].exclude(id=self.kwargs.get('pk'))
        else:
            context['my_team'] = user_groups[0]
            context['teams'] = context['teams'].exclude(id=context['my_team'].id)
            # this team's queues

        my_queues = get_team_queues(context['my_team'])            
        context['newnotes'] = VulnerabilityCase.objects.filter(vulnote__date_published__year=year, vulnote__date_published__month=month, team_owner=context['my_team']).exclude(vulnote__date_published__isnull=True)
        context['updated'] = VulnerabilityCase.objects.filter(vulnote__date_last_published__year=year, vulnote__date_last_published__month=month, team_owner=context['my_team']).exclude(vulnote__date_published__isnull=True)
        context['ticket_emails'] = FollowUp.objects.filter(title__icontains="New Email", date__year=year, date__month=month, ticket__queue__in=my_queues).exclude(ticket__case__isnull=False)
        context['case_emails'] = FollowUp.objects.filter(title__icontains="New Email", ticket__queue__in=my_queues, date__year=year, date__month=month).exclude(ticket__case__isnull=True)
        context['case_emails_distinct'] = context['case_emails'].order_by('ticket__case__id').distinct('ticket__case__id').count()
        context['total_emails'] = len(context['ticket_emails']) + len(context['case_emails'])
        if (month < datetime.now().month) and (year <= datetime.now().year):
            context['show_next'] = 1
        elif (year < datetime.now().year):
            context['show_next'] = 1
        context['total_tickets'] = Ticket.objects.filter(queue__in=my_queues, created__year=year, created__month=month).count()
        context['ticket_stats'] = Ticket.objects.filter(queue__in=my_queues, created__year=year, created__month=month).values('queue__title').order_by('queue__title').annotate(count=Count('queue__title')).order_by('-count')
        context['total_closed'] = Ticket.objects.filter(queue__in=my_queues, created__year=year, created__month=month, status=Ticket.CLOSED_STATUS).count()
        context['closed_ticket_stats'] = Ticket.objects.filter(queue__in=my_queues, created__year=year, created__month=month, status=Ticket.CLOSED_STATUS).values('close_reason').order_by('close_reason').annotate(count=Count('close_reason')).order_by('-count')

        new_cases = VulnerabilityCase.objects.filter(created__year=year, created__month=month, team_owner=context['my_team']).order_by('created')
        date_month = date(year, month, 1)
        active_cases = VulnerabilityCase.objects.filter(status = VulnerabilityCase.ACTIVE_STATUS, created__lt=date_month, team_owner=context['my_team'])
        deactive_cases = CaseAction.objects.filter(title__icontains="changed status of case from Active to Inactive", date__month=month, date__year=year, case__team_owner=context['my_team']).select_related('case').order_by('case').distinct('case')
        to_active_cases = CaseAction.objects.filter(title__icontains="changed status of case from Inactive to Active", date__month=month, date__year=year, case__team_owner=context['my_team']).select_related('case').order_by('case').distinct('case')
        context.update({'case_stats': {'new_cases':new_cases,
                                       'active_cases': active_cases,
                                       'deactive_cases': deactive_cases,
                                       'to_active_cases': to_active_cases}})
        context['new_users'] = User.objects.using('vincecomm').filter(date_joined__month=month, date_joined__year=year).count()
        context['total_users'] = User.objects.using('vincecomm').all().count()
        vendor_group_dict = {group.name:group.user_set.count() for group in Group.objects.using('vincecomm').exclude(groupcontact__isnull=True) if group.user_set.count() > 0}
        vendor_groups = Group.objects.using('vincecomm').exclude(groupcontact__isnull=True)
        context['vendor_users'] = User.objects.using('vincecomm').filter(groups__in=vendor_groups).distinct().count()
        context['vendors'] = len(vendor_group_dict)
        context['cves'] = Vulnerability.objects.filter(date_added__year=year, date_added__month=month, case__team_owner=context['my_team']).exclude(cve__isnull=True)
        context['cves_reserved'] = CVEReservation.objects.filter(time_reserved__year=year, time_reserved__month=month, account__team=context['my_team'])
        tickets_in_queues = Ticket.objects.filter(queue__in=my_queues)
        context['basic_ticket_stats'] = calc_basic_ticket_stats(tickets_in_queues)

        context['reportpage']=1

        read_queues = get_r_queues(self.request.user)
        context['tickettags'] = TicketTag.objects.filter(ticket__queue__in=my_queues).values('tag').order_by('tag').annotate(count=Count('tag')).annotate(month_count=Count('tag', filter=Q(ticket__created__year=year, ticket__created__month=month))).order_by('-tag')
        logger.debug(context['tickettags'])
        #context['tickettags'] = TicketTag.objects.filter(ticket__queue__in=my_queues).values('tag').order_by('tag').annotate(count=Count('tag')).order_by('-count')
        logger.debug(context['tickettags'])
        context['casetags'] = CaseTag.objects.filter(case__team_owner=context['my_team']).values('tag').order_by('tag').annotate(count=Count('tag')).annotate(count=Count('tag')).annotate(month_count=Count('tag', filter=Q(created__year=year, created__month=month))).order_by('-count')

        context['vultags'] = VulnerabilityTag.objects.filter(vulnerability__case__team_owner=context['my_team']).values('tag').order_by('tag').annotate(count=Count('tag')).annotate(count=Count('tag')).annotate(month_count=Count('tag', filter=Q(vulnerability__date_added__year=year, vulnerability__date_added__month=month))).order_by('-count')
        context['fwd_reports'] = FollowUp.objects.filter(title__icontains="Successfully forwarded", ticket__queue__in=my_queues, date__month=month, date__year=year)

        return context


class UserGraphReport(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/usergraphs.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)


    def post(self, request, *args, **kwargs):
        logger.debug(f"UserGraphReport Post: {self.request.POST}")
        month = self.request.POST['month']
        dt = datetime.strptime(month, '%b-%y')
        logger.debug(dt)
        users = User.objects.using('vincecomm').filter(date_joined__month=dt.month,
                                                       date_joined__year=dt.year) \
                    .annotate(day=TruncDay("date_joined")) \
                    .values("day") \
                    .annotate(c=Count("id")) \
                    .order_by("day")
        userlist = []
        cumulative_users=[]
        total = 0
        for x in users:
            userlist.append({'label':x["day"].strftime("%b-%d"), 'c':x["c"]})
            total = total + x["c"]
            cumulative_users.append({'label':x["day"].strftime("%b-%d"), 'c':total})
        
        vendor_groups = Group.objects.using('vincecomm').exclude(groupcontact__isnull=True)
        vendorusers = User.objects.using('vincecomm').filter(groups__in=vendor_groups,
                                                             date_joined__month=dt.month,
                                                             date_joined__year=dt.year).distinct() \
                                                     .annotate(day=TruncDay("date_joined"))\
                                                     .values("day") \
                                                     .annotate(c=Count("id")) \
                                                     .order_by("day")
        vendoruserlist=[]
        vendors_cumulative = []
        total = 0
        for x in vendorusers:
            vendoruserlist.append({'label':x['day'].strftime("%b-%d"), 'c':x["c"]})
            total = total + x["c"]
            vendors_cumulative.append({'label':x['day'].strftime("%b-%d"), 'c':total})

        return JsonResponse({'status': 'success', 'users':userlist,
                             'cumusers':cumulative_users,
                             'vendors': vendoruserlist,
                             'vendorscum': vendors_cumulative}, status=200)
    
    def get_context_data(self, **kwargs):
        context = super(UserGraphReport, self).get_context_data(**kwargs)
        users = User.objects.using('vincecomm').all() \
                    .annotate(month=TruncMonth("date_joined")) \
                    .values("month") \
                    .annotate(c=Count("id")) \
                    .order_by("month")

        userlist = []
        cumulative_users=[]
        total = 0
        monthly = []
        total_months = lambda dt: dt.month + 12 * dt.year
        if users:
            for tot_m in range(total_months(users[0]["month"]) - 1, total_months(users[len(users)-1]["month"])):
                y, m = divmod(tot_m, 12)
                monthly.append(datetime(y, m+1, 1).strftime("%b-%y"))

            if not(monthly):
                logger.debug("ONLY 1 month")
                monthly = [users[0]["month"].strftime("%b-%y")]
            
        for x in monthly:
            month = datetime.strptime(x, "%b-%y").month
            year = datetime.strptime(x, "%b-%y").year
            count = User.objects.using('vincecomm').filter(date_joined__month=month, date_joined__year=year).count()
            if count:
                userlist.append({'label': x, 'c': count})
                total = total + count
            else:
                userlist.append({'label': x, 'c': 0})

            cumulative_users.append({'label':x, 'c':total})

        context['userregjs'] = userlist
        context['cumulativeusersjs'] = cumulative_users
        
        vendor_groups = Group.objects.using('vincecomm').exclude(groupcontact__isnull=True)
        """vendorusers = User.objects.using('vincecomm').filter(groups__in=vendor_groups).distinct() \
                                                     .annotate(month=TruncMonth("date_joined"))\
                                                     .values("month") \
                                                     .annotate(c=Count("id")) \
                                                     .order_by("month")"""
        vendoruserlist=[]
        vendors_cumulative = []
        total = 0
        last_month = 0
        for x in monthly:
            month = datetime.strptime(x, "%b-%y").month
            year = datetime.strptime(x, "%b-%y").year
            count =  User.objects.using('vincecomm').filter(groups__in=vendor_groups, date_joined__month=month, date_joined__year=year).distinct().count()
            if count:
                vendoruserlist.append({'label': x, 'c': count})
                total = total + count
            else:
                vendoruserlist.append({'label':x, 'c': 0})

            vendors_cumulative.append({'label':x, 'c':total})

        context['vendorsjs'] = vendoruserlist
        context['vendorscumulativejs'] = vendors_cumulative
        return context
        

    
class TriageView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView, FormMixin):
    login_url = "vince:login"
    template_name = "vince/triage.html"
    model = Ticket
    paginate_by = 50
    form_class = TriageFilterForm

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            if self.kwargs.get('pk'):
                return has_queue_read_access(self.request.user, self.kwargs.get('pk'))
            else:
                return True
        else:
            return False        


    def get_queryset(self):
        if self.kwargs.get('pk'):
            queue = TicketQueue.objects.get(id=self.kwargs.get('pk'))
            my_queues = TicketQueue.objects.filter(team=queue.team)
        else:
            my_queues = get_rw_queues(self.request.user)
        return Ticket.objects.filter(queue__in=my_queues, status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS]).exclude(assigned_to__isnull=False).order_by('-modified')

    def post(self, request, *args, **kwargs):
        logger.debug(f"TicketFilterResult Post: {self.request.POST}")

        res = self.get_queryset()

        page = self.request.POST.get('page', 1)

        if 'datestart' in self.request.POST:
            # add a day to dateend since it translates to 0AM
            enddate = DateTimeField().clean(self.request.POST['dateend']) + timedelta(days=1)
            if self.request.POST['datestart']:
                res = res.filter(created__range=(DateTimeField().clean(self.request.POST['datestart']), enddate))
            elif 'dateend' in self.request.POST:
                if self.request.POST['dateend']:
                    res = res.filter(created__range=(DateTimeField().clean('1970-01-01'), enddate))

        if 'queue' in self.request.POST:
            queuelist = self.request.POST.getlist('queue')
            res = res.filter(queue__id__in=queuelist)

        if 'wordSearch' in self.request.POST:
            if self.request.POST['wordSearch']:
                wordSearch = process_query(self.request.POST['wordSearch'])
                titlesearch = res.filter(title__icontains=self.request.POST['wordSearch'])
                res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[wordSearch])
                res = res | titlesearch

        paginator = Paginator(res, 50)

        return render(request, "vince/searchresults.html", {'object_list': paginator.page(page), 'total': res.count(), 'show_params': 1 })

    def get_context_data(self, **kwargs):
        context = super(TriageView, self).get_context_data(**kwargs)
        context['triagepage']=1
        context['triage_user'] = get_triage_users(self.request.user)
        context['contact_changes'] = ContactInfoChange.objects.filter(approved=False).values('contact__vendor_name').distinct().count()
        context['pending_users'] = User.objects.using('vincecomm').filter(vinceprofile__pending=True, vinceprofile__ignored=False).count()
        if self.kwargs.get('pk'):
            context['my_cr'] = TicketQueue.objects.get(id=self.kwargs.get('pk'))
        else:
            context['my_cr'] = get_user_cr_queue(self.request.user)
        #get team queues for form
        readable_queues = TicketQueue.objects.filter(team=context['my_cr'].team)
        context['teams'] = get_all_cr_queue(self.request.user)
        bounces = FollowUp.objects.filter(title__istartswith="Email Bounce Notification", ticket__status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS])
        context['pbounces'] = BounceEmailNotification.objects.filter(bounce_type=BounceEmailNotification.PERMANENT, action_taken=False)
        date_from = self.request.GET.get('date_from')
        initial = {}
        if date_from:
            initial['datestart'] = DateField().clean(date_from)
        date_to = self.request.GET.get('date_to')
        if date_to:
            initial['dateend'] = DateField().clean(date_to)
        queue = self.request.GET.get('queue')
        if queue:
            queue = TicketQueue.objects.filter(title=queue).first()
            initial['queue'] = queue.id
        form = TriageFilterForm(initial=initial)
        form.fields['queue'].choices = [
            (q.id, q.title) for q in readable_queues]
        context['form'] = form
        return context

class CasesWithoutVendorsReport(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    login_url = "vince:login"
    template_name = "vince/casesnovendors.html"
    paginate_by = 20

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_queryset(self):
        return VulnerabilityCase.objects.exclude(id__in=VulnerableVendor.objects.all().values('case__id'))

    def get_context_data(self, **kwargs):
        context = super(CasesWithoutVendorsReport, self).get_context_data(**kwargs)
        context['reportpage']=1
        return context

class VinceCommUserThreadView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/include/threads.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VinceCommUserThreadView, self).get_context_data(**kwargs)
        context['vc_user'] = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        page = self.request.GET.get('page', 1)
        threads = Thread.ordered(Thread.all(context['vc_user']))
        paginator = Paginator(threads, 10)
        context['threads'] = paginator.page(page)
        return context

class Vince2VCUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/vincecomm_user.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def dispatch(self, request, *args, **kwargs):
        user = get_object_or_404(User, id=self.kwargs['pk'])

        #lookup vc user
        vcuser = User.objects.using('vincecomm').filter(email=user.email).first()
        if vcuser:
            return redirect("vince:vcuser", vcuser.id)
        else:
            raise Http404

    
class VinceCommUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/vincecomm_user.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VinceCommUserView, self).get_context_data(**kwargs)
        context['vc_user'] = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        context['contactpage'] = 1
        if context['vc_user']:
            context['activity'] = VendorAction.objects.using('vincecomm').filter(user=context['vc_user']).order_by('-created')[:30]
            context['contact'] = EmailContact.objects.filter(email=context['vc_user'].username)
            context['contact_record'] = EmailContact.objects.filter(email=context['vc_user'].username, contact__vendor_type="Contact").first()
            threads = Thread.ordered(Thread.all(context['vc_user']))
            paginator = Paginator(threads, 10)
            page = 1
            context['threads'] = paginator.page(page)
            context['ticket_list'] = Ticket.objects.filter(submitter_email=context['vc_user'].username).order_by('-created')
            context['reset_mfa'] = MFAResetTicket.objects.filter(user_id=context['vc_user'].id, ticket__status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS]).exists()
            context['bounce_stats'] = get_bounce_stats(context['vc_user'].email, context['vc_user'])
            context['bounces'] = BounceEmailNotification.objects.filter(email=context['vc_user'].email)
        return context

class VinceCommRemoveUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = 'vince/vincecomm_user_rm.html'

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VinceCommRemoveUserView, self).get_context_data(**kwargs)
        context['vc_user'] = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        context['action'] = reverse('vince:vcuser_rm', args=[self.kwargs['pk']])
        if self.request.GET.get('tkt'):
            context['bounce_ticket'] = self.request.GET.get('tkt')
        return context

    def post(self, request, *args, **kwargs):
        user = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
        if user:
            user.is_active=False
            user.save()
            check_ga = None
            groups = user.groups.all()
            for group in groups:
                group.user_set.remove(user)
            emails = VinceCommEmail.objects.filter(email__iexact=user.username)
            for email in emails:
                ga = VinceCommGroupAdmin.objects.filter(email=email).first()
                if ga:
                    check_ga = ga
                email.delete()
            emails = EmailContact.objects.filter(email__iexact=user.username)
            for email in emails:
                _add_activity(self.request.user, 3, email.contact, f"removed email address {email.email}")
                email.delete()
            #look for cases that this user may have participanted in
            cps = CaseParticipant.objects.filter(user_name__iexact=user.username)
            for cp in cps:
                ca = CaseAction(case=cp.case, title="Removed Participant from Case",
                                comment="Participant %s removed from case" % cp.user_name,
                                user=self.request.user, action_type=1)
                ca.save()
                remove_participant_vinny_case(cp.case, cp)
                cp.delete()

            if self.request.POST.get('ticket'):
                tkt = Ticket.objects.filter(id=self.request.POST['ticket']).first()
                if tkt:
                    fup = FollowUp(user=self.request.user,
                                   ticket=tkt,
                                   title="VINCE user removed due to permanent bounce")
                    fup.save()
            #close any bounces that may be associated with this user
            bn = BounceEmailNotification.objects.filter(email=user.email, action_taken=False)
            for b in bn:
                b.action_taken=True
                b.save()
                
            messages.success(
                self.request,
                _("The user has been removed from all groups and contacts and is now inactive"))
            if check_ga:
                messages.warning(
                    self.request,
                    _(f"This user has been removed as a group admin for {ga.contact.vendor_name}. Please reassign a new group admin."))
            return redirect("vince:vcuser", user.id)
        else:
            messages.error(
                self.request,
                _("Error: User was not found"))
            return redirect("vince:vc_user", user.id)


class TriageAddEvent(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/addevent.html"
    model = CalendarEvent

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)

        if self.request.POST.get('arg'):
            initial = {}
            initial["date"] = self.request.POST.get('arg')
            form = CalendarEventForm(initial=initial)
            user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            assignable_users = User.objects.filter(is_active=True, groups__in=user_groups).order_by(User.USERNAME_FIELD)

            form.fields['user'].choices = [(u.id, u.usersettings.vince_username) for u in assignable_users]
            return render(request, self.template_name, {'form': form})
        elif self.request.POST.get('newend'):
            # edit the enddate on this event
            event = get_object_or_404(CalendarEvent, id=self.request.POST.get('event_id'))
            event.end_date = self.request.POST.get('newend')
            event.save()
            return JsonResponse({'status': 'success'}, status=200)
        else:
            if self.request.POST.get('user'):
                user_assigned = User.objects.get(id=self.request.POST['user'])
            else:
                user_assigned = self.request.user

            if self.request.POST['event_id'] == "1":
                title = f"{user_assigned.usersettings.preferred_username} TRIAGE"
                classname = 'triage_event'
            else:
                title = f"{user_assigned.usersettings.preferred_username} OOF"
                classname = 'oof_event'
            #create the event
            event, created = CalendarEvent.objects.update_or_create(
                user=user_assigned,
                event_id = int(self.request.POST['event_id']),
                date = self.request.POST['date'],
                defaults = {
                    "user_added":self.request.user,
                    "title":title,
                })
            if created:
                return JsonResponse({'title': title, 'id': event.id, 'className': classname, 'date': self.request.POST['date']}, safe=False, status=200)
            else:
                return JsonResponse({'error': 'You may not add duplicate events.'}, status=401)

class TriageRemoveEvent(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/remove_event.html"
    model = CalendarEvent

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)

        if self.request.POST.get('arg'):
            event = get_object_or_404(CalendarEvent, id=self.request.POST['arg'])
            return render(request, self.template_name, {'event': event})
        elif self.request.POST.get('event'):
            event = get_object_or_404(CalendarEvent, id=self.request.POST['event'])
            event_id = event.id

            if (event.user == self.request.user or event.user_added == self.request.user) or (self.request.user.is_superuser):
                event.delete()

                return JsonResponse({'event': event_id}, status=200)
            else:
                return JsonResponse({'error': 'You do not have permission to remove this event'}, status=401)

        return JsonResponse({'error': 'Bad Request'}, status=403)




class TriageRoleView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/roles.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(TriageRoleView, self).get_context_data(**kwargs)
        context['triage_user'] = get_triage_users(self.request.user)
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        users = User.objects.filter(groups__in=user_groups)
        context['events'] = CalendarEvent.objects.filter(user__in=users)
        context['user_groups'] = list(user_groups.values_list("name", flat=True))
        return context

    def get(self, request, *args, **kwargs):
        if 'assign' in request.GET:
            if int(request.GET['assign']) == 0:
                users = User.objects.all()
                for u in users:
                    u.usersettings.triage = False
                    u.usersettings.save()
                messages.success(
                    self.request,
                    _("Successfully unassigned triage user."))
            else:
                user = get_object_or_404(User, id=request.GET['assign'])
                user.usersettings.triage = True
                user.usersettings.save()

                messages.success(
                    self.request,
                    _("Successfully changed triage user."))

        return super().get(request, *args, **kwargs)


class VinceEncryptandSend(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/encrypt.html"

    def test_func(self):
        ticket = get_object_or_404(Ticket, id=self.kwargs['pk'])
        return is_in_group_vincetrack(self.request.user) and has_queue_write_access(self.request.user, ticket.queue)

    def get_context_data(self, **kwargs):
        context = super(VinceEncryptandSend, self).get_context_data(**kwargs)
        context['emails'] = AdminPGPEmail.objects.filter(active=True)
        context['ticket'] = get_object_or_404(CaseRequest, id=self.kwargs['pk'])
        context['action'] = reverse("vince:encrypt", args=[self.kwargs['pk']])
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        ticket = get_object_or_404(CaseRequest, id=self.kwargs['pk'])
        emails = AdminPGPEmail.objects.filter(active=True)
        report_template = get_template('vince/email-fwd.txt')
        for email in emails:
            logger.debug("sending to %s" % email)
            attachment = None
            if ticket.user_file:
                artifact = TicketArtifact.objects.filter(ticket__id=ticket.id, title=ticket.user_file.name).first()
                if artifact:
                    attachment = ArtifactAttachment.objects.filter(artifact=artifact).first()
                    if attachment:
                        attachment = attachment.attachment
            rv = send_encrypted_mail(email, ticket.vrf_subject, report_template.render(context=model_to_dict(ticket)), attachment)
            if rv:
                # Error occurred
                messages.error(
                    self.request,
                    rv)
                return redirect("vince:cr", self.kwargs['pk'])
        messages.success(
            self.request,
            _("The email was successfully sent."))

        fup = FollowUp(ticket=ticket,
                       title=f"Successfully forwarded email to {email.email}",
                       user=self.request.user)
        fup.save()
        return redirect("vince:cr", self.kwargs['pk'])

class VinceTagManagerView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/tag_manager.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get(self, request, *args, **kwargs):
        if check_misconfiguration(self.request.user):
            return redirect("vince:misconfigured")
        return super().get(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super(VinceTagManagerView, self).get_context_data(**kwargs)
        context['tag_types'] = dict(TagManager.TAG_TYPE_CHOICES)
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if len(user_groups) > 1:
            if self.kwargs.get('pk'):
                context['team'] = self.request.user.groups.get(id=self.kwargs.get('pk')).name
                context['other_teams'] = user_groups.exclude(id=self.kwargs.get('pk'))
                user_groups = self.request.user.groups.filter(id=self.kwargs.get('pk'))
            else:
                #this user is in multiple teams  
                context['team'] = user_groups[0].name
                context['other_teams'] = user_groups.exclude(id=user_groups[0].id)
                user_groups=[user_groups[0]]
            logger.debug(user_groups)
        context['tags'] = TagManager.objects.filter(Q(team__in=user_groups)|Q(team__isnull=True))
        context['group'] = user_groups[0]
        context['activity'] = context['tags'].order_by('-created')
        return context


class VinceNewTagView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/new_tag.html"
    form_class = AddNewTagForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VinceNewTagView, self).get_context_data(**kwargs)
        context['tag_type_id'] = self.kwargs['pk']
        types = dict(TagManager.TAG_TYPE_CHOICES)
        logger.debug(types)
        context['form'] = AddNewTagForm(initial={'tag_type':int(self.kwargs['pk'])})
        context['tag_type'] = types[int(self.kwargs['pk'])]
        return context
    
    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        #make sure tag doesn't already exist
        form = AddNewTagForm(self.request.POST)
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        if len(user_groups) > 1:
            if self.kwargs.get('group'):
                user_groups = self.request.user.groups.filter(id=self.kwargs.get('group'))
            else:
                user_groups=[user_groups[0]]
            logger.debug(user_groups)

        if self.request.POST.get('id'):
            tag = get_object_or_404(TagManager, id=self.request.POST.get('id'))
            if self.request.POST.get('remove'):
                if tag.team != user_groups[0]:
                    messages.error(self.request,
                                   "You are not permitted to remove another team's tags")
                    return redirect("vince:tags")
                if tag.team == None and not self.request.user.is_superuser:
                    messages.error(self.request,
                                   "You are not permitted to remove a global tag")
                    return redirect("vince:tags")
                    
                tag.delete()
            elif self.request.POST.get('edit'):
                context = {'tag_type_id':self.kwargs['pk']}
                initial = {}
                initial['tag'] = tag.tag
                initial['description'] = tag.description
                initial['tag_type'] = tag.tag_type
                form = AddNewTagForm(initial=initial)
                context['form'] = form
                return render(request, self.template_name, context)
        else:
            existing = TagManager.objects.filter(tag = self.request.POST['tag'].lower(), tag_type = self.kwargs['pk'], team__in=user_groups).first()
            if form.is_valid():
                if existing:
                    existing.tag = self.request.POST.get('tag').lower()
                    existing.description = self.request.POST.get('description')
                    existing.alert_on_add = self.request.POST.get('alert_on_add', False)
                    existing.save()
                    return redirect("vince:tags")
                else:
                    t = form.save()
                    t.user = self.request.user
                    t.team = user_groups[0]
                    t.save()
            else:
                logger.debug(form.errors)
            
        return redirect("vince:tags")
        

class VinceTeamsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/teams.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VinceTeamsView, self).get_context_data(**kwargs)
        context['teams'] = Group.objects.exclude(groupsettings__contact__isnull=True)
        context['my_teams'] = self.request.user.groups.exclude(groupsettings__contact__isnull=True).values_list('id', flat=True)
        if context['my_teams']:
            context['my_team'] = context['my_teams'][0]
        return context

class VinceTeamSettingsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/teamsettings.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and is_my_team(self.request.user, self.kwargs['pk'])

    def get_context_data(self, **kwargs):
        context = super(VinceTeamSettingsView, self).get_context_data(**kwargs)
        context['team'] = get_object_or_404(Group, id=self.kwargs['pk'])
        initial = {}
        try:
            initial['email_phone'] = get_public_phone(context['team'].groupsettings.contact)
            initial['email_email'] = get_public_email(context['team'].groupsettings.contact)
        except:
            logger.debug("this group does not have groupsettings")
            raise Http404
        
        if context['team'].groupsettings.vulnote_template:
            initial['vulnote_template'] = context['team'].groupsettings.vulnote_template
        else:
            initial['vulnote_template'] = VULNOTE_TEMPLATE

        if context['team'].groupsettings.team_signature:
            initial['team_signature'] = context['team'].groupsettings.team_signature
        else:
            initial['team_signature'] = settings.DEFAULT_EMAIL_SIGNATURE
        initial['outgoing_email'] = context['team'].groupsettings.team_email or settings.DEFAULT_REPLY_EMAIL
        initial['disclosure_link'] = context['team'].groupsettings.disclosure_link
        initial['cna_email'] = context['team'].groupsettings.cna_email
        context['form'] = TeamSettingsForm(initial=initial)
        context['activity'] = Action.objects.filter(comment="Team Settings Change", user__groups__in=[context['team']]).order_by('-date')[:20]
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        team = get_object_or_404(Group, id=self.kwargs['pk'])

        if (self.request.POST['vulnote_template'] != team.groupsettings.vulnote_template):
            team.groupsettings.vulnote_template = self.request.POST['vulnote_template']
            #create Action
            action = Action(title=f"{self.request.user.usersettings.preferred_username} edited {team.name} team's vul note template",
                            user=self.request.user,
                            comment="Team Settings Change")
            action.save()

        if (self.request.POST['team_signature'] != team.groupsettings.team_signature):
            team.groupsettings.team_signature = self.request.POST['team_signature']
            action = Action(title=f"{self.request.user.usersettings.preferred_username} edited {team.name} team's email signature",
                            user=self.request.user,
                            comment="Team Settings Change")
            action.save()

        if (self.request.POST['disclosure_link'] != team.groupsettings.disclosure_link):
            team.groupsettings.disclosure_link = self.request.POST['disclosure_link']
            action = Action(title=f"{self.request.user.usersettings.preferred_username} edited {team.name} team's disclosure guidance link",
                            user=self.request.user,
                            comment="Team Settings Change")
            action.save()

        if (self.request.POST['cna_email'] != team.groupsettings.cna_email):
            action = Action(title=f"{self.request.user.usersettings.preferred_username} changed {team.name} team's CNA email address from {team.groupsettings.cna_email} to {self.request.POST['cna_email']}",
                            user=self.request.user,
                            comment="Team Settings Change")
            action.save()
            team.groupsettings.cna_email = self.request.POST['cna_email']

        team.groupsettings.save()
        
        messages.success(
            self.request,
            _('Your changes were successfully saved.'))

        return redirect("vince:teamsettings", self.kwargs['pk'])
    
class VinceUserAdminView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/user_admin.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VinceUserAdminView, self).get_context_data(**kwargs)
        context['activity'] = CognitoUserAction.objects.all().order_by('-date')[:20]
        return context

class VinceContactReportsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/contact_report.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VinceContactReportsView, self).get_context_data(**kwargs)
        if self.kwargs.get('type'):
            t = int(self.kwargs.get('type'))
            if t == 1:
                #list of contacts that have users
                group_user = [group.groupcontact.contact.vendor_id for group in Group.objects.using('vincecomm').exclude(groupcontact__isnull=True) if len(group.user_set.all()) > 0]
                
                #gc = Group.objects.using('vincecomm').exclude(groupcontact__isnull=True).values_list('groupcontact__contact', flat=True)
                #vc_contacts = list(VinceCommContact.objects.exclude(id__in=gc).values_list('vendor_id', flat=True))
                vcgroupadmins = GroupAdmin.objects.all().values_list('contact', flat=True)
                context['results'] = Contact.objects.filter(active=True, id__in=group_user).exclude(id__in=vcgroupadmins)
            elif t == 2:
                group_user = [group.groupcontact.contact.vendor_id for group in Group.objects.using('vincecomm').exclude(groupcontact__isnull=True) if len(group.user_set.all()) > 0]
                context['results'] = Contact.objects.filter(active=True).exclude(id__in=group_user)
            elif t==3:
                context['results'] = Contact.objects.filter(active=False)
            elif t==4:
                context['results'] = User.objects.using('vincecomm').filter(vinceprofile__multifactor=False, is_active=True)
            elif t== 5:
                # contacts with EMAIL type emails also associated with a user
                all_users = list(User.objects.using('vincecomm').filter(is_active=True).values_list('email', flat=True))
                emails = EmailContact.objects.filter(email__in=all_users, email_function__in=['EMAIL', 'REPLYTO']).values_list('contact__id', flat=True)
                context['results'] = Contact.objects.filter(active=True, id__in=emails)
        return context


class CreateNewVinceUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/create_user.html"
    form_class = CreateNewVinceUser

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser

    def get_success_url(self):
        return reverse_lazy('vince:useradmin')

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        form = CreateNewVinceUser(self.request.POST)
        if form.is_valid():
            if form.cleaned_data["password1"] != form.cleaned_data["password2"]:
                form._errors.setdefault("password2", ErrorList([
                    u"Passwords did not match"
                ]))
                return super().form_invalid(form)

            #Check users
            old_user = User.objects.using('vincecomm').filter(email=form.cleaned_data['email']).first()

            response, error = create_new_user(request, old_user)
            if response == None:
                if old_user:
                    messages.error(
                        self.request,
                        _(f'Error creating user: {error}. This user may already exist.'))
                    form._errors.setdefault("email", ErrorList([
                        u"Check valid email address"
                    ]))
                else:
                    messages.error(
                        self.request,
                        _(f'Error creating user. {error}'))

                return super().form_invalid(form)

            if response.get('User'):
                if self.request.POST.get('send_email'):
                    messages.success(
                        self.request,
                        _('The user was successfully created and notified.'))
                else:
                    messages.success(
                        self.request,
                        _('The user was successfully created.  Please inform them of their temporary password.'))

                useraction = CognitoUserAction(title=f"created new user",
                                               user=self.request.user,
                                               email=form.cleaned_data['email'])
                useraction.save()

                return super(CreateNewVinceUserView, self).form_valid(form)

        else:
            return super().form_invalid(form)

class EmailFilterResults(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    template_name = 'vince/emailresults.html'
    paginate_by = 50
    model = VinceEmail
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and self.request.user.is_staff

    def get_context_data(self, **kwargs):
        context = super(EmailResultsView, self).get_context_data(**kwargs)
        context['emailpage']=1
        return context

    def get_queryset(self):
        return VinceEmail.objects.all().order_by('-created')

    def post(self, request, *args, **kwargs):
        logger.debug(f"EmailFilterResults Post: {self.request.POST}")

        res = VinceEmail.objects.all().order_by('-created').distinct()

        page = self.request.POST.get('page', 1)
        if 'method' in self.request.POST:
            statuslist = self.request.POST.getlist('method')
            res = res.filter(email_type__in=statuslist)

        if 'user' in self.request.POST:
            ownerlist = self.request.POST.getlist('user')
            res = res.filter(user__id__in=ownerlist)

        if 'datestart' in self.request.POST:
            # add a day to dateend since it translates to 0AM
            enddate = DateTimeField().clean(self.request.POST['dateend']) + timedelta(days=1)
            if self.request.POST['datestart']:
                res = res.filter(created__range=(DateTimeField().clean(self.request.POST['datestart']),
                                                 enddate))
            elif 'dateend' in self.request.POST:
                if self.request.POST['dateend']:
                    res = res.filter(created__range=(DateTimeField().clean('1970-01-01'),
                                                     enddate))

        if 'wordSearch' in self.request.POST:
            if self.request.POST['wordSearch']:
                wordSearch = process_query(self.request.POST['wordSearch'])

                emails = VendorNotificationEmail.objects.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[wordSearch]).values_list('id', flat=True)
                if emails:
                    res = res.filter(Q(notification__id__in=emails)| Q(pgp_key_id__icontains=self.request.POST['wordSearch']) | Q(to__icontains=self.request.POST['wordSearch']))
                else:
                    res = res.filter(Q(pgp_key_id__icontains=self.request.POST['wordSearch']) | Q(to__icontains=self.request.POST['wordSearch']))

        paginator = Paginator(res, 50)

        return render(request, self.template_name, {'object_list': paginator.page(page), 'total': res.count() })


class EmailFilterView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/emails.html"
    form_class = EmailFilterForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and self.request.user.is_staff

    def get_context_data(self, **kwargs):
        context = super(EmailFilterView, self).get_context_data(**kwargs)
        context['emailpage'] = 1
        date_from = self.request.GET.get('date_from')
        initial = {}
        if date_from:
            initial['datestart'] = DateField().clean(date_from)
        date_to = self.request.GET.get('date_to')
        if date_to:
            initial['dateend'] = DateField().clean(date_to)
        if self.request.GET.get('user'):
            initial['user'] = int(self.request.GET.get('user'))
        if self.request.GET.get('method'):
            initial['method'] = int(self.request.GET.get('method'))

        form = EmailFilterForm(initial=initial)

        assignable_users = User.objects.filter(is_active=True, groups__name='vince').order_by(User.USERNAME_FIELD)

        form.fields['user'].choices = [(u.id, u.usersettings.vince_username) for u in assignable_users]

        context['form'] = form
        return context


class SendEmailAll(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/email_all.html"
    form_class = NewEmailAll
    
    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser

    def form_valid(self, form):
        logger.debug(self.request.POST)
        ticket = form.save(self.request.user)
        messages.success(
	    self.request,
            _("Your email has been sent."))
        return redirect("vince:email")

        
class CreateNewEmailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/new_email.html"
    form_class = NewVinceEmail

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and self.request.user.is_staff

    def form_valid(self, form, pgpkeys):

        sendmail = []
        emails = form.cleaned_data['to'].split(',')

        if form.cleaned_data['email_type'] == 3:
            if len(emails)>1:
                #Error occurred
                messages.error(
                    self.request,
                    f"VINCE only supports 1 email address per SMIME Certificate")
                return redirect('vince:newemail')
            if not(form.cleaned_data['new_certificate']) and not(form.cleaned_data['certificate']):
                logger.debug(form.cleaned_data)
                messages.error(self.request,
                               f"A certificate is required for SMIME Encryption")
                return super().form_invalid(form)
            if form.cleaned_data['certificate']:
                cert = form.cleaned_data['certificate']
                if cert.email != form.cleaned_data['to']:
                    messages.error(self.request,
                                   f"The email associated with this certificate {cert.email} does not match To: {form.cleaned_data['to']}")
                    return super().form_invalid(form)

        if form.cleaned_data['email_type'] == 2:
            # do pgp setup first in case there is a problem
            if len(emails) > 1:
                for email in emails:
                    email = email.strip()
                    logger.debug(f"looking up pgp key for {email} in {pgpkeys}")
                    #get pgp key for this email:
                    pgp_key_data = None
                    if pgpkeys:
                        pgp_key_data = ContactPgP.objects.filter(pgp_key_id__in=pgpkeys, pgp_email__iexact=email)
                    elif not(form.cleaned_data['pgp_key']):
                        #no pgp keys selected, no pgp key data provided - try to look it up
                        pgp_key_data = ContactPgP.objects.filter(pgp_email=email)


                    if pgp_key_data:
                        if len(pgp_key_data) > 1:
                            #Error occurred
                            messages.error(
                                self.request,
                                f"There are multiple PGP keys for { email }.  Please review and add a pgp key.")
                            return redirect('vince:newemail')
                        else:
                            pgp_key_data = pgp_key_data.first()
                            pgp_dict = {'pgp_key_data': pgp_key_data.pgp_key_data}
                            pgp_dict = extract_pgp_info(pgp_dict)
                            if pgp_dict == None:
                                messages.error(
                                    self.request,
                                    f"There was an error parsing the PGP Key for { email }")
                                return redirect('vince:newemail')
                            sendmail.append({'email': email, 'pgp_key_data':pgp_key_data.pgp_key_data, 'pgp_key_id':pgp_key_data.pgp_key_id})
                    else:
                        if not(pgpkeys) and (form.cleaned_data['pgp_key']):
                            #use the key provided and send to all emails listed
                            pgp_dict = {'pgp_key_data': form.cleaned_data['pgp_key']}
                            pgp_dict = extract_pgp_info(pgp_dict)
                            if pgp_dict == None:
                                messages.error(
                                    self.request,
                                    "There was an error parsing the PGP Key")
                                return redirect('vince:newemail')
                            sendmail.append({'email': form.cleaned_data['to'], 'pgp_key_data': form.cleaned_data['pgp_key'], 'pgp_key_id': pgp_dict['pgp_key_id']})
                            #send the one email to everyone, don't send multiple emails
                            break

                        else:
                            #Error occurred
                            messages.error(
                                self.request,
                                f"No PGP Key for { email }.  Please add or select a valid PGP key for this contact")
                            return redirect('vince:newemail')
            else:
                pgp_dict = {'pgp_key_data': form.cleaned_data['pgp_key']}
                pgp_dict = extract_pgp_info(pgp_dict)
                if pgp_dict == None:
                    messages.error(
                        self.request,
                        "There was an error parsing the PGP Key")
                    return redirect('vince:newemail')
                sendmail.append({'email': emails[0], 'pgp_key_data': form.cleaned_data['pgp_key'], 'pgp_key_id': pgp_dict['pgp_key_id']})

        notification = VendorNotificationEmail(subject=form.cleaned_data['subject'],
                                               email_body = form.cleaned_data['email_body'])
        notification.save()

        subject = form.cleaned_data['subject']
        tkt = None
        #Does subject already contain ticket id?
        queues = list(TicketQueue.objects.all().values_list('slug', flat=True))
        #General queue is the only one where slug != title
        queues.append("General")
        rq= '|'.join(queues)
        rq = "(?i)(" + rq + ")-(\d+)"
        m = re.search(rq, form.cleaned_data['subject'])
        if m:
            q = m.group(1)
            tid = m.group(2)
            #lookup Ticket
            tkt = Ticket.objects.filter(id=tid).first()
            # subject already contains ticket id - this is probably a reply

        #this is a regular email
        if form.cleaned_data['ticket']:
            form_tkt = form.cleaned_data['ticket']
            # subject contains SOME ticket id - check if it's the right one
            if tkt:
                rq = f"{form_tkt.queue.slug}|{form_tkt.queue.title}"                                  
                rq = "(?i)(" + rq + ")-(\d+)"
                m = re.search(rq, form.cleaned_data['subject'])
                if not m:                                                                                                         
                    # subject doesn't contain THIS ticket id
                    tkt = form.cleaned_data['ticket']
                    subject = f"[{tkt.queue.slug}-{tkt.id}] {form.cleaned_data['subject']}"                
            else:
                tkt = form.cleaned_data['ticket']
                subject = f"[{tkt.queue.slug}-{tkt.id}] {form.cleaned_data['subject']}"                

        elif tkt==None:
            if form.cleaned_data['case']:
                queue = get_user_case_queue(self.request.user)
            else:
                queue = get_user_gen_queue(self.request.user)
            title = f"New Email to {form.cleaned_data['to']}"
            if len(title) > 200:
                title = title[:195] + ".."
            tkt = Ticket(title = title,
                         created = timezone.now(),
                         status = Ticket.CLOSED_STATUS,
                         queue = queue,
                         description = form.cleaned_data['email_body'],
                         submitter_email = self.request.user.email,
                         assigned_to = self.request.user)
            if form.cleaned_data['case']:
                tkt.case=form.cleaned_data['case']

            tkt.save()
            subject = f"[{tkt.queue.slug}-{tkt.id}] {form.cleaned_data['subject']}"

        # add contacts to emails
        for email in emails:
            email = email.strip()
            contact = EmailContact.objects.filter(email__iexact=email)
            for c in contact:
                tktc = TicketContact.objects.update_or_create(contact=c.contact,
                                                      ticket=tkt)


        vince_email = form.save(commit=False)
        vince_email.ticket = tkt
        vince_email.notification = notification
        vince_email.user = self.request.user
        error = False
        if form.cleaned_data['email_type'] == 1:
            send_regular_email_notification(emails, subject, form.cleaned_data['email_body'])
            title = f"New unencrypted email sent from VINCE to {form.cleaned_data['to']}"
            comment = form.cleaned_data['email_body']
            if len(title) > 300:
                title = title[:295] + ".."
                comment = f"To: {form.cleaned_data['to']}\n{comment}"
            followup = FollowUp(ticket=tkt,
                                title=title,
                                user=self.request.user,
                                comment=comment)
            followup.save()

        elif form.cleaned_data['email_type'] == 2:
            #this is pgp
            logger.debug(sendmail)
            pgp_key_list_str = ""
            # NOW SEND THE MAIL
            for mail in sendmail:
                # this will get the key id which we can save in the vinceemail model.
                email = AdminPGPEmail(email=mail['email'],
                                      pgp_key_data=mail['pgp_key_data'])
                rv = send_encrypted_mail(email, subject, form.cleaned_data['email_body'])
                if rv:
                    # Error occurred
                    messages.error(
                        self.request,
                        f"Error sending mail to {mail['email']}: {rv}")
                    error = True
                else:
                    messages.success(
                        self.request,
                        f"Successfully sent mail to {mail['email']}")
                    title=f"New PGP Encrypted Email sent from VINCE to {email.email} using KEY ID: {mail['pgp_key_id']}"
                    comment = form.cleaned_data['email_body']
                    if len(title) > 300:
                        title = title[:295] + ".."
                        comment = f"To: {form.cleaned_data['to']}\n{comment}"
                    followup = FollowUp(ticket=tkt,
                                        title=title,
                                        user=self.request.user,
                                        comment=comment)
                    followup.save()

                    pgp_key_list_str = pgp_key_list_str + mail['pgp_key_id'] + ","
            vince_email.pgp_key_id = pgp_key_list_str

        elif form.cleaned_data['email_type'] == 3:
            if form.cleaned_data['new_certificate']:
                cert, created = VinceSMIMECertificate.objects.update_or_create(email = form.cleaned_data['to'],
                                                                               defaults = {
                                                                                   'certificate': form.cleaned_data['new_certificate']})
            else:
                cert = form.cleaned_data['certificate']
            vince_email.certificate = cert
            rv = None
            try:
                rv = send_smime_encrypted_mail(cert, subject, self.request.POST.get('email_body'))
            except:
                logger.debug(traceback.format_exc())
                followup = FollowUp(ticket=tkt,
                                    title=f"Email not sent.  Error occurred during encryption.",
                                    user=self.request.user,
                                    comment=traceback.format_exc())
                followup.save()
                error = True
                messages.error(
                    self.request,
                    "Error occurred while trying to encrypt the email. Is certificate in .pem format?")
            if rv:
                followup = FollowUp(ticket=tkt,
                                    title=f"Email not sent.  Error occurred during encryption.",
                                    user=self.request.user,
                                    comment=rv)
                followup.save()
                error = True
                # Error occurred
                messages.error(
		    self.request,
                    rv)

            if not(error):
                followup = FollowUp(ticket=tkt,
                                    title=f"New SMIME Encrypted Email sent from VINCE to {cert.email}",
                                    user=self.request.user,
                                    comment=form.cleaned_data['email_body'])
                followup.save()

        if not(error):
            messages.success(
                self.request,
                f"Success!  Your email was sent.  Refer to this ticket.",
            )

        vince_email.save()
        return HttpResponseRedirect(tkt.get_absolute_url())

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        form = NewVinceEmail(self.request.POST, request.FILES)
        templates = EmailTemplate.objects.filter(locale="en", body_only=True)
        form.fields['email_template'].choices = [('', '--------')] + [(q.id, q.template_name) for q in templates]
        pgp_keys = self.request.POST.getlist("pgp_key_id")
        if form.is_valid():
            return self.form_valid(form, pgp_keys)
        else:
            return super().form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(CreateNewEmailView, self).get_context_data(**kwargs)
        if self.request.POST:
            form = NewVinceEmail(self.request.POST)
        else:
            initial = {}
            if self.kwargs.get('reply'):
                # get followup
                fup = get_object_or_404(FollowUp, id=self.kwargs.get('reply'))
                if fup.comment:
                    # this is a ticket comment
                    comments = fup.comment.splitlines()
                    match = re.search("New [E|e]mail( received)? from \"?(?P<from_email>[^\"]+)\"? \"(?P<subject>[^\"]+)\"( to (?P<to_email>.+?(?=CERT)))?", fup.title)
                    if match:
                        email_from = match.group('from_email')
                        subject = match.group('subject')
                        to_email = match.group('to_email')
                    else:
                        email_from = ""
                        subject= "Re:"
                        to_email = ""
                else:
                    comments = fup.ticket.description.splitlines()
                    email_from = fup.ticket.submitter_email
                    match = re.search("New [E|e]mail( received)?(?P<from_email> from ([ \x20-\x7E]+))? to (?P<to_email>.+?(?=CERT))", fup.title)
                    if match:
                        to_email = match.group('to_email')
                    else:
                        to_email = ""
                    subject = fup.ticket.title

                if subject.startswith('Re:') or subject.startswith('RE:'):
                    new_subject = subject
                else:
                    new_subject = f"Re: {subject}"

                #don't do this because it will be prepended when sent
                #Does subject already contain ticket id?
                #rq = f"{fup.ticket.queue.slug}|{fup.ticket.queue.title}"
                #rq = "(?i)(" + rq + ")-(\d+)"
                #m = re.search(rq, new_subject)
                #if not m:
                    # add ticket id
                    #new_subject = f"{new_subject} [{fup.ticket.queue.slug}-{fup.ticket.id}]"

                replybody = [' ',
                             ' ',
                             ' ',
                             '-----------------------------------',
                             f"From: {email_from}",
                             f"Date: {fup.date.strftime('%A, %B %d, %Y at %H:%M')}",
                             f"To: {to_email}",
                             f"Subject: {subject}"]

                for c in comments:
                    replybody.append('> '+c)

                initial['email_body'] = "\n".join(replybody)
                initial['subject'] = new_subject
                initial['ticket'] = fup.ticket.id
                if email_from:
                    name_only, email_from_only = email.utils.parseaddr(email_from)
                    initial['to'] = email_from_only

            if self.kwargs.get('user'):
                vc_user = User.objects.using('vincecomm').filter(id=self.kwargs['pk']).first()
                if vc_user == None:
                    raise Http404
                initial = {'to': vc_user.email}
            elif self.kwargs.get('admins'):
                emails = [x.email.email for x in VinceCommGroupAdmin.objects.filter(contact__vendor_id=self.kwargs['pk'])]    
                initial = {'to': ",".join(emails)} 
            elif self.kwargs.get('tkt'):
                tkt = get_object_or_404(Ticket, id=self.kwargs['tkt'])
                emails = AdminPGPEmail.objects.filter(active=True).first()
                if emails:
                    initial = {'to': emails.email, 'pgp_key': emails.pgp_key_data, 'ticket': self.kwargs['tkt'], 'email_body': tkt.description, 'subject': 'New VINCE Report', 'email_type': 2}
                    messages.warning(
                        self.request,
                        "Check email details before sending. Emails and Key copied from current Admin encrypt-and-send PGP list."
                    )
                else:
                    initial = {'ticket': self.kwargs['tkt'], 'email_body': tkt.description, 'subject': 'New VINCE Report', 'email_type': 2}
                    messages.warning(
                        self.request,
                        "Encrypt and Send PGP list not configured. Please add emails and PGP keys in admin panel or add manually below.")
            elif self.kwargs.get('pk'):
                contact = get_object_or_404(Contact, id=self.kwargs['pk'])
                initial = {'contact': contact.vendor_name, 'to': ",".join(contact.get_emails())}
            form = NewVinceEmail(initial=initial)
            templates = EmailTemplate.objects.filter(locale="en", body_only=True)
            form.fields['email_template'].choices = [('', '--------')] + [(q.id, q.template_name) for q in templates]
        context['form'] = form
        context['emailpage'] = 1
        return context


def cvss_translator(value, field):

    if value == "N":
        if field == "AV":
            return "NETWORK"
        return "NONE"
    elif value == "L":
        if field == "L":
            return "LOCAL"
        return "LOW"
    elif value == "H":
        return "HIGH"
    elif value == "A":
        return "ADJACENT"
    elif value == "P":
        return "PHYSICAL"
    elif value == "R":
        return "REQUIRED"
    elif value == "S":
        return "SCOPE"
    elif value == "C":
        return "CHANGED"
    elif value == "U":
        return "UNCHANGED"
    
        


@login_required(login_url="vince:login")
@user_passes_test(is_in_group_vincetrack, login_url='vince:login')
def DownloadCVEJson(request, pk):
    if is_in_group_vincetrack(request.user):
        cve = CVEAllocation.objects.filter(id=pk).first()
        cvss = VulCVSS.objects.filter(vul = cve.vul).first()
        
        cve_json = {}
        cve_json["data_type"] ="CVE"
        cve_json["data_format"] = "MITRE"
        cve_json["data_version"] = "4.0"
        cve_json["CVE_data_meta"] = {"ID":cve.cve_name,
                                     "ASSIGNER":cve.assigner,
                                     "DATE_PUBLIC": cve.date_public.strftime("%Y%m%dT%H:%M:%S.%fZ"),
                                     "TITLE":cve.title if cve.title else "",
                                     "AKA": "",
                                     "STATE":"PUBLIC"}
        cve_json["source"] = {'discovery': cve.source if cve.source else "UNKNOWN",
                              'defect': [],
                              'advisory':""}
        products = cve.cveaffectedproduct_set.all()
        vendors = []
        for product in products:
            vendor = {}
            vendor["vendor_name"] = product.organization
            vendor["product"] = {"product_data":[{"product_name": product.name,
                                                  "version": {"version_data":[
                                                      {"version_name": product.version_name if product.version_name else "",
                                                       "version_affected":product.version_affected if product.version_affected else "",
                                                       "version_value":product.version_value,
                                                       "platform":""
                                                       }]}}]}
            vendors.append(vendor)
        cve_json["affects"] = {"vendor": {"vendor_data": vendors}}
        problems = []
        if cve.cwe:
            for cwe in json.loads(cve.cwe):
                problems.append({"description": [{"lang": "eng", "value": cwe }]})
        cve_json["problemtype"] = {"problemtype_data": problems}
        cve_json["description"] = {"description_data":[{"lang":"eng", "value": cve.vul.description}]}
        references=[]
        if cve.references:
            for ref in json.loads(cve.references):
                if type(ref) is dict:
                    references.append({"refsource":ref["refsource"], "url": ref["url"], "name": ""})
                else:
                    references.append({"refsource":"MISC", "url": ref, "name": ""})

        cve_json["references"] = {"reference_data":references}

        if cvss:
            if cvss.score:
                cvss_score = float(cvss.score)
            else:
                cvss_score = 0
            cve_json["impact"] = {"cvss":{
                              "version": "3.1",
                              "attackVector":cvss_translator(cvss.AV, "AV"),
                              "attackComplexity":cvss_translator(cvss.AC, "AC"),
                              "privilegesRequired":cvss_translator(cvss.PR, "PR"),
                              "userInteraction":cvss_translator(cvss.UI, "UI"),
                              "scope":cvss_translator(cvss.S, "S"),
                              "confidentialityImpact": cvss_translator(cvss.C, "C"),
                              "integrityImpact":cvss_translator(cvss.I, "I"),
                              "availabilityImpact":cvss_translator(cvss.A, "A"),
                              "vectorString":cvss.vector,
                              "baseScore":cvss_score,
                              "baseSeverity":cvss.severity.upper()
                              }}
                              
        
        was=[]
        if cve.work_around:
            for wa in cve.work_around:
                was.append({'lang': "eng", "value": wa})
        cve_json["work_around"] = was
        if cve.resolution:
            cve_json["solution"] = [{"lang":"eng", "value": cve.resolution}]
        else:
            cve_json["solution"] = []
        if cve.credit:
            cve_json["credit"] = [{"lang":"eng", "value":cve.credit}]
        else:
            cve_json["credit"] = []

        cve_json = json.dumps(cve_json, indent=4)

        json_file = ContentFile(cve_json)
        json_file.name = cve.cve_name + ".json"
        mime_type = 'application/json'
        response = HttpResponse(json_file, content_type = mime_type)
        response['Content-Disposition'] = 'attachment; filename=' + json_file.name
        response["Content-type"] = "application/json"
        response["Cache-Control"] = "must-revalidate"
        response["Pragma"] = "must-revalidate"
        return response

class ReadEmailAdminView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/process_email.html"
    form_class = EmailImportForm

    def test_func(self):
        return (is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser)

    def form_valid(self, form):
        obj_key = form.cleaned_data['email_key']
        try:
            call_command('process_mail', f'--key={obj_key}', f'--bucket={settings.EMAIL_BUCKET}')
            messages.success(
                self.request,
                "Email Processed"
            )
        except:
            logger.warning(traceback.format_exc())
            messages.error(self.request,
                           "Problem with processing email")

        return redirect("vince:process_email")

class UserReportView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/user_reports.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and self.request.user.is_staff

    def get_context_data(self, **kwargs):
        context = super(UserReportView, self).get_context_data(**kwargs)
        get_user = self.request.GET.get('user', self.request.user.id)
        context['select_user'] = get_object_or_404(User, id=get_user)
        context['selectable_users'] = User.objects.filter(is_active=True, groups__name='vince').exclude(id=get_user).order_by(User.USERNAME_FIELD)
        year = int(self.request.GET.get('year', datetime.now().year))
        month = int(self.request.GET.get('month', datetime.now().month))
        if month == 0:
            month = 12
            year = year - 1
        elif month > 12:
            month = 1
            year = year + 1
        context['year'] = year
        context['monthstr'] = date(year, month, 1).strftime('%B')
        context['month'] = month
        tickets_in_queues = Ticket.objects.filter(assigned_to=context['select_user'])
        context['basic_ticket_stats'] = calc_basic_ticket_stats(tickets_in_queues)
        context['breakdown'] = tickets_in_queues.filter(status__in=[Ticket.CLOSED_STATUS, Ticket.OPEN_STATUS, Ticket.IN_PROGRESS_STATUS, Ticket.REOPENED_STATUS]).values('status').order_by('status').annotate(count=Count('status'))
        my_cases = CaseAssignment.objects.filter(assigned=context['select_user']).distinct().values_list('case')
        context['newnotes'] = VulnerabilityCase.objects.filter(id__in=my_cases, vulnote__date_published__year=year, vulnote__date_published__month=month).exclude(vulnote__date_published__isnull=True)
        context['updated'] = VulnerabilityCase.objects.filter(id__in=my_cases, vulnote__date_last_published__year=year, vulnote__date_last_published__month=month).exclude(vulnote__date_published__isnull=True)
        context['emails'] = VinceEmail.objects.filter(user=context['select_user'], created__year=year, created__month=month)
        new_cases = VulnerabilityCase.objects.filter(created__year=year, created__month=month, id__in=my_cases).order_by('created')
        date_month = date(year, month, 1)
        active_cases = VulnerabilityCase.objects.filter(status = VulnerabilityCase.ACTIVE_STATUS, created__lt=date_month, id__in=my_cases)
        deactive_cases = CaseAction.objects.filter(title__icontains="changed status of case from Active to Inactive", date__month=month, date__year=year, id__in=my_cases).select_related('case').order_by('case').distinct('case')
        to_active_cases = CaseAction.objects.filter(id__in=my_cases, title__icontains="changed status of case from Inactive to Active", date__month=month, date__year=year).select_related('case').order_by('case').distinct('case')
        context.update({'case_stats': {'new_cases':new_cases,
                                       'active_cases': active_cases,
                                       'deactive_cases': deactive_cases,
                                       'to_active_cases': to_active_cases}})
        if (month < datetime.now().month) and (year <= datetime.now().year):
            context['show_next'] = 1
        elif (year < datetime.now().year):
            context['show_next'] = 1
        context['total_tickets'] = Ticket.objects.filter(created__year=year, created__month=month, assigned_to=context['select_user']).count()
        context['ticket_stats'] = Ticket.objects.filter(created__year=year, created__month=month, assigned_to=context['select_user']).values('queue__title').order_by('queue__title').annotate(count=Count('queue__title')).order_by('-count')
        ticket_changes = TicketChange.objects.filter(followup__ticket__assigned_to=context['select_user'], followup__date__year=year, followup__date__month=month, field='Status', new_value='Closed').values_list('followup__ticket__id', flat=True)
        context['total_closed'] = Ticket.objects.filter(id__in=ticket_changes).count()
        context['closed_ticket_stats'] = Ticket.objects.filter(id__in=ticket_changes).values('close_reason').order_by('close_reason').annotate(count=Count('close_reason')).order_by('-count')
        context['new_users'] = User.objects.using('vincecomm').filter(date_joined__month=month, date_joined__year=year).count()
        context['tickets'] = tickets_in_queues.exclude(status__in=[Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS, Ticket.DUPLICATE_STATUS])
        context['ticketsjs'] = [ obj.as_dict() for obj in context['tickets']]
        return context


class CognitoSearchUser(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/user_search.html"

    def test_func(self):
        return (is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser)

    def get_context_data(self, **kwargs):
        context = super(CognitoSearchUser, self).get_context_data(**kwargs)
        context['form'] = UserSearchForm()
        return context


class CognitoGetUserDetails(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/user_details.html"
    form_class = CognitoUserProfile

    def test_func(self):
        return (is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser)

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)

        data = None

        try:
            data = get_user_details(self.request.POST['email'])
        except (Boto3Error, ClientError) as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UserNotFoundException']:
                messages.error(
                    self.request,
                    _(f"User {self.request.POST['email']} doesn't exist"))
                return render(request, 'vince/user_search.html', {'form': UserSearchForm()})

        if data:
            dicts = data['UserAttributes']
            initial = {}
            initial['first_name'] = next((item["Value"] for item in dicts if item["Name"] == "given_name"), None)
            initial['last_name'] = next((item["Value"] for item in dicts if item["Name"] == "family_name"), None)
            initial['email'] = next((item["Value"] for item in dicts if item["Name"] == "email"), None)
            initial['preferred_username'] = next((item["Value"] for item in dicts if item["Name"] == "preferred_username"), None)
            initial['title'] = next((item["Value"] for item in dicts if item["Name"] == "custom:title"), None)
            initial['org'] = next((item["Value"] for item in dicts if item["Name"] == "custom:Organization"), None)
            initial['phone_number'] = next((item["Value"] for item in dicts if item["Name"] == "phone_number"), None)

            form = CognitoUserProfile(initial=initial)
        else:
            messages.error(
                self.request,
                _(f"User {self.request.POST['email']} doesn't exist"))
            return render(request, 'vince/user_search.html', {'form': UserSearchForm()})

        return render(request, 'vince/user_details.html', {'form': form})


class CognitoChangeUserAttributes(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    login_url = "vince:login"
    template_name = "vince/user_details.html"
    form_class = CognitoUserProfile

    def test_func(self):
        return (is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser)

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)

        change_email = False
        form = CognitoUserProfile(self.request.POST)
        if form.is_valid():
            if self.request.POST.get('old_email') != self.request.POST.get('email'):
                logger.debug("User wants to change user email address")
                # check to make sure email doesn't already exist
                other_user = User.objects.using('vincecomm').filter(username=self.request.POST.get('email')).first()
                change_email = True
                if other_user:
                    messages.error(
                        self.request,
                        _(f'Error modifying user: {self.request.POST["email"]} already exists. '))
                    return render(request, 'vince/user_search.html', {'form': UserSearchForm()})

            response, error = admin_change_user_details(request, self.request.POST.get('old_email'))
            if response == None:
                messages.error(
                    self.request,
                    _(f'Error modifying user: {error}. '))
                return render(request, 'vince/user_search.html', {'form': UserSearchForm()})
            else:

                if change_email:
                    title = f"modified username/email from {self.request.POST['old_email']} to {self.request.POST['email']}"
                else :
                    title = f"modified user {self.request.POST['old_email']} screen name to {self.request.POST['preferred_username']}"

                useraction = CognitoUserAction(title=title,
                                               user=self.request.user,
                                               email=form.cleaned_data['email'])
                useraction.save()

                messages.success(
                    self.request,
                    _(f"User {self.request.POST['email']} successfully updated"))
                return render(request, 'vince/user_search.html', {'form': UserSearchForm()})
        else:
            logger.debug(form.errors)
            return super().form_invalid(form)


class ManageAutoAssignmentView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/manage_auto_assign.html"

    def test_func(self):
        return (is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser)

    def get_context_data(self, **kwargs):
        context = super(ManageAutoAssignmentView, self).get_context_data(**kwargs)
        user_groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        context['roles'] = UserRole.objects.filter(Q(group__in=user_groups)|Q(group__isnull=True))
        context['assignments'] = UserAssignmentWeight.objects.all()
        return context

class ManageRoleAddUser(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vince:login"
    template_name = "vince/role_add_user.html"

    def test_func(self):
        return (is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser)

    def get_context_data(self, **kwargs):
        context = super(ManageRoleAddUser, self).get_context_data(**kwargs)
        context['role'] = get_object_or_404(UserRole, id=self.kwargs['pk'])
        if context['role'].group:
            assignable_users = User.objects.filter(is_active=True, groups__in=[context['role'].group]).order_by(User.USERNAME_FIELD)
        else:
            assignable_users = User.objects.filter(is_active=True, groups__name='vince').order_by(User.USERNAME_FIELD)
        initial = {}
        initial['role'] = context['role']
        form = AddRoleUserForm(initial=initial)
        form.fields['user'].choices = [
            (u.id, u.usersettings.vince_username) for u in assignable_users]

        context['form'] = form
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        if self.request.POST.get('id'):
            assignment = get_object_or_404(UserAssignmentWeight, id=self.request.POST.get('id'))
            if self.request.POST.get('remove'):
                assignment.delete()
            elif self.request.POST.get('edit'):
                context = {}
                context['role'] = get_object_or_404(UserRole, id=self.kwargs['pk'])
                assignable_users = User.objects.filter(id=assignment.user.id)
                initial = {}
                initial['role'] = assignment.role
                initial['weight'] = assignment.weight
                form = AddRoleUserForm(initial=initial)
                form.fields['user'].choices = [
                    (u.id, u.usersettings.vince_username) for u in assignable_users]
                context['form'] = form
                return render(request, self.template_name, context)

        else:
            form = AddRoleUserForm(self.request.POST)
            #does it exist?
            assignment = UserAssignmentWeight.objects.filter(
                user=self.request.POST['user'],
                role=self.request.POST['role'],
            ).first()
            if assignment:
                assignment.weight = int(self.request.POST['weight'])
                assignment.effective_weight = int(self.request.POST['weight'])
                assignment.save()
            else:
                form.save()


        return redirect("vince:manage_auto_assign")



class CVEServicesDashboard(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/cveservices.html'
    login_url="vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            if self.kwargs.get('pk'):
                if is_my_team(self.request.user, self.kwargs['pk']):
                    return True
            else:
                return True
        return False

    def get_context_data(self, **kwargs):
        context = super(CVEServicesDashboard, self).get_context_data(**kwargs)
        if self.kwargs.get('pk'):
            context['my_team'] = get_object_or_404(Group, id=self.kwargs['pk'])
        else:
            context['teams'] = Group.objects.exclude(groupsettings__contact__isnull=True)
            context['my_teams'] = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            if context['my_teams']:
                context['my_team'] = context['my_teams'][0]

        context['accounts'] = CVEServicesAccount.objects.filter(team=context['my_team'])
        if context['accounts']:
            acc = context['accounts'][0]
            context['cve_service'] = acc
            cve_lib = cvelib.CveApi(acc.email, acc.org_name, acc.api_key, env=settings.CVE_SERVICES_API)
            if cve_lib.ping():
                try:
                    context['account'] = cve_lib.show_user(acc.email)
                    context['org'] = cve_lib.show_org()
                    context['quota'] = cve_lib.quota()
                    context['cve_users'] = list(cve_lib.list_users())
                except cvelib.CveApiError as e:
                    context['account_error'] = str(e)
                    context['accounts'][0].active = False
                    context['accounts'][0].save()
        else:
            context['service_down'] = 1


        
        return context

class CVEServicesDetailAccount(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = CVEServicesAccount
    login_url = "vince:login"
    template_name = "vince/cve_detail.html"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            account = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            if is_my_team(self.request.user, account.team.id):
                return True
        return False

    def get_context_data(self, **kwargs):
        context = super(CVEServicesDetailAccount, self).get_context_data(**kwargs)
        acc = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
        context['cve_service'] = acc
        cve_lib = cvelib.CveApi(acc.email, acc.org_name, acc.api_key, env=settings.CVE_SERVICES_API)
        if cve_lib.ping():
            try:
                context['account'] = cve_lib.show_user(acc.email)
                context['org'] = cve_lib.show_org()
                context['quota'] = cve_lib.quota()
                context['cve_users'] = list(cve_lib.list_users())
            except cvelib.CveApiError as e:
                context['account_error'] = str(e)
                acc.active = False
                acc.save()
        else:
            context['service_down'] = 1    
            
        return context

class CVEServicesDeleteAccount(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = CVEServicesAccount
    login_url = "vince:login"
    template_name = "vince/confirm_cve_delete.html"

    def test_func(self):
        if self.request.user.is_superuser and is_in_group_vincetrack(self.request.user):
            account = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            if is_my_team(self.request.user, account.team.id):
                return True
        return False

    def get_context_data(self, **kwargs):
        context = super(CVEServicesDeleteAccount, self).get_context_data(**kwargs)
        context['account'] = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        account = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
        if self.request.user.is_superuser:
            account.delete()
        else:
            account.active = False
            account.save()
        return redirect("vince:cve_dashboard")


class VulReserveCVEView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vince/confirm_reserve.html'
    login_url = "vince:login"
    
    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            if self.kwargs.get('pk'):
                vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
                if has_case_write_access(self.request.user, vul.case):
                    return True
            else:
                return True    
        return False
    
    def get_context_data(self, **kwargs):
        context = super(VulReserveCVEView, self).get_context_data(**kwargs)
        if self.kwargs.get('pk'):
            context['vul'] = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            cve = CVEAllocation.objects.filter(vul=context['vul'])
            context['action'] = reverse("vince:reservecve", args=[context['vul'].id])
            try:
                if cve.cvereservation:
                    context['error'] = f"A CVE has already been reserved for this vulnerability by { cve.user_reserved.usersettings.preferred_username }"
            except:
                pass
        else:
            context['action'] = reverse("vince:reservecve")    
        groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        #get available accounts associated with my teams
        if groups:
            accounts = CVEServicesAccount.objects.filter(team__in=groups, active=True)
        else:
            accounts = []

        if len(accounts) == 0:
            cvelink = reverse("vince:cve_dashboard")
            context['error'] = f"There are no available CVE Services accounts for your team. Configure account in <a href='{cvelink}'>CVE Services</a>"

        context['form'] = CVEReserveForm(initial={'count':1})
        context['form'].fields['account'].choices = [(g.id, f"{g.team.name} ({g.email})") for g in accounts]
        year = datetime.now().year
        context['form'].fields['year'].choices = [(y, y) for y in range(year, year-10, -1)]
        #context['form'].fields['year'].choices = [(datetime.now().year, datetime.now().year), (datetime.now().year-1, datetime.now().year-1), (datetime.now().year-2, datetime.now().year-2)]
        if self.kwargs.get('pk'):
            context['form'].fields['sequential'].widget=forms.HiddenInput()
            context['form'].fields['count'].widget=forms.HiddenInput()
            
                
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)

        form = CVEReserveForm(self.request.POST)
        groups = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
        #get available accounts associated with my teams
        accounts = CVEServicesAccount.objects.filter(team__in=groups, active=True)
        form.fields['account'].choices = [(g.id, f"{g.team.name} ({g.email})") for g in accounts]
        year = datetime.now().year
        form.fields['year'].choices = [(y, y) for y in range(year, year-10, -1)]

        if form.is_valid():
            if self.kwargs.get("pk"):
                request_no = 1
                random = True
                ret_link = reverse("vince:vul", args=[self.kwargs["pk"]])
            else:
                request_no = form.cleaned_data['count']
                random = form.cleaned_data['sequential']
                if random == "True":
                    random = False
                else:
                    random = True
                ret_link = reverse("vince:cvelist", args=[form.cleaned_data['account']])
                
            account = CVEServicesAccount.objects.filter(id=form.cleaned_data['account'], active=True).first()
            if account == None:
                messages.error(
                    self.request,
                    _(f"Error: No matching active CVE Services account"))
                if self.kwargs.get('pk'):
                    return redirect(ret_link)
                else:
                    return redirect("vince:cve_manage")
            



        vul=None
        cve=None
        if self.kwargs.get("pk"):

            vul = get_object_or_404(Vulnerability, id=self.kwargs['pk'])
            cve = CVEAllocation.objects.filter(vul=vul).first()
            if cve:
                reservation = CVEReservation.objects.filter(cve_info=cve).first()
                if reservation:
                    messages.error(
		        self.request,
                        _(f"Error: this vulnerability already has a CVE ID assigned {reservation.cve_id}"))
                    return redirect("vince:vul", vul.id)
            else:

                cve = CVEAllocation(vul=vul,
                                    cve_name="PLACEHOLDER",
                                    assigner=account.email,
                                    description=vul.description)
                cve.save()
        

        new_cve_ids = []
        cve_lib = cvelib.CveApi(account.email, account.org_name, account.api_key, env=settings.CVE_SERVICES_API)
        if cve_lib.ping():
            try:
                new_reserve, quota = cve_lib.reserve(request_no, random, form.cleaned_data["year"])
                for x in new_reserve["cve_ids"]:
                    cveres = CVEReservation(cve_info = cve,
                                            cve_id = x["cve_id"],
                                            account=account,
                                            user_reserved = self.request.user)
                    cveres.save()
                    #add this CVE to the reservation
                    if vul:
                        vul.cve = cveres.cve_id[4:]
                        vul.save()
                    if cve:
                        cve.cve_name = cveres.cve_id
                        cve.save()
                    new_cve_ids.append(cveres.cve_id)
                                   
                               
            except cvelib.CveApiError as e:
                    messages.error(
                        self.request,
                        _(f"Error Requesting CVE ID {e}"))
                    return redirect(ret_link)

        else:
            messages.error(
                self.request,
                _f("Error: CVE Service down. Try again later."))
            return redirect(ret_link)

        messages.success(
            self.request,
            _(f"You have successfully reserved {', '.join(new_cve_ids)}. You have {quota} remaining"))
        return redirect(ret_link)


class CVEAccountViewKey(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vince/cve_view_key.html"
    login_url = "vince:login"
    
    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            cveaccount = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            if is_my_team(self.request.user, cveaccount.team.id):
                return True
        return False

    def get_context_data(self, **kwargs):
        context = super(CVEAccountViewKey, self).get_context_data(**kwargs)

        acc = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
        context['account'] = acc
        return context
    
    
class CVEListReserved(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vince/cve_list.html"
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            cveaccount = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            if is_my_team(self.request.user, cveaccount.team.id):
                return True
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)

        year = self.request.POST.get('year')
        cve_id = self.request.POST.get('wordSearch')
        if cve_id:
            cve_id = cve_id.upper()
        if self.request.POST.get('vince'):
            #search all vince cves for this team (not just the account)
            cveaccount = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            cves = CVEReservation.objects.filter(account__team__id = cveaccount.team.id)
            if year:
                cves = cves.filter(time_reserved__year=year)
            if cve_id:
                cves = cves.filter(cve_id=cve_id)
            cves = [c.as_dict() for c in cves]
        else:
            acc = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            cve_lib = cvelib.CveApi(acc.email, acc.org_name, acc.api_key, env=settings.CVE_SERVICES_API)
            if cve_lib.ping():
                try:
                    if cve_id:
                        cves = cve_lib.show_cve(cve_id)
                        cves = [cves]
                    elif year:
                        cves = list(cve_lib.list_cves(year=year))
                    else:
                        cves = list(cve_lib.list_cves(year=datetime.now().year))
                    for x in cves:
                        #lookup cve id - was this requested via VINCE?
                        v_cve = CVEReservation.objects.filter(cve_id=x["cve_id"]).first()
                        x["cve_link"] = reverse("vince:detailedcve", args=[acc.id, x["cve_id"]])
                        if v_cve:
                            if v_cve.cve_info:
                                x["vul"] = reverse("vince:vul", args=[v_cve.cve_info.vul.id])
                                x["case"] = v_cve.cve_info.vul.case.vu_vuid
                            if v_cve.user_reserved:
                                x["user"] = v_cve.user_reserved.usersettings.preferred_username
                        else:
                            #lookup vul
                            v_cve = Vulnerability.objects.filter(cve=x["cve_id"][4:]).first()
                            if v_cve:
                                x["vul"] = reverse("vince:vul", args=[v_cve.id])
                                x["case"] = v_cve.case.vu_vuid

                except cvelib.CveApiError as e:
                    return render(request, "vince/cve_list_results.html", {'error': e})

            else:
                return render(request, "vince/cve_list_results.html", {'error': "CVE service down"})

        return render(request, "vince/cve_list_results.html", {'cves':cves, 'account':self.kwargs['pk'] })
        
    def get_context_data(self, **kwargs):
        context = super(CVEListReserved, self).get_context_data(**kwargs)

        acc = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
        context['account'] = acc
        context["my_team"] = acc.team
        context['form'] = CVEFilterForm(initial={'year': datetime.now().year})
        cve_lib = cvelib.CveApi(acc.email, acc.org_name, acc.api_key, env=settings.CVE_SERVICES_API)
        if cve_lib.ping():
            try:
                cves = list(cve_lib.list_cves(year=datetime.now().year))
            except cvelib.CveApiError as e:
                context['account_error'] = str(e)
                acc.active = False
                acc.save()
        else:
            context['service_down'] = 1

        for x in cves:
            #lookup cve id - was this requested via VINCE?
            v_cve = CVEReservation.objects.filter(cve_id=x["cve_id"]).first()
            x["cve_link"] = reverse("vince:detailedcve", args=[acc.id, x["cve_id"]])
            if v_cve:
                if v_cve.cve_info:
                    if v_cve.cve_info.vul:
                        x["vul"] = reverse("vince:vul", args=[v_cve.cve_info.vul.id])
                        x["case"] = v_cve.cve_info.vul.case.vu_vuid
                if v_cve.user_reserved:
                    x["user"] = v_cve.user_reserved.usersettings.preferred_username
            else:
                #lookup vul                                                                                                                       
                v_cve = Vulnerability.objects.filter(cve=x["cve_id"][4:]).first()
                if v_cve:
                    x["vul"] = reverse("vince:vul", args=[v_cve.id])
                    x["case"] = v_cve.case.vu_vuid

        context['cves'] = cves
        logger.debug(context['cves'])
        return context


class CVESingleDetailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vince/cve_single_detail.html"
    login_url = "vince:login"

    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            cveaccount = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            if is_my_team(self.request.user, cveaccount.team.id):
                return True
        return False

    def get_context_data(self, **kwargs):
        context = super(CVESingleDetailView, self).get_context_data(**kwargs)
        logger.debug("SINGLE VIEW")
        acc = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
        cve_lib = cvelib.CveApi(acc.email, acc.org_name, acc.api_key, env=settings.CVE_SERVICES_API)
        if cve_lib.ping():
            try:
                cves = cve_lib.show_cve(self.kwargs['cveid'])
                logger.debug(cves)
            except cvelib.CveApiError as e:
                context['account_error'] = str(e)
        else:
            context['service_down'] = 1

        context['cve'] = cves

        context['vince_request'] = CVEReservation.objects.filter(cve_id = self.kwargs['cveid']).first() 
        
        return context

    
class CVEServicesManageAccount(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    template_name = 'vince/manage_cve.html'
    login_url="vince:login"
    form_class = CVEServicesForm

    def get_success_url(self):
        return reverse_lazy('vince:cve_dashboard')
    
    def test_func(self):
        if is_in_group_vincetrack(self.request.user):
            if self.kwargs.get('pk'):
                if is_my_team(self.request.user, self.kwargs['pk']):
                    return True
            else:
                return True
        return False


    def get_context_data(self, **kwargs):
        context = super(CVEServicesManageAccount, self).get_context_data(**kwargs)

        if self.kwargs.get('pk'):
            #this is a form edit
            account = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            context['title'] = 'Edit CVE Services Account'
            form = CVEServicesForm(instance=account)
            context['form'] = form
        else:
            context['title'] = 'Add CVE Services Account'
            initial = {}
            teams = Group.objects.exclude(groupsettings__contact__isnull=True)
            my_teams = self.request.user.groups.exclude(groupsettings__contact__isnull=True)
            form = CVEServicesForm()
            form.fields['team'].choices = [(g.id, g.name) for g in my_teams]
            context['form'] = form
        return context

    def form_invalid(self, form):
        logger.debug(f"CVEservicesManageAccount errors: {form.errors}")
        return super().form_invalid(form)
    
    def post(self, request, *args, **kwargs):
        if self.kwargs.get('pk'):
            account = get_object_or_404(CVEServicesAccount, id=self.kwargs['pk'])
            form = CVEServicesForm(request.POST, instance=account)
        else:
            form = CVEServicesForm(request.POST)

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        account = form.save()
        return redirect("vince:cve_dashboard")

class VINCEBounceManager(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vince/bouncemanager.html"
    login_url = "vince:login"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)


    def get_context_data(self, **kwargs):
        context = super(VINCEBounceManager, self).get_context_data(**kwargs)
        #look for open tickets with bounces

        context['permanent'] = BounceEmailNotification.objects.filter(bounce_type=BounceEmailNotification.PERMANENT, action_taken=False).order_by('-bounce_date')

        

        context['transient'] = BounceEmailNotification.objects.filter(bounce_type=BounceEmailNotification.TRANSIENT, ticket__status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS]).order_by('-bounce_date')


        context['operm'] = FollowUp.objects.filter(title__startswith="Email Bounce Notification", ticket__status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS], comment__icontains="Permanent")
        return context


    
def _get_app_name(request):

    if "comm" in request:
        return "vinny"

    return None

def error_404(request, exception):
    data = {}

    app_name = _get_app_name(request.path)

    if app_name:
        return render(request, f'{app_name}/404.html', data, status=404)

    return render(request, 'vincepub/404.html', data, status=404)


def error_403(request, exception):
    data = {}

    app_name = _get_app_name(request.path)

    if app_name:
        return render(request, f'{app_name}/403.html', data, status=403)

    return render(request, 'vincepub/403.html', data, status=403)

def error_500(request):
    data = {}

    app_name = _get_app_name(request.path)

    if app_name:
        return render(request, f'{app_name}/500.html', data, status=500)

    return render(request, 'vincepub/500.html', data, status=500)

def error_400(request, exception):
    data = {}

    app_name = _get_app_name(request.path)

    if app_name:
        return render(request, f'{app_name}/400.html', data, status=400)

    return render(request, 'vincepub/400.html', data, status=400)
