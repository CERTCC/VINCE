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
import logging
from django.shortcuts import render, redirect, get_object_or_404, render_to_response
from django.contrib import messages
from django.views import generic, View
from django.views.generic.edit import FormView, UpdateView, FormMixin, CreateView
from django.contrib.auth.models import User
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.http import HttpResponse, Http404, JsonResponse, HttpResponseNotAllowed, HttpResponseServerError, HttpResponseForbidden, HttpResponseRedirect, HttpResponseBadRequest
from django.core.validators import validate_email
from django.core.exceptions import ValidationError, PermissionDenied
from django.utils.translation import ugettext as _
from django.utils import timezone
from django.db.models import Case as DBCase
import pytz
import difflib
import json
import boto3
from rest_framework import exceptions, generics, authentication, viewsets, mixins, status as rest_status
from rest_framework.permissions import IsAdminUser, IsAuthenticated, BasePermission
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from vinny.serializers import CaseSerializer, PostSerializer, OrigReportSerializer, VendorStatusSerializer, VulSerializer, VendorSerializer, VulNoteSerializer, VendorStatusUpdateSerializer, VendorInfoSerializer, CSAFSerializer
from vincepub.serializers import VUReportSerializer, VendorVulSerializer, NewVendorRecordSerializer
from vincepub.serializers import VulSerializer as VPVulSerializer
from django.template.loader import get_template
from dateutil.parser import parse
from django.forms.fields import DateField, DateTimeField
from django.core.paginator import Paginator
from datetime import datetime, timedelta, tzinfo
import requests
import mimetypes
from django.forms.utils import ErrorList
from vinny.models import *
from vincepub.models import VulCoordRequest, VUReport, NoteVulnerability, VendorVulStatus, VendorRecord
from vinny.forms import *
from vinny.lib import vince_comm_send_sqs, send_sns, send_sns_json, send_usermention_notification, new_track_ticket, send_post_email, user_is_admin, user_has_access
from random import randint
from django.template.defaulttags import register
from django.urls import reverse, reverse_lazy
from cogauth.views import TokenMixin, GetUserMixin, PendingTestMixin
from cogauth.utils import cognito_admin_user, token_verify, create_service_account, send_courtesy_email
from cogauth.backend import JSONWebTokenAuthentication
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import authenticate, login as auth_login
from .permissions import is_in_group_vincegroupadmin, is_in_group_vincetrack, is_in_group_vincelimited, is_not_pending
from django.forms.formsets import formset_factory
from django.forms.models import modelformset_factory, inlineformset_factory
import vinny.contact_update as contact_update
from vinny.mailer import send_templated_mail
import traceback
import html
import re
from itertools import chain
from django.db.models import Q, OuterRef, Subquery, Max
from botocore.exceptions import ClientError
from botocore.client import Config

# Create your views here.

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class EST(tzinfo):
    def utcoffset(self, dt):
        return timedelta(hours=-5)

    def dst(self, dt):
        return timedelta(0)


def _user_allowed(member, user):
    # here is where it gets complicated -
    # does this vendor allow all users to have acess to the case?
    try:
        if member.group.groupcontact.default_access:
            return True
        # else is this a group admin?
        elif user_is_admin(member.group.groupcontact.contact, user):
            return True
        elif user_has_access(member, user):
            return True
    except GroupContact.DoesNotExist:
        #this is a participant/reporter                                         
        return True
    return False
    
def _is_my_case(user, case):
    groups = user.groups.all()
    if not groups:
        return False
    user_group = groups.values_list('id', flat=True)
    if user.is_superuser:
        return True
    else:
        members = CaseMember.objects.filter(case__id=case, group__in=user_group)
        for member in members:
            if _user_allowed(member, user):
                return True
    return False

def _is_my_report(user, report):
    if report.user == user:
        return True
    if report.coordinator:
        if (user.groups.filter(id=report.coordinator.id).exists()):
            return True
        if user.is_superuser:
            return True
    elif is_in_group_vincetrack(user):
        return True

    return False

def _user_in_contact(user, contact):
    gc = GroupContact.objects.filter(contact=contact).first()
    logger.debug(gc.contact.uuid)
    return user.groups.filter(name=gc.contact.uuid).exists()
        
def _my_group_name(user):
    groups = user.groups.all()
    if not groups:
        return "None"
    return groups[0].name

def _my_group(user):
    groups = user.groups.all()
    if not groups:
        return []
    return groups.values_list('id', flat=True)

def _get_my_cases(user):
    groups = _my_group(user)
    cases = []
    member = CaseMember.objects.filter(group__in=groups)
    for m in member:
        if _is_my_case(user, m.case.id):
            cases.append(m.case.id)
    return Case.objects.filter(id__in=cases)
    
def _is_my_post(user, post):
    if post.author == user:
        return True
    else:
        return False

def _my_member(user, case):
    member = CaseMember.objects.filter(case=case, group__in=_my_group(user)).first()
    return member


def _my_cases(user):
    if user.is_superuser:
        return Case.objects.all()

    my_cases = CaseMember.objects.filter(group__in=_my_group(user)).values_list('case')
    return Case.objects.filter(id__in=my_cases)

def _my_active_cases(user):
    return _my_cases(user).filter(status=Case.ACTIVE_STATUS)


def _my_reports(user):
    return VTCaseRequest.objects.filter(user=user)

def _my_group_admin(user):
    contacts = _my_contact_group(user)
    if contacts:
        group = contacts[0]
        ga = VinceCommGroupAdmin.objects.filter(contact=group).values_list('email__email', flat=True)
        # check if User exists                                         
        if ga:
            return User.objects.filter(username__in=ga)
    return []

def _my_group_for_case(user, case):
    my_groups = user.groups.exclude(groupcontact__isnull=True)
    casemembers = CaseMember.objects.filter(case=case, group__in=my_groups)
    for member in casemembers:
        if member.coordinator or member.reporter_group:
            #this is a coordinator or a reporting group
            continue
        elif _user_allowed(member, user):
            return member.group.name
    #this user is a participant
    return None

# this is slightly different from above, will return a queryset instead of a name
def _my_groups_for_case(user, case):
    my_groups = user.groups.exclude(groupcontact__isnull=True)
    casemembers = CaseMember.objects.filter(case=case, group__in=my_groups)
    rv = casemembers
    for member in casemembers:
        if _user_allowed(member, user):
            continue
        else:
            rv = rv.exclude(id=member.id)
        # this one doesn't have access to this case based on access controls
        # remove from set
    return rv


def _my_group_id_for_case(user, case):
    my_groups = user.groups.exclude(groupcontact__isnull=True)
    casemembers = CaseMember.objects.filter(case=case, group__in=my_groups)
    if casemembers:
        for member in casemembers:
            if _user_allowed(member, user):
                return member.group
    #this user is a participant
    return None


def _my_contact_group(user):
    admin_groups = VinceCommGroupAdmin.objects.filter(email__email=user.email, contact__active=True).values_list('contact__id', flat=True)
    groups = user.groups.filter(groupcontact__contact__vendor_type__in=["Vendor", "Coordinator"], groupcontact__contact__in=admin_groups).exclude(groupcontact__isnull=True)
    my_groups = []
    for ug in groups:
        my_groups.append(ug.groupcontact.contact)
    return my_groups

def _cases_for_group(group):
    cases = CaseMember.objects.filter(group=group).values_list('case__id', flat=True)
    return Case.objects.filter(id__in=cases)
    

def _users_in_my_group(user):
    groups = user.groups.exclude(groupcontact__isnull=True)
    logger.debug("IN USERS IN MY GROUP")
    if groups:
        return User.objects.filter(groups__in=groups).exclude(vinceprofile__service=True).distinct()
    return []

def _users_in_group(contact):
    gc = GroupContact.objects.filter(contact=contact).first()
    if gc:
        return User.objects.filter(groups=gc.group, is_active=True).exclude(vinceprofile__service=True)
    else:
        return []

def _unread_msg_count(user):
    return len(Thread.ordered(Thread.unread(user)))

def _groupchat_case_participants(case):
    participants = CaseMember.objects.filter(case=case)
    members = []
    already_added = []
    for participant in participants:
        if participant.participant:
            members.append({'value':participant.participant.vinceprofile.preferred_username, 'label':participant.participant.vinceprofile.preferred_username })
            already_added.append(participant.participant.vinceprofile.preferred_username)
        elif participant.group:
            #only allow groups with actual VINCE users
            if participant.group.user_set.count() > 0:
                try:
                    members.append({'value':participant.group.groupcontact.contact.vendor_name, 'label':participant.group.groupcontact.contact.vendor_name})
                except:
                    continue
    return members

def _case_participants(case):
    participants = CaseMember.objects.filter(case=case)
    members = []
    already_added = []
    for participant in participants:
        if participant.participant:
            members.append({'value':participant.participant.vinceprofile.preferred_username, 'label':participant.participant.vinceprofile.preferred_username })
            already_added.append(participant.participant.vinceprofile.preferred_username)
        elif participant.group:
            try:
                members.append({'value':participant.group.groupcontact.contact.vendor_name, 'label':participant.group.groupcontact.contact.vendor_name})
            except:
                #groupcontact doesn't exist
                continue
    # get anyone that's made a post on this case
    posts = Post.objects.filter(case=case).exclude(author__vinceprofile__preferred_username__in=already_added).distinct('author')
    for post in posts:
        #poster may have been removed from case so check here
        try:
            if _is_my_case(post.author, case.id):
                members.append({'value':post.author.vinceprofile.preferred_username, 'label':post.author.vinceprofile.preferred_username})
        except:
            #post author may no longer exist
            continue
    return members


def _show_status_vul(user, vuls, case):
    showupdatestatus=False
    group = _my_group_for_case(user, case)
    if len(vuls)==0:
        showstatus = False
    else:
        if group:
            showstatus = True
            # else this is a participant/coordinator                                                                                  
        else:
            showstatus = False

    members = _my_groups_for_case(user, case)
    for member in members:
        status = CaseMemberStatus.objects.filter(member=member)
        if len(status) >= len(vuls):
            showupdatestatus = True
            break
        else:
            showupdatestatus = False
            
    return showstatus, showupdatestatus

def _remove_case_pinned_posts(case):
    posts = Post.objects.filter(case=case, pinned=True)
    for post in posts:
        post.pinned=False
        post.save()
        

def object_to_json_response(obj, status=200):
    """                                                                                                          
    Given an object, returns an HttpResponse object with a JSON serialized
    version of that object
    """
    logger.debug(obj)
    return JsonResponse(
        data=obj, status=status, safe=False, json_dumps_params={'ensure_ascii': False},
    )


@login_required(login_url="vinny:login")
@user_passes_test(is_in_group_vincetrack, login_url='vinny:login')
def autocomplete_vendor(request):
    if request.GET.get('term'):
        #vendorlist = list(VinceCommContact.objects.filter(vendor_name__istartswith=request.GET.get('term')).values_list('vendor_name', flat=True).distinct())
        vendorlist = list(Group.objects.all().exclude(groupcontact__isnull=True).values_list('groupcontact__contact__vendor_name', flat=True))
    else:
        vendorlist = list(Group.objects.all().exclude(groupcontact__isnull=True).values_list('groupcontact__contact__vendor_name', flat=True))
        #vendorlist = list(VinceCommContact.objects.values_list('vendor_name', flat=True).distinct())
    data = json.dumps(vendorlist)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)


@login_required(login_url="vinny:login")
@user_passes_test(is_not_pending, login_url="vinny:login")
def autocomplete_coordinators(request, pk):
    case = get_object_or_404(Case, id=pk)
    if _is_my_case(request.user, pk):
        clist = list(CaseMember.objects.filter(case=case, coordinator=True).exclude(group__groupcontact__vincetrack=False).values_list('group__groupcontact__contact__vendor_name', flat=True))
        
        data = json.dumps(", ".join(clist))
        mimetype = 'application/json'
        return HttpResponse(data, mimetype)
        
    return HttpResponse([], 'application/json')


@login_required(login_url="vinny:login")
@user_passes_test(is_in_group_vincetrack, login_url='vinny:login')
def autocomplete_users(request):
    if request.GET.get('term'):
        vendorlist = list(User.objects.filter(email__istartswith=request.GET.get('term'), vinceprofile__pending=False, is_active=True).exclude(vinceprofile__service=True).values_list('email', flat=True))
    else:
        vendorlist = list(User.objects.filter(vinceprofile__pending=False, is_active=True).exclude(vinceprofile__service=True).values_list('email', flat=True))
    data = json.dumps(vendorlist)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)


@register.simple_tag()
def random_number(length=3):
    """
    Create a random integer with given length.
    For a length of 3 it will be between 100 and 999.
    For a length of 4 it will be between 1000 and 9999.
    """
    return randint(10**(length-1), (10**(length)-1))

@register.filter(name='vulstatus')
def vulstatus(qs, vul):
    status = qs.filter(vulnerability=vul).values_list('status', flat=True)
    if status:
        logger.debug(status[0])
        return status[0]
    else:
        return None

@register.filter(name='vulapproved')
def vulapproved(qs, vul):
    status = qs.filter(vulnerability=vul).first()
    if status:
        return status.approved
    else:
        return False

@register.filter(name='has_statement')
def has_statement(qs, vul):
    statement = qs.filter(vulnerability=vul)
    if statement:
        if statement[0].statement or statement[0].references:
            return True
        else:
            return False
    return False

@register.simple_tag()
def show_status(status=3):
    if status == 1:
        return "Affected"
    elif status == 2:
        return "Not Affected"
    else:
        return "Unknown"

@register.simple_tag()
def show_status_class(status=3):
    if status == 1:
        return "label alert"
    elif status == 2:
        return "label success"
    else:
        return "label warning"

def get_status_int(status):
    if status.lower() == "affected":
        return 1
    elif status.lower() == "not affected":
        return 2
    elif status.lower() == "unknown":
        return 3
    else:
        return None
    
@register.filter(name="post_order")
def post_order(case, order):
    if order == "first":
        return Post.objects.filter(case=case).order_by('created').first()
    else:
        return Post.objects.filter(case=case).order_by('-created')[:1].first()


def create_action(title, user, case=None):
    action = VendorAction(title=title,
                          user=user)
    if case:
        action.case=case

    action.save()

    return action

    
class TokenLogin(GetUserMixin, generic.TemplateView):
    template_name = 'vinny/index.html'

    def post(self, request, *args, **kwargs):
        if (token_verify(self.request.POST['access_token'])):
            request.session['ACCESS_TOKEN'] = self.request.POST['access_token']
            request.session['REFRESH_TOKEN'] = self.request.POST['refresh_token']
            user = self.get_user()
            logger.debug(user)
            user = authenticate(self.request, username=user.email)
            logger.debug("get local user")
            logger.debug(user)
            if user:
                auth_login(request, user)
                request.session['timezone'] = user.vinceprofile.timezone
                logger.debug("after auth_login")
                return JsonResponse({'response': 'success'}, status=200)
        logger.debug("unauthorized access")
        return JsonResponse({'response': 'Unauthorized', 'error': 'Unauthorized access'}, status=401)

class RedirectVince(LoginRequiredMixin, generic.TemplateView):
    template_name = 'vinny/redirect.html'
    login_url = "vinny:login"

    def get_context_data(self, **kwargs):
        context = super(RedirectVince, self).get_context_data(**kwargs)
        next_url = self.request.GET.get('next')
        context['action'] = next_url
        return context
    
class VinceTokens(LoginRequiredMixin, generic.TemplateView):
    login_url = "vinny:login"
    
    def get(self, request, *args, **kwargs):
        return JsonResponse({'ACCESS_TOKEN': self.request.session.get('ACCESS_TOKEN'),
                             'REFRESH_TOKEN': self.request.session.get('REFRESH_TOKEN')}, status=200)
    
class IndexView(generic.TemplateView):
    template_name = 'vinny/index.html'

class FAQView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.TemplateView):
    template_name = 'vinny/faq.html'

    def get_context_data(self, **kwargs):
        context = super(FAQView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        return context

class VinceAttachmentView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"

    def test_func(self):
        a_type = self.kwargs.get('type')
        if a_type == "case":
            c_attach = VinceCommCaseAttachment.objects.filter(file__uuid=self.kwargs.get('path')).first()
            if c_attach == None:
                raise Http404
            if c_attach.action.case:
                case = get_object_or_404(Case, id=c_attach.action.case.id)
                return _is_my_case(self.request.user, case.id) and PendingTestMixin.test_func(self)
        elif a_type == "report":
            r_attach = ReportAttachment.objects.filter(file__uuid=self.kwargs.get('path')).first()
            if r_attach == None:
                raise Http404
            if r_attach.action:
                report = get_object_or_404(VTCaseRequest, id=r_attach.action.cr.id)
                return _is_my_report(self.request.user, report) and PendingTestMixin.test_func(self)
        elif a_type == "msg":
            m_attach = MessageAttachment.objects.filter(file__uuid=self.kwargs.get('path')).first()
            if m_attach == None:
                raise Http404
            message = get_object_or_404(Message, id=m_attach.message.id)
            thread = message.thread.id
            return UserThread.objects.filter(thread=message.thread.id, user=self.request.user).exists() and PendingTestMixin.test_func(self)
        elif a_type == "track":
            t_attach = VinceTrackAttachment.objects.filter(file__uuid=self.kwargs.get('path')).first()
            if t_attach == None:
                raise Http404
            if t_attach.case:
                case = get_object_or_404(Case, id=t_attach.case.id)
                return _is_my_case(self.request.user, case.id) and PendingTestMixin.test_func(self)
        raise Http404

    def get(self, request, *args, **kwargs):
        logger.debug(self.kwargs['path'])
        attachment = VinceAttachment.objects.filter(uuid=self.kwargs['path']).first()
        if attachment:
            mime_type = attachment.mime_type
            response = HttpResponseRedirect(attachment.access_url, content_type = mime_type)
            response['Content-Disposition'] = f"attachment; filename=\"{attachment.filename}\""
            response["Content-type"] = mime_type
            response["Cache-Control"] = "must-revalidate"
            response["Pragma"] = "must-revalidate"
            return response
        raise Http404

class VinceVRFAttachmentView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"

    def test_func(self):
        report = get_object_or_404(VTCaseRequest, id=self.kwargs['pk'])
        return _is_my_report(self.request.user, report) and PendingTestMixin.test_func(self)

    def get(self, request, *args, **kwargs):
        report = get_object_or_404(VTCaseRequest, id=self.kwargs['pk'])
        if report.user_file:
            mime_type = mimetypes.guess_type(report.user_file.name, strict=False)[0]
            if not(mime_type):
                mime_type = 'application/octet-stream'
            response = HttpResponseRedirect(report.user_file.url, content_type = mime_type)
            response['ResponseContentDisposition'] = f"attachment; filename=\"{report.user_file.name}\""
            response["Content-type"] = mime_type
            response["Cache-Control"] = "must-revalidate"
            response["Pragma"] = "must-revalidate"
            return response
        raise Http404
    
class DashboardView(LoginRequiredMixin, TokenMixin, PendingTestMixin,  generic.TemplateView):
    """A quick summary overview for users. A list of their own tickets,                
    and a list of unassigned tickets"""
    template_name='vinny/dashboard.html'
    login_url="vinny:login"

    """
    #do not need to verify email, it is done on signup
    def dispatch(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            logger.debug("user is authenticated")
            if request.user.vinceprofile.email_verified == False:
                return redirect("cogauth:verify_email")
        return super().dispatch(request, *args, **kwargs)
    """
    
    def get_context_data(self, **kwargs):
        context = super(DashboardView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['dashboard'] = 'yes'
        if settings.DEBUG:
            context['devmode'] = True

        #check config
        admin_group_name = settings.COGNITO_ADMIN_GROUP
        #Does this group exist
        admin_group = Group.objects.using('vincecomm').filter(groupcontact__contact__vendor_name=settings.COGNITO_ADMIN_GROUP).first()
        if admin_group == None:
            messages.error(
                self.request,
		_(f"VINCE is not correctly configured. ADMIN GROUP {settings.COGNITO_ADMIN_GROUP} does not exist."))
        
        if is_in_group_vincetrack(self.request.user):
            assignable_users = _users_in_my_group(self.request.user)
            if assignable_users:
                assignable_users = assignable_users.order_by(User.USERNAME_FIELD)
            form = CaseRoleForm()
            form.fields['owner'].choices = [
                (u.id, u.vinceprofile.vince_username) for u in assignable_users]

            context['form'] = form
            my_cases = _my_active_cases(self.request.user)
            cases = my_cases.annotate(last_post_date=Max('post__created')).exclude(last_post_date__isnull=True).order_by('-last_post_date')
            cases_no_posts = my_cases.exclude(id__in=cases).order_by('-modified')
            context['cases'] = chain(cases, cases_no_posts)
            context['pending'] =  VTCaseRequest.objects.filter(user=self.request.user, status=0).order_by('-date_submitted')
            return context

        last_login = self.request.session.get("LAST_LOGIN")
        my_cases = _get_my_cases(self.request.user)
        my_cases = my_cases.filter(status=Case.ACTIVE_STATUS)
        #get posts in those cases
        unseen_cases = []
        context['new_posts'] = 0
        # build tuple: case, last modified (first post, if no post, details)
        cases = my_cases.annotate(last_post_date=Max('post__created')).exclude(last_post_date__isnull=True).order_by('-last_post_date')
        context['num_published'] = my_cases.filter(note__datefirstpublished__isnull=False).count()
        cases_no_posts = my_cases.exclude(id__in=cases).order_by('-modified')
        context['cases'] = list(chain(cases, cases_no_posts))
        context['num_new_cases'] = 0
        
        for case in my_cases:
            logger.debug(case)
            last_post = Post.objects.filter(case=case).order_by('-modified')
            last_viewed = CaseViewed.objects.filter(user=self.request.user, case=case).first()
            if last_post and last_viewed:
                #is there a new post since last viewed?
                posts = last_post.filter(created__gt=last_viewed.date_viewed)
                if posts:
                    unseen_cases.append(case.id)
                    context['new_posts'] += posts.count()
            elif last_viewed == None and last_login != "New":
                #this user hasn't viewed this case yet
                context['num_new_cases'] += 1
                context['new_posts'] += last_post.count()
                unseen_cases.append(case.id)
                
        context['unseen_cases'] = unseen_cases
        if last_login == "New":
            context['num_new_cases'] = len(my_cases)
            context['new_user'] = True
        elif last_login:
            context['last_login'] = parse(last_login)
            
        context['pending'] =  VTCaseRequest.objects.filter(user=self.request.user, status=0).order_by('-date_submitted')
        return context


class SingleVulDetailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/vul.html"
    
    def test_func(self):
        case = get_object_or_404(CaseVulnerability, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, case.case.id) and PendingTestMixin.test_func(self)

    def get_context_data(self, **kwargs):
        context = super(SingleVulDetailView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        vul = get_object_or_404(CaseVulnerability, id=self.kwargs['pk'])
        context['exploits'] = CaseVulExploit.objects.filter(vul=vul)
        context['vul'] = vul
        context['cvss'] = CaseVulCVSS.objects.filter(vul=vul).first()
        context['showstatus'], context['showupdatestatus'] = _show_status_vul(self.request.user, [vul], vul.case)
        if context['showupdatestatus']:
            members = _my_groups_for_case(self.request.user, vul.case)
            context['status'] = CaseMemberStatus.objects.filter(member__in=members, vulnerability=vul)
            
        return context
        
    
class VulnerabilityDetailView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/vuls.html"
    
    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def get_context_data(self, **kwargs):
        context = super(VulnerabilityDetailView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        vuls = CaseVulnerability.objects.filter(case=case)
        context['vuls'] = vuls
        context['vulsjs'] = [obj.as_dict() for obj in context['vuls']]
        context['case'] = case
        # need this for limited access view
        if self.request.META.get('HTTP_REFERER'):
            context['case_link'] = self.request.META.get('HTTP_REFERER')
        else:
            context['case_link'] = reverse("vinny:case", args=[self.kwargs['pk']])

        #what group am I in?
        status_dict = dict(CaseMemberStatus.STATUS_CHOICES)
        context['showstatus'], context['showupdatestatus'] = _show_status_vul(self.request.user, vuls, case)
        if context['showstatus']:
            members = _my_groups_for_case(self.request.user, case)
            for v in context['vulsjs']:
                status = CaseMemberStatus.objects.filter(member__in=members, vulnerability__id=v['id']).first()
                if status:
                    v['status'] = status_dict[status.status]
                else:
                    v['status'] = "Unknown"
        
        return context
    
class RemoveFileView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/confirmrm.html"

    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def get_context_data(self, **kwargs):
        context = super(RemoveFileView, self).get_context_data(**kwargs)
        context['action'] = reverse("vinny:rmfile", args=[self.kwargs['pk'], self.kwargs['doc']])
        return context
    
    def post(self, request, *args, **kwargs):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        attachment = get_object_or_404(VinceCommCaseAttachment, id=self.kwargs['doc'])
        if not(self.request.user.is_staff):
            if attachment.action.user != self.request.user:
                return JsonResponse({'error':'Unauthorized'}, status=401)
            
        if attachment.file:
            attachment.file.file.delete(save=False)
            attachment.file.delete()
        else:
            attachment.delete()
        messages.success(
            self.request,
            _("Your file was successfully removed."))        
        return redirect("vinny:case", self.kwargs['pk'])

class VinceCommPrintReportsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/printreport.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) or is_in_group_vincelimited(self.request.user)


    def get_context_data(self, **kwargs):
        context = super(VinceCommPrintReportsView, self).get_context_data(**kwargs)
        year = int(self.kwargs['year'])
        month = int(self.kwargs['month'])
        if month == 0:
            month = 12
            year = year - 1
        elif month > 12:
            month = 1
            year = year + 1
        context['year'] = year
        context['monthstr'] = date(year, month, 1).strftime('%B')
        context['month'] = month
        context['newnotes'] = Case.objects.filter(note__datefirstpublished__year=year, note__datefirstpublished__month=month).exclude(note__datefirstpublished__isnull=True)
        context['updated'] = Case.objects.filter(note__dateupdated__year=year, note__dateupdated__month=month).exclude(note__datefirstpublished__isnull=True)
        new_cases = Case.objects.filter(created__year=year, created__month=month).order_by('created')
        date_month = date(year, month, 1)

        active_cases = Case.objects.filter(status = Case.ACTIVE_STATUS, created__lt=date_month)
        published_active_cases = active_cases.filter(Q(note__datefirstpublished__isnull=False) | Q(publicdate__isnull=False))
        pre_public_active_cases = active_cases.exclude(Q(note__datefirstpublished__isnull=False) | Q(publicdate__isnull=False))
        context.update({'case_stats': {'new_cases':new_cases,
                                       'active_cases': active_cases,
                                       'published_active_cases': published_active_cases,
                                       'unpublished_active_cases': pre_public_active_cases}})
        context['new_users'] = User.objects.using('vincecomm').filter(date_joined__month=month, date_joined__year=year).count()
        return context

        
class VinceCommReportView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/report.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) or is_in_group_vincelimited(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(VinceCommReportView, self).get_context_data(**kwargs)
        context['limitedaccess'] = 1
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['reportspage'] = 1
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
        if (month < datetime.now().month) and (year <= datetime.now().year):
            context['show_next'] = 1
        elif (year < datetime.now().year):
            context['show_next'] = 1
        context['newnotes'] = Case.objects.filter(note__datefirstpublished__year=year, note__datefirstpublished__month=month).exclude(note__datefirstpublished__isnull=True)
        context['updated'] = Case.objects.filter(note__dateupdated__year=year, note__dateupdated__month=month).exclude(note__datefirstpublished__isnull=True)
        new_cases = Case.objects.filter(created__year=year, created__month=month).order_by('created')
        date_month = date(year, month, 1)

        active_cases = Case.objects.filter(status = Case.ACTIVE_STATUS, created__lt=date_month)
        published_active_cases = active_cases.filter(Q(note__datefirstpublished__isnull=False) | Q(publicdate__isnull=False))
        pre_public_active_cases = active_cases.exclude(Q(note__datefirstpublished__isnull=False) | Q(publicdate__isnull=False))
        #deactive_cases = CaseAction.objects.filter(title__icontains="changed status of case from Active to Inactive", date__month=month, date__year=year).select_related('case').order_by('case').distinct('case')
        #to_active_cases = CaseAction.objects.filter(title__icontains="changed status of case from Inactive to Active", date__month=month, date__year=year).select_related('case').order_by('case').distinct('case')
        context.update({'case_stats': {'new_cases':new_cases,
                                       'active_cases': active_cases,
                                       'published_active_cases': published_active_cases,
                                       'unpublished_active_cases': pre_public_active_cases}})
        context['new_users'] = User.objects.using('vincecomm').filter(date_joined__month=month, date_joined__year=year).count()
        context['total_users'] = User.objects.using('vincecomm').all().count()
        
        return context
    
            
class CaseSummaryView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    login_url = "vinny:login"
    model = Case
    template_name = "vinny/case_summary.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) or is_in_group_vincelimited(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CaseSummaryView, self).get_context_data(**kwargs)
        context['limitedaccess'] = 1
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['vendors'] = CaseMember.objects.filter(case__id=self.kwargs['pk'], coordinator=False).order_by("group__name")
        context['participants'] = CaseMember.objects.filter(case__id=self.kwargs['pk'], participant__isnull=False, coordinator=False)
        context['coordinators'] = CaseMember.objects.filter(case__id=self.kwargs['pk'], coordinator=True)
        vuls = CaseVulnerability.objects.filter(case__id=self.kwargs['pk'])
        context['vuls'] = vuls
        return context

class RequestAccessView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/request_access.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) or is_in_group_vincelimited(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(RequestAccessView, self).get_context_data(**kwargs)
        context['action'] = reverse("vinny:requestaccess", args=[self.kwargs['pk']])
        return context
    
    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        new_track_ticket("Case", "Case access requested", "User has requested access to this case", case, self.request.user.username)
        #add a model to keep track of requests
        messages.success(
            self.request,
            _("Your request has been submitted."))
        return redirect("vinny:case_summary", self.kwargs['pk'])
    
class LimitedAccessView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    login_url = "vinny:login"
    model = Case
    paginate_by = 10
    template_name = "vinny/limited.html"
    
    def test_func(self):
        return is_in_group_vincetrack(self.request.user) or is_in_group_vincelimited(self.request.user)

    def get_queryset(self):
        return Case.objects.filter(status=Case.ACTIVE_STATUS).exclude(due_date__isnull=True).order_by('due_date')
    
    def get_context_data(self, **kwargs):
        context = super(LimitedAccessView, self).get_context_data(**kwargs)
        context['limitedaccess'] = 1
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        initial = {'status': [Case.ACTIVE_STATUS]}
        form = LimitedCaseFilterForm(initial=initial)
        context['form'] = form
        return context

class ChangeDefaultCaseAccess(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vinny/caseaccess.html'
    login_url = "vinny:login"

    #only group admins have access
    def test_func(self):
        self.admin = None
        if is_in_group_vincegroupadmin(self.request.user):
            gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
            self.admin = VinceCommGroupAdmin.objects.filter(contact__id=gc.contact.id, email__email=self.request.user.email).first()
            if self.admin:
                return PendingTestMixin.test_func(self)
        return False
    
    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
        default_access = self.request.POST.get('accessSwitch', default=False)
        if default_access == "on":
            default_access = True

        gc.default_access = default_access
        gc.save()
        return JsonResponse({"status": "success"}, status=200)

class UserCaseAccessView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vinny/admin_users.html'
    login_url = "vinny:login"

    def test_func(self):
        if is_in_group_vincegroupadmin(self.request.user):
            gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
            admin = VinceCommGroupAdmin.objects.filter(contact__id=gc.contact.id, email__email=self.request.user.email).first()
            if admin:
                return PendingTestMixin.test_func(self)
        elif self.request.user.is_superuser:
            return True
        return False

    def get_context_data(self, **kwargs):
        context = super(UserCaseAccessView, self).get_context_data(**kwargs)
        gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
        context['users'] = _users_in_group(gc.contact)
        context['admin'] = VinceCommGroupAdmin.objects.filter(contact__id=gc.contact.id, email__email=self.request.user.email).first()
        context['object'] = gc.contact
        context['vendor_name'] = gc.contact.vendor_name
        emaillist = context['users'].values_list('username', flat=True)
        context['invited_users'] = VinceCommEmail.objects.filter(invited=True, contact=context['object']).exclude(email__in=emaillist)
        context['eligible_users'] = VinceCommEmail.objects.filter(invited=False, contact=context['object'],email_list=False).exclude(email__in=emaillist)
        context['groupcontact'] = gc
        cases = _cases_for_group(Group.objects.filter(groupcontact=gc).first())
        context['caseaccess'] = CaseMemberUserAccess.objects.filter(casemember__case__in=cases)
        return context

    
class CaseAccessView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vinny/caseaccess.html'
    login_url = "vinny:login"

    #only group admins and track users have access
    def test_func(self):
        if is_in_group_vincegroupadmin(self.request.user):
            admin = VinceCommGroupAdmin.objects.filter(contact__id=self.kwargs.get('vendor_id'), email__email=self.request.user.email).first()
            if admin:
                return PendingTestMixin.test_func(self)
        elif self.request.user.is_superuser:
            return True
        return False

    def get_context_data(self, **kwargs):
        context = super(CaseAccessView, self).get_context_data(**kwargs)
        #which group are they groupadmin of?
        vendor_id = self.kwargs.get('vendor_id')
        context['vendor'] = vendor_id
        context['u']= get_object_or_404(User, id=self.kwargs.get('user_id'))
        group = Group.objects.filter(groupcontact__contact__id=vendor_id).first()
        context['cases'] = _cases_for_group(Group.objects.filter(groupcontact__contact__id=vendor_id).first())
        cases = context['cases'].values_list('id', flat=True)
        context['access'] = list(CaseMemberUserAccess.objects.filter(user=context['u'], casemember__case__id__in=cases).values_list('casemember__case__vuid', flat=True))
        logger.debug(context['access'])
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        cases = self.request.POST.getlist('access', [])
        logger.debug(cases)
        vendor_id = self.kwargs.get('vendor_id')
        user_id = get_object_or_404(User, id=self.kwargs.get('user_id'))
        group = Group.objects.filter(groupcontact__contact__id=vendor_id).first()
        gc = group.groupcontact
        vendor_id = self.kwargs.get('vendor_id')
        all_cases = _cases_for_group(Group.objects.filter(groupcontact__contact__id=vendor_id).first())
        for case in all_cases:
            access = CaseMemberUserAccess.objects.filter(user=user_id, casemember__case=case).first()
            if case.vuid in cases:
                # this user has full access to all current cases
                #does this user have access?
                if access:
                    continue
                else:
                    casemember = CaseMember.objects.filter(case=case, group=group).first()
                    if casemember:
                        access = CaseMemberUserAccess(user=user_id,
                                                      admin=self.request.user,
                                                      casemember = casemember)
                        access.save()

            else:
                if access:
                    # this user's access is revoked
                    access.delete()
            
        
        return JsonResponse({'response': 'Success'}, status=200)
        

class PromoteUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vinny/confirm_promotion.html'
    login_url = "vinny:login"

    def test_func(self):
        if is_in_group_vincegroupadmin(self.request.user):
            gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
            logger.debug(gc)
            admin = VinceCommGroupAdmin.objects.filter(contact__id=gc.contact.id, email__email=self.request.user.email).first()
            if admin:
                logger.debug(admin)
                return PendingTestMixin.test_func(self)
        return False

    def get_context_data(self, **kwargs):
        context = super(PromoteUserView, self).get_context_data(**kwargs)
        user = get_object_or_404(User, id=self.kwargs.get('uid'))
        context['puser'] = user
        #is this user already a groupadmin?
        gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
        admin = VinceCommGroupAdmin.objects.filter(contact__id=gc.contact.id, email__email=user.email).first()
        if admin:
            context['remove_confirm'] = True
        else:
            context['promote_confirm'] = True
        context['gc'] = gc
        return context
    
    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
        user = get_object_or_404(User, id=self.kwargs.get('uid'))
        admin = VinceCommGroupAdmin.objects.filter(contact__id=gc.contact.id, email__email=user.email).first()
        if admin:
            admin.delete()
            action = VendorAction(title=f"{self.request.user.vinceprofile.vince_username} removed {user.vinceprofile.vince_username} as a group admin",
                                      user=self.request.user)
            action.save()
            changes = ContactInfoChange(contact=gc.contact,
                                        model="VinceCommGroupAdmin",
                                        action=action,
                                        field="groupadmin",
                                        old_value=user.email,
                                        new_value="")
            changes.save()
            # is this user a groupadmin of another group?
            admin = VinceCommGroupAdmin.objects.filter(email__email=user.email).first()
            if admin == None:
                ga_group = Group.objects.filter(name="vince_group_admin").first()
                if ga_group:
                    ga_group.user_set.remove(user)
        else:
            email = VinceCommEmail.objects.filter(email=user.email, contact=gc.contact.id).first()
            if email:
                admin = VinceCommGroupAdmin(contact=gc.contact,
                                            email=email,
                                            comm_action=True)
                admin.save()

                ga_group = Group.objects.filter(name="vince_group_admin").first()
                if ga_group:
                    ga_group.user_set.add(user)
                
                action = VendorAction(title=f"{self.request.user.vinceprofile.vince_username} made {user.vinceprofile.vince_username} a group admin",
                                      user=self.request.user)
                action.save()
                changes = ContactInfoChange(contact=gc.contact,
                                            model="VinceCommGroupAdmin",
                                            action=action,
                                            field="groupadmin",
                                            old_value="",
                                            new_value=user.email)
                changes.save()
            else:
                return JsonResponse({'response':'Error'}, status=500)

        #send sns to track
        contact_update.send_ticket_groupadmin(changes, gc.contact, self.request.user)

        return JsonResponse({'response': 'success'}, status=200)
        
    
class AdminView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vinny/admin.html'
    login_url = "vinny:login"

    def test_func(self):
        ga_groups = VinceCommGroupAdmin.objects.filter(email__email=self.request.user.email, contact__vendor_type__in=["Coordinator", "Vendor"], contact__active=True)
        if len(ga_groups) > 0:
            if self.kwargs.get('vendor_id'):
                admin = VinceCommGroupAdmin.objects.filter(contact__id=self.kwargs.get('vendor_id'), email__email=self.request.user.email).first()
                if admin:
                    return PendingTestMixin.test_func(self)
        return PendingTestMixin.test_func(self)
    
    def dispatch(self, request, *args, **kwargs):
        if self.kwargs.get('vendor_id'):
            return super().dispatch(request, *args, **kwargs)
        
        if is_in_group_vincegroupadmin(self.request.user):
            ga_groups = VinceCommGroupAdmin.objects.filter(email__email=self.request.user.email, contact__vendor_type__in=["Coordinator", "Vendor"], contact__active=True)
            if len(ga_groups) > 1:
                return redirect("vinny:multiple_admins")
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super(AdminView, self).get_context_data(**kwargs)
        #which group are they groupadmin of?
        context['adminview']=1
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        if self.kwargs.get('vendor_id') :
            admin = VinceCommGroupAdmin.objects.filter(contact__id=self.kwargs.get('vendor_id'), email__email=self.request.user.email).first()
            if admin:
                context['admin'] = True
                context['users'] = _users_in_group(admin.contact)
                context['object'] = admin.contact
                context['vendor_name'] = admin.contact.vendor_name
                context['notification_emails'] = VinceCommEmail.objects.filter(contact=context['object'], email_list=True)
                if context['users']:
                    emaillist = context['users'].values_list('username', flat=True)
                    context['invited_users'] = VinceCommEmail.objects.filter(invited=True, contact=context['object']).exclude(email__in=emaillist)
                    context['eligible_users'] = VinceCommEmail.objects.filter(invited=False, contact=context['object'], email_list=False, status=True).exclude(email__in=emaillist)
                    context['groupcontact'] = GroupContact.objects.filter(contact__id=self.kwargs.get('vendor_id')).first()
                    cases = _cases_for_group(Group.objects.filter(groupcontact=context['groupcontact']).first())
                    context['caseaccess'] = CaseMemberUserAccess.objects.filter(casemember__case__in=cases)
                    #get service account        
                    context['service'] = User.objects.filter(groups__in=[context['groupcontact'].group], vinceprofile__service=True).first()
            elif is_in_group_vincetrack(self.request.user):
                context['groupcontact'] = GroupContact.objects.filter(contact__id=self.kwargs.get('vendor_id')).first()
                cases = _cases_for_group(Group.objects.filter(groupcontact=context['groupcontact']).first())
                context['caseaccess'] = CaseMemberUserAccess.objects.filter(casemember__case__in=cases)
                if context['groupcontact']:
                    context['users'] = _users_in_group(context['groupcontact'].contact)
                    context['object'] = context['groupcontact'].contact
                    
                    context['vendor_name'] = context['object'].vendor_name
                    context['notification_emails'] = VinceCommEmail.objects.filter(contact=context['object'], email_list=True)
                    if context['users']:
                        emaillist = context['users'].values_list('username', flat=True)
                        context['invited_users'] = VinceCommEmail.objects.filter(invited=True, contact=context['object']).exclude(email__in=emaillist)
                        context['eligible_users'] = VinceCommEmail.objects.filter(invited=False, contact=context['object'],email_list=False, status=True).exclude(email__in=emaillist)
                        #get service account        
                        context['service'] = User.objects.filter(groups__in=[context['groupcontact'].group], vinceprofile__service=True).first()
            
        elif is_in_group_vincegroupadmin(self.request.user):
            ga_group = VinceCommGroupAdmin.objects.filter(email__email=self.request.user.username, contact__vendor_type__in=["Coordinator", "Vendor"], contact__active=True).first()
            if ga_group:
                context['admin'] = True
                context['users'] = _users_in_group(ga_group.contact)
                context['object'] = ga_group.contact
                context['vendor_name'] = ga_group.contact.vendor_name
                context['notification_emails'] = VinceCommEmail.objects.filter(contact=context['object'], email_list=True)
                if context['users']:
                    emaillist = context['users'].values_list('username', flat=True)
                    context['invited_users'] = VinceCommEmail.objects.filter(invited=True, contact=context['object']).exclude(email__in=emaillist)
                    context['eligible_users'] = VinceCommEmail.objects.filter(invited=False, contact=context['object'],email_list=False, status=True).exclude(email__in=emaillist)
                    context['groupcontact'] = GroupContact.objects.filter(contact__id=ga_group.contact.id).first()

                    cases = _cases_for_group(Group.objects.filter(groupcontact=context['groupcontact']).first())
                    context['caseaccess'] = CaseMemberUserAccess.objects.filter(casemember__case__in=cases)
                    
                    #get service account        
                    context['service'] = User.objects.filter(groups__in=[context['groupcontact'].group], vinceprofile__service=True).first()

        return context


class AdminRemoveUser(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/admin_remove.html"

    def test_func(self):
        if (is_in_group_vincegroupadmin(self.request.user) and PendingTestMixin.test_func(self)):
            vendor_id = self.kwargs.get('vendor_id')
            admin = VinceCommGroupAdmin.objects.filter(contact__id=vendor_id, email__email=self.request.user.email).first()
            if admin:
                return True
        return False

    def get_context_data(self, **kwargs):
        context = super(AdminRemoveUser, self).get_context_data(**kwargs)
        context['type'] = self.kwargs.get("type", None)
        context['uid'] = self.kwargs.get("uid", None)
        context['object'] = get_object_or_404(VinceCommContact, id=self.kwargs.get('vendor_id'))
        return context
    
    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        user_type = self.kwargs.get("type", None)
        my_group = get_object_or_404(VinceCommContact, id=self.kwargs.get('vendor_id'))
        rmuser = self.kwargs.get('uid')
        if user_type == "user":
            user = User.objects.filter(id=rmuser).first()
            if user:
                group = GroupContact.objects.filter(contact=my_group).first()
                group.group.user_set.remove(user)
                emuser = VinceCommEmail.objects.filter(email=user.username, contact=my_group).first()
                if emuser:
                    contact_update.remove_email_contact(my_group, emuser, self.request.user)
                    # is this user a groupadmin
                    logger.debug(emuser.email)
                    logger.debug(emuser.contact.vendor_name)
                    logger.debug(my_group.vendor_name)
                    admin = VinceCommGroupAdmin.objects.filter(email=emuser, contact=my_group).first()
                    logger.debug(admin)
                    if admin:
                        logger.warning("REMOVING GROUP ADMIN")
                        admin.delete()
                    admins = VinceCommGroupAdmin.objects.filter(contact=my_group)
                    for admin in admins:
                        logger.debug(f"ADMIN for {admin.contact} is {admin.email}")
                    gadmin = VinceCommGroupAdmin.objects.filter(email__email=emuser.email)
                    if gadmin == None:
                        groupadmin = Group.objects.using('vincecomm').filter(name='vince_group_admin').first()
                        user = User.objects.using('vincecomm').filter(username = ga).first()
                        if user:
                            groupadmin.user_set.remove(user)
                    emuser.delete()
                    create_action(f"{self.request.user.vinceprofile.vince_username} removed user {user.vinceprofile.vince_username}", self.request.user)
                    #is this user a groupadmin of any other vendors, if not remove groupadmin group privs

                    messages.success(
                        self.request,
                        _("The user has been removed from your group"))
                    return redirect("vinny:admin")
            messages.error(
                self.request,
                _("Error: User was not found"))
            return redirect("vinny:admin")
        elif user_type == "contact":
            user = VinceCommEmail.objects.filter(id=rmuser).first()
            if user:
                if user.contact == my_group:
                    contact_update.remove_email_contact(my_group, user, self.request.user)
                    create_action(f"{self.request.user.vinceprofile.vince_username} removed user {user.email}", self.request.user)
                    user.delete()
                    messages.success(
                        self.request,
                        _("The user has been removed from your group"))
                    return redirect("vinny:admin")
            messages.error(
                self.request,
                _("Error: User was not found"))
            return redirect("vinny:admin")
            
    
class AdminAddUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/admin.html"
    
    def test_func(self):
        if (is_in_group_vincegroupadmin(self.request.user) and PendingTestMixin.test_func(self)):
            vendor_id = self.kwargs.get('vendor_id')
            admin = VinceCommGroupAdmin.objects.filter(contact__id=vendor_id, email__email=self.request.user.email).first()
            if admin:
                return True
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        my_group = get_object_or_404(VinceCommContact, id=self.kwargs.get('vendor_id'))
        # This doesn't use the email form used in other places in the app, so we have to strip() fields here
        users = request.POST.get('adduser')
        if users:
            users = users.strip()
            try:
                validate_email(users)
            except ValidationError as e:
                return JsonResponse({'response': 'Invalid Email Address'}, status=200)
        else:
            return JsonResponse({'response': 'Invalid Email Address'}, status=200)
                
        username = request.POST.get('username')
        if username:
            username = username.strip()
        new_contact = {'email': users, 'name': username, 'email_type': 'Work', 'email_function': 'TO', 'status': True}
        context = {}
        context['group'] = my_group.vendor_name
        context['groupadmin'] =	self.request.user.username
        context['signup'] = settings.SERVER_NAME+"/vince/comm/signup/"
        context['team_signature'] = settings.DEFAULT_EMAIL_SIGNATURE
        # check if user already exists
        old_user = User.objects.filter(email__iexact=users).first()
        if old_user:
            # add user to group
            group = GroupContact.objects.filter(contact=my_group).first()
            group.group.user_set.add(old_user)
            users = old_user.email
            
        # check if email already exists
        old_email = VinceCommEmail.objects.filter(email__iexact=users, contact=my_group).first()
        if old_email:
            if old_email.email_list:
                return JsonResponse({'response':'This email has already been added as notification-only email and cannot be used for user access.'}, status=200)
            elif old_email.invited:
                if old_user:
                    send_templated_mail("vincecomm_add_existing_user", context, [users])
                    return JsonResponse({'response': 'success'}, status=200)
                else:
                    return JsonResponse({'response': 'User has already been invited.'}, status=200)
            else:
                # send email
                if old_user:
                    return JsonResponse({'response': 'User already exists.'}, status=200)
                else:
                    # actually send the invitation email to a user
                    send_templated_mail("vincecomm_add_user", context, [users])
                old_email.invited=True
                create_action("f{self.request.user.vinceprofile.vince_username} invited new user {users}", self.request.user)
                return JsonResponse({'response': 'success'}, status=200)

        new_email = VinceCommEmail(email=users,
                                   name=username,
                                   email_type='Work',
                                   email_function='TO',
                                   status=True,
                                   contact=my_group,
                                   email_list=False,
                                   invited=True)
        new_email.save()
        
        contact_update.add_email_contact(my_group, new_contact, self.request.user)

        logger.debug("SENDING MAIL")
        if old_user:
            send_templated_mail("vincecomm_add_existing_user", context, [users])
        else:
            send_templated_mail("vincecomm_add_user", context, [users])
        
        return JsonResponse({'response': 'success'}, status=200)


class ModifyEmailNotifications(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "vinny/confirm_email_change.html"

    def test_func(self):
        if (is_in_group_vincegroupadmin(self.request.user) and PendingTestMixin.test_func(self)):
            vendor_id = self.kwargs.get('vendor_id')
            admin = VinceCommGroupAdmin.objects.filter(contact__id=vendor_id, email__email=self.request.user.email).first()
            if admin:
                return True
        return False

    def post(self, request, *args, **kwargs):
        logger.debug(request.POST)
        email = get_object_or_404(VinceCommEmail, id=self.kwargs.get('uid'))
        if email.email_function in ["TO", "CC"]:
            email.email_function = "EMAIL"
            email.save()
            change = contact_update.create_contact_change(email.contact, email.email, "email notifications", "Enabled", "Disabled", self.request.user)
        else:
            email.email_function = "TO"
            email.save()
            change = contact_update.create_contact_change(email.contact, email.email, "email notifications", "Disabled", "Enabled", self.request.user)

        contact_update.send_ticket([change], email.contact, self.request.user)
        messages.success(
            self.request,
            "Got it!  Your preferences have been saved!"
        )
        return redirect("vinny:admin", email.contact.id)

    def get_context_data(self, **kwargs):
        context = super(ModifyEmailNotifications, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['adminpage']=1
        context['type'] = self.kwargs.get('type')
        if self.kwargs.get('type') == "user":
            context['user'] = get_object_or_404(User, id=self.kwargs.get('uid'))
            context['email'] = VinceCommEmail.objects.filter(email=context['user'].email, contact=self.kwargs.get('vendor_id')).first()
        elif self.kwargs.get('type') == 'email':
            context['email'] = get_object_or_404(VinceCommEmail, id=self.kwargs.get('uid'))

        if context['email'].email_function in ["TO", "CC"]:
            context['disable'] = 1
        else:
            context['enable'] = 1
            
        context['post_url'] = reverse("vinny:changeemail", args=[self.kwargs.get('vendor_id'), 'email', context['email'].id])
        return context    

class MultipleStatusView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/multi_status.html"
    login_url = "vinny:login"

    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def dispatch(self, request, *args, **kwargs):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        groups = _my_groups_for_case(self.request.user, case)
        if len(groups) == 1:
            return redirect("vinny:status", self.kwargs['pk'])
        else:
            return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super(MultipleStatusView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        context['case'] = case
        context['groups'] = _my_groups_for_case(self.request.user, case)
        return context

    
class MultipleContactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/multi_contact.html"
    login_url = "vinny:login"

    def test_func(self):
        self.contacts = _my_contact_group(self.request.user)
        if len(self.contacts) > 0:
            return True and PendingTestMixin.test_func(self)
        else:
            # this user does not belong to a group with contact info
            return False

    def get_context_data(self, **kwargs):
        context = super(MultipleContactView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['contacts'] = _my_contact_group(self.request.user)
        context['contactpage']=1
        return context


class MultipleGroupAdminView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/multi_admin.html"
    login_url = "vinny:login"

    def test_func(self):
        if is_in_group_vincegroupadmin(self.request.user):
            self.ga_groups = VinceCommGroupAdmin.objects.filter(email__email=self.request.user.email)
            if len(self.ga_groups) > 0:
                return True and PendingTestMixin.test_func(self)
        return False
        
    def get_context_data(self, **kwargs):
        context = super(MultipleGroupAdminView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['groups'] = VinceCommGroupAdmin.objects.filter(email__email=self.request.user, contact__vendor_type__in=["Coordinator", "Vendor"], contact__active=True)
        
        context['adminview']=1
        return context

    
class ContactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vinny/contact.html'
    login_url="vinny:login"

    def test_func(self):
        if len(self.contacts) > 0:
            if self.kwargs.get('vendor_id'):
                contact = VinceCommContact.objects.filter(id=self.kwargs.get('vendor_id')).first()
                admin = VinceCommGroupAdmin.objects.filter(contact__id=self.kwargs.get('vendor_id'), email__email=self.request.user.email).first()
                return admin and _user_in_contact(self.request.user, contact) and PendingTestMixin.test_func(self)
            return PendingTestMixin.test_func(self)
        else:
            # this user does not belong to a group with contact info
            return False

    def dispatch(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            self.contacts = _my_contact_group(self.request.user)
            if self.kwargs.get('vendor_id'):
                return super().dispatch(request, *args, **kwargs)
            if len(self.contacts) > 1:
                return redirect("vinny:multiple_contacts")

        return super().dispatch(request, *args, **kwargs)

        
    def get_context_data(self, **kwargs):
        context = super(ContactView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        if self.kwargs.get('vendor_id'):
            context['object'] = VinceCommContact.objects.filter(id=self.kwargs.get('vendor_id')).first()
            context['vince_users'] = _users_in_group(context['object'])
        else:
            context['object'] = _my_contact_group(self.request.user)[0]
            context['vince_users'] = _users_in_group(context['object'])

        ga = VinceCommGroupAdmin.objects.filter(contact=context['object']).values_list('email__email', flat=True)
        # check if User exists
        if ga:
            context['gadmins'] = User.objects.filter(username__in=ga)

        context['gc'] = GroupContact.objects.filter(contact=context['object']).first()
        context['contactpage']=1
        return context
    
class InboxView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.TemplateView):
    template_name = "vinny/inbox.html"
    login_url="vinny:login"

    def get_context_data(self, **kwargs):
        context = super(InboxView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        sentthreads = Thread.ordered(Thread.deleted(self.request.user))
        threads = Thread.ordered(Thread.inbox(self.request.user))
        folder = "inbox"
        page = 1
        paginator = Paginator(threads, 10)
        sent_paginator = Paginator(sentthreads, 10)
        context.update({
            "folder": folder,
            "threads": paginator.page(page),
            "sentthreads": sent_paginator.page(page),
            
        })
        #"threads_unread": Thread.ordered(Thread.unread(self.request.user))
        context['form'] = InboxFilterForm()
        context['inboxpage'] = 'yes'
       	#check config
        admin_group_name = settings.COGNITO_ADMIN_GROUP
        #Does this group exist
        admin_group = Group.objects.using('vincecomm').filter(groupcontact__contact__vendor_name=settings.COGNITO_ADMIN_GROUP).first()
        if admin_group == None:
            messages.error(
		self.request,
                _(f"VINCE is not correctly configured. ADMIN GROUP {settings.COGNITO_ADMIN_GROUP} does not exist."))
        return context

class SearchThreadsView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.ListView):
    login_url = "vinny:login"
    template_name = "vinny/include/threads.html"

    def get_queryset(self):
        return Thread.ordered(Thread.inbox(self.request.user))

    def get_context_data(self, **kwargs):
        context = super(SearchThreadsView, self).get_context_data(**kwargs)
        sentthreads = Thread.ordered(Thread.deleted(self.request.user))
        page = self.request.GET.get('page', 1)
        sent_paginator = Paginator(sentthreads, 10)
        context['threads'] = sent_paginator.page(page)
        context['page_class'] = "searchsent"
        return context
    
    def post(self, request, *args, **kwargs):
        # logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        page = self.request.POST.get('page', 1)
        
        status = self.request.POST.getlist('status')

        res = Thread.none()
        if len(status) == 3:
            # all options selected, so we just give them everything but distinct()
            res = Thread.all(self.request.user).distinct()
        elif len(status) >= 1:
            # we have one or more options selected (but not all three, handled above)
            # note: ordering here is specific: If user selects read and unread, we need unread to be True at filter
            status = sorted(status)
            if '1' in status:
                res = res.union(Thread.read(self.request.user))
            if '2' in status:
                res = res.union(Thread.unread(self.request.user))
            if '3' in status:
                res = res.union(Thread.deleted(self.request.user))
        else:
            # nothing selected, give them the inbox view
            res = Thread.inbox(self.request.user)

        keyword = self.request.POST.get('keyword')
        if keyword:
            res = res.filter(Q(messages__content__icontains=self.request.POST['keyword']) | Q(subject__icontains=self.request.POST['keyword'])).distinct()

        res = Thread.ordered(res)
        paginator = Paginator(res, 10)
        
        return render(request, self.template_name, {'threads': paginator.page(page), 'empty_msg': "No threads match that filter", 'page_class':"search_notes"})


class MyReportsFilterView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.ListView):
    login_url = "vinny:login"
    template_name = "vinny/include/reports.html"

    def get_queryset(self):
        return VTCaseRequest.objects.filter(user=self.request.user).order_by('-date_submitted')
    
    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        page = self.request.POST.get('page', 1)
        res = self.get_queryset()
        status_list = self.request.POST.getlist('status[]')
        if status_list:
            logger.debug(status_list)
            res = res.filter(status__in=status_list)
            
        if self.request.POST['keyword'] != '':
            wordSearch = process_query(self.request.POST['keyword'])
            res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[wordSearch])
        logger.debug(res)
        res = res.order_by('-date_submitted')
        paginator = Paginator(res, 10)

        return render(request, self.template_name, {'object_list': paginator.page(page), 'total': len(res) })            

class LimitedAccessSearch(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    login_url = "vinny:login"
    template_name = "vinny/include/cases.html"

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) or is_in_group_vincelimited(self.request.user)

    def get_queryset(self):
        return Case.objects.all().order_by('-modified')

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        page = self.request.POST.get('page', 1)
        res = self.get_queryset()
        status_list = self.request.POST.getlist('status')

        if 'status' in self.request.POST:
            statuslist = self.request.POST.getlist('status')
            if '3' in statuslist:
                res = res.exclude(note__datefirstpublished__isnull=True)
            if '3' in statuslist:
                statuslist.remove('3')
            if statuslist:
                res = res.filter(status__in=statuslist)

        if 'wordSearch' in self.request.POST:
            if self.request.POST['wordSearch']:
                wordSearch = process_query(self.request.POST['wordSearch'])
                res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[wordSearch])

        paginator = Paginator(res, 10)

        return render(request, self.template_name, {'cases': paginator.page(page), 'total': len(res), 'limitedaccess':1 })
    
class DashboardCaseView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.ListView):
    login_url = "vinny:login"
    template_name = "vinny/include/cases.html"

    def get_queryset(self):
        if self.request.user.is_superuser:
            return Case.objects.all().order_by('-modified')
        my_cases = _get_my_cases(self.request.user)
        return my_cases.order_by('-modified')

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        page = self.request.POST.get('page', 1)
        my_cases = self.get_queryset()
        owner_list = self.request.POST.getlist('owner')
        logger.debug(owner_list)
        res = my_cases
        if owner_list:
            coordinators = CaseCoordinator.objects.filter(assigned__id__in=owner_list).values_list('case', flat=True)
            res = res.filter(id__in=coordinators)
        
        if self.request.POST.get('keyword'):
            if self.request.POST['keyword'] != "":
                wordSearch = process_query(self.request.POST['keyword'])
                res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[wordSearch])
                #search posts
                post_result = PostRevision.objects.filter(post__case__in=my_cases).extra(where=["search_vector @@ (to_tsquery('english', %s))=true"], params=[wordSearch]).values_list('post__case', flat=True)
                if post_result:
                    extra_cases = Case.objects.filter(id__in=post_result).exclude(id__in=res)
                    res = list(chain(res, extra_cases))

        paginator = Paginator(res, 10)
        return render(request, self.template_name, {'cases': paginator.page(page), 'total': len(res)})
        
    
class MessageView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.RedirectView):
    login_url = "vinny:login"

    def dispatch(self, request, *args, **kwargs):
        msg = get_object_or_404(Message, id=self.kwargs['pk'])
        self.thread = msg.thread.id
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, **kwargs):
        return reverse('vinny:thread_detail', args=[self.thread])

class MessagesView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.DetailView):
    login_url = "vinny:login"
    context_object_name = "thread"
    model=Thread
    template_name='vinny/messages.html'

    def get_queryset(self):
        qs = super(MessagesView, self).get_queryset()
        qs = qs.filter(userthread__user=self.request.user).distinct()
        return qs

    def get_context_data(self, **kwargs):
        context = super(MessagesView, self).get_context_data(**kwargs)
        context['thread'] = self.object
        return context
    
class ThreadView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.UpdateView):
    """
    View a single Thread or POST a reply.
    """
    model = Thread
    form_class = MessageReplyForm
    login_url = "vinny:login"
    context_object_name = "thread"
    template_name = "vinny/thread_detail.html"
    success_url = reverse_lazy("vinny:messages")

    def get_success_url(self):
        return reverse_lazy("vinny:messages", args=[self.object.thread.id])
    
    def dispatch(self, *args, **kwargs):
        return super(ThreadView, self).dispatch(*args, **kwargs)

    def get_queryset(self):
        qs = super(ThreadView, self).get_queryset()
        qs = qs.filter(userthread__user=self.request.user).distinct()
        return qs

    def form_valid(self, form):
        files = [self.request.FILES.get('attachment[%d]' % i) for i in range (0, len(self.request.FILES))]
        logger.debug(files)
        self.object = form.save(files=files)
        return redirect(self.get_success_url())

    def get_form_kwargs(self):
        kwargs = super(ThreadView, self).get_form_kwargs()
        kwargs.update({
            "user": self.request.user,
            "thread": self.object
        })
        return kwargs

    def get_context_data(self, **kwargs):
        context = super(ThreadView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['inboxpage'] = 'yes'
        return context
    
    def get(self, request, *args, **kwargs):
        response = super(ThreadView, self).get(request, *args, **kwargs)
        self.object.userthread_set.filter(user=request.user).update(unread=False)
        return response

class ThreadDeleteView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.DeleteView):
    """
    Delete a thread.
    """
    model = Thread
    success_url = reverse_lazy("vinny:inbox")
    template_name = "vinny/thread_confirm_delete.html"
    login_url = "vinny:login"

    def dispatch(self, *args, **kwargs):
        return super(ThreadDeleteView, self).dispatch(*args, **kwargs)

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        success_url = self.get_success_url()
        self.object.userthread_set.filter(user=request.user).update(deleted=True)
        return HttpResponseRedirect(success_url)

class GroupChatView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.CreateView):
    template_name = 'vinny/sendmsguser.html'
    login_url = "vinny:login"
    form_class = SendMessageUserForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and PendingTestMixin.test_func(self)

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        response =  super().form_invalid(form)
        response.status_code=400
        return response
    
    def form_valid(self, form):
        logger.debug(self.request.POST)
        form.cleaned_data['to_group'] = self.request.POST.getlist("taggles_group[]")
        files = [self.request.FILES.get('attachment[%d]' % i) for i in range (0, len(self.request.FILES))]
        ticket = form.save(files)
        messages.success(
            self.request,
            _("Your message has been sent"))
        return JsonResponse({'response': 'success'}, status=200)

    def get_context_data(self, **kwargs):
        context = super(GroupChatView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['inbox'] = 'yes'
        context['title'] = "Start Private Group Thread"
        if self.kwargs.get("case_id"):
            case = Case.objects.filter(id=self.kwargs.get("case_id")).first()
            context['case'] = case
            members = _groupchat_case_participants(case)
            context['assignable'] = [contact["label"] for contact in members]
            context["action"] = reverse("vinny:groupchatcase", args=[self.kwargs.get("case_id")])
        return context

    def get_initial(self):
        case_id = self.kwargs.get("case_id", None)
        if case_id:
            cases = Case.objects.filter(id=case_id)
        else:
            cases = _my_active_cases(self.request.user)
        return {'case': [(q.id, q.get_title) for q in cases]}
    

    def get_form_kwargs(self):
        kwargs = super(GroupChatView, self).get_form_kwargs()
        kwargs.update({
            "user": self.request.user,
            "privgroupchat": True
        })
        return kwargs


class SendMessageAllView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.CreateView):
    template_name = "vinny/sendmessage_all.html"
    login_url = "vinny:login"
    form_class = SendMessageAllForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user) and self.request.user.is_superuser

    def form_invalid(self, form):
        logger.debug(form.errors)
        return JsonResponse({'response': 'invalid'}, status=400)

    def form_valid(self, form):
        logger.debug(self.request.POST)
        ticket = form.save(self.request.user)
        messages.success(
            self.request,
            _("Your message has been sent."))
        return redirect("vinny:inbox")

    def get_initial(self):
        my_teams = self.request.user.groups.filter(groupcontact__vincetrack=True)
        return {'from_group': [(q.id, q.groupcontact.contact.vendor_name) for q in my_teams]}
    
    def get_context_data(self, **kwargs):
        context = super(SendMessageAllView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['inbox'] = 'yes'
        context['action'] = reverse("vinny:sendmsgall")
        return context
    
class SendMessageUserView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.CreateView):
    template_name = "vinny/sendmsguser.html"
    login_url = "vinny:login"
    form_class = SendMessageUserForm

    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def form_invalid(self, form):
        logger.debug(form.errors)
        return JsonResponse({'response': 'invalid'}, status=400)
    
    def form_valid(self, form):
        files = [self.request.FILES.get('attachment[%d]' % i) for i in range (0, len(self.request.FILES))]
        form.cleaned_data['to_user'] = self.request.POST.getlist("taggles[]")
        form.cleaned_data['to_group'] = self.request.POST.getlist("taggles_group[]")
        ticket = form.save(files)

        return JsonResponse({'response': 'success', 'url': reverse("vince:dashboard")}, status=200)

    def get_context_data(self, **kwargs):
        context = super(SendMessageUserView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['inbox'] = 'yes'
        if self.kwargs.get("user_id"):
            context['action'] = reverse("vinny:sendmsgus", args=[self.kwargs.get("user_id")])
            context['user_tags'] = [x.email for x in User.objects.filter(id=self.kwargs.get("user_id"))]
        elif self.kwargs.get("group_id"):
            context['action'] = reverse("vinny:sendmsggroup", args=[self.kwargs.get("group_id")])
            g = Group.objects.filter(groupcontact__contact__vendor_id=self.kwargs.get('group_id'))
            context['group_tags'] = [x.groupcontact.contact.vendor_name for x in g]
            context['vendor_emails'] = list(User.objects.filter(groups__in=g).values_list('email', flat=True))
        elif self.kwargs.get("admin_id"):
            context['action'] = reverse("vinny:sendmsguser")
            context['user_tags'] = [x.email.email for x in VinceCommGroupAdmin.objects.filter(contact__vendor_id=self.kwargs.get('admin_id'))]
        else:
            context["action"] = reverse("vinny:sendmsguser")
            
        return context

    def get_initial(self):
        user_id = self.kwargs.get("user_id", None)
        group_id = self.kwargs.get("group_id", None)
        case = self.kwargs.get('case', None)
        if user_id is not None:
            user_id = [int(user_id)]
        elif "to_user" in self.request.GET and self.request.GET["to_user"].isdigit():
            user_id = map(int, self.request.GET.getlist("to_user"))
        if not self.kwargs.get("multiple", False) and user_id:
            user_id = user_id[0]
        if group_id is not None:
            group_id = int(group_id)
        if case == None:
            if user_id:
                case = [('', '--------')] + [(q.id, q.get_title) for q in _my_cases(User.objects.get(id=user_id))]
            elif group_id:
                case = [('', '--------')] + [(q.id, q.get_title) for q in _cases_for_group(Group.objects.filter(groupcontact__contact__vendor_id=group_id).first())]
            else:
                case = [('', '--------')] + [(q.id, q.get_title) for q in _my_cases(self.request.user)]
        else:
            case = [('', '--------')] + [(q.id, q.get_title) for q in Case.objects.filter(vuid=case)]
        return {'case': case,
                'group_admin': [(q.id, q.username) for q in _users_in_my_group(self.request.user)],
                'to_user': user_id,
                'to_group': group_id}

    def get_form_kwargs(self):
        kwargs = super(SendMessageUserView, self).get_form_kwargs()
        kwargs.update({
            "user": self.request.user,
            "privgroupchat": False
        })
        return kwargs


class SendMessageView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.CreateView):
    template_name = "vinny/sendmsg.html"
    login_url = "vinny:login"
    form_class = SendMessageForm
    
    def form_valid(self, form):
        logger.debug("IN FORM VALID")
        files = [self.request.FILES.get('attachment[%d]' % i) for i in range (0, len(self.request.FILES))]
        logger.debug(files)
        ticket = form.save(files)
        
        logger.debug(self.request.POST)
        messages.success(
            self.request,
            _("Your message has been sent."))
        return JsonResponse({'response': 'success'}, status=200)

    def get_context_data(self, **kwargs):
        context = super(SendMessageView, self).get_context_data(**kwargs)
        context['group_admin'] = _my_group_admin(self.request.user)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['msgtype'] = self.kwargs.get('type', 1)
        logger.debug(CaseMember.objects.filter(case__id=self.kwargs.get('case'), coordinator=True).exclude(group__groupcontact__vincetrack=False).values_list('group__groupcontact__contact__vendor_name', flat=True))
        try:
            if self.kwargs.get('case'):
                members = list(CaseMember.objects.filter(case__id=self.kwargs.get('case'), coordinator=True).exclude(group__groupcontact__vincetrack=False).values_list('group__groupcontact__contact__vendor_name', flat=True))
                members = [i for i in members if i]
                context['coord'] = ", ".join(members)
        except:
            pass

        #check config
        admin_group_name = settings.COGNITO_ADMIN_GROUP
        #Does this group exist
        admin_group = Group.objects.using('vincecomm').filter(groupcontact__contact__vendor_name=settings.COGNITO_ADMIN_GROUP).first()
        if admin_group == None:
            messages.error(
		self.request,
                _(f"VINCE is not correctly configured for sending direct messages. ADMIN group {settings.COGNITO_ADMIN_GROUP} does not exist."))
        return context
    
    def get_initial(self):
        return {'case': [(q.id, q.get_title) for q in _my_cases(self.request.user)],
                'report':[(q.id, q.get_title) for q in _my_reports(self.request.user)],
                'subject': self.kwargs.get('type', 1),
                'select_case': self.kwargs.get('case', None)}

    def get_form_kwargs(self):
        kwargs = super(SendMessageView, self).get_form_kwargs()
        kwargs.update({
            "user": self.request.user,
        })
        return kwargs


class PostCaseView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.RedirectView):
    login_url = "vinny:login"

    def dispatch(self, request, *args, **kwargs):
        post = get_object_or_404(Post, id=self.kwargs['pk'])
        self.case = post.case.id
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, **kwargs):
        return reverse('vinny:case', args=[self.case])

class VinceCaseView(LoginRequiredMixin, generic.RedirectView):
    login_url = "vinny:login"

    def dispatch(self, request, *args, **kwargs):
        case = get_object_or_404(Case, vince_id=self.kwargs['pk'])
        self.case = case.id
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, **kwargs):
        return reverse('vinny:case', args=[self.case])


class GetStatementView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/statement.html"
    login_url = "vinny:login"

    def test_func(self):
        self.case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def get_context_data(self, **kwargs):
        context = super(GetStatementView, self).get_context_data(**kwargs)
        context['case'] = self.case
        case_member = self.kwargs['member']
        context['case_member'] = CaseMember.objects.filter(id=case_member).first()
        context['statement'] = CaseStatement.objects.filter(member=case_member, case=self.case).first()
        context['status'] = CaseMemberStatus.objects.filter(member=case_member, vulnerability__case=self.case)
        return context

class ContactAddLogoView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    form_class = UploadLogoForm
    template_name = 'vinny/contact.html'

    def test_func(self):
        if self.kwargs.get('vendor_id'):
            self.contact = VinceCommContact.objects.filter(id=self.kwargs.get('vendor_id')).first()
            logger.debug(self.contact)
            return _user_in_contact(self.request.user, self.contact) and PendingTestMixin.test_func(self)
        else:
            # this user does not belong to a group with contact info 
            return False

    def get_form_kwargs(self):
        kwargs = super(ContactAddLogoView, self).get_form_kwargs()
        kwargs.update({
            "contact": get_object_or_404(VinceCommContact, id=self.kwargs.get('vendor_id')),
            "user": self.request.user
        })
        return kwargs

    def form_valid(self, form):
        file = self.request.FILES.get('file')
        if self.request.POST.get('delete'):
            doc = form.save()
        else:
            doc = form.save(file=file)
        return JsonResponse({'response': 'success'}, status=200)
    #return redirect('vinny:contact', self.kwargs['vendor_id'])


class ReportDocumentCreateView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    model = ReportAttachment
    template_name = 'vinny/addreportfile.html'
    form_class = UploadFileForm

    def test_func(self):
        self.report = get_object_or_404(VTCaseRequest, id=self.kwargs['pk'])
        return _is_my_report(self.request.user, self.report) and PendingTestMixin.test_func(self)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['report'] = self.report
        context['title'] = "Upload File to Report"
        return context

    def get_form_kwargs(self):
        kwargs = super(ReportDocumentCreateView, self).get_form_kwargs()
        kwargs.update({
            "report": get_object_or_404(VTCaseRequest, id=self.kwargs['pk']),
            "user": self.request.user
        })
        return kwargs

    def form_valid(self, form):
        doc = form.save()
        messages.success(
            self.request,
	    _("Your file was successfully uploaded."))
        vince_comm_send_sqs("NewFile", "CaseRequestArtifact", self.report.vrf_id,
                            self.request.user.username, None, "Reporter Uploaded File")
        return redirect('vinny:cr_report', self.kwargs['pk'])
    
class CaseDocumentCreateView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    model = VinceCommCaseAttachment
    template_name = 'vinny/addfile.html'
    form_class = UploadDocumentForm
    
    def test_func(self):
        self.case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['case'] = self.case
        context['title'] = "Upload File to Case"
        return context

    def get_form_kwargs(self):
        kwargs = super(CaseDocumentCreateView, self).get_form_kwargs()
        kwargs.update({
            "case": get_object_or_404(Case, id=self.kwargs['pk']),
            "user": self.request.user
        })
        return kwargs

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)
    
    def form_valid(self, form):
        doc = form.save()
        vince_comm_send_sqs("NewFile", "CaseArtifact", self.case.vuid,
                            self.request.user.username, None, "Vendor Uploaded File")
        return redirect('vinny:case', self.kwargs['pk'])

class CaseAddTrackingView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    model = CaseTracking
    template_name = 'vinny/addtracking.html'
    form_class = AddTrackingForm

    def test_func(self):
        self.case = get_object_or_404(Case, id=self.kwargs['pk'])
        test = _is_my_case(self.request.user, self.kwargs['pk'])
        if test:
            return PendingTestMixin.test_func(self)
        else:
            return False

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['case'] = self.case
        context['title'] = "Add Tracking Number to Case"
        return context

    def get_form(self):
        try:
            my_group = _my_group_id_for_case(self.request.user, self.case)
            ct = CaseTracking.objects.get(case=self.case, group=my_group)
            return self.form_class(instance=ct, **self.get_form_kwargs())
        except CaseTracking.DoesNotExist:
            return self.form_class(**self.get_form_kwargs())
    
    def get_form_kwargs(self):
        kwargs = super(CaseAddTrackingView, self).get_form_kwargs()
        kwargs.update({
            "case": self.case,
            "user": self.request.user,
            "group": _my_group_id_for_case(self.request.user, self.case)
            
        })
        return kwargs

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        doc = form.save()
        context = {}
        context['vuid'] = self.case.vu_vuid
        context['tracking'] = form.cleaned_data['tracking']
        try:
            if self.case.team_owner.coordinatorsettings.team_signature:
                context['team_signature']= self.case.team_owner.coordinatorsettings.team_signature
            else:
                context['team_signature']= self.DEFAULT_EMAIL_SIGNATURE
        except:
            context['team_signature']= self.DEFAULT_EMAIL_SIGNATURE
            
        if context['tracking']:
            send_templated_mail("new_tracking", context, [self.request.user.email])
        return redirect('vinny:case', self.kwargs['pk'])
        
class UserCardView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.DetailView):
    template_name = 'vinny/usercard.html'
    model = VinceProfile

    def get_object(self):
        return VinceProfile.objects.get(user__id=self.kwargs['id'])

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.GET.get('quick'):
            context['template'] = 'vince/card.html'
        else:
            context['template'] = settings.VINCECOMM_BASE_TEMPLATE
            context['full'] = 1
        return context

class GroupCardView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.DetailView):
    template_name = 'vinny/groupcard.html'
    model = GroupContact

    def get_object(self):
        return GroupContact.objects.get(group__id=self.kwargs['id'])

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.kwargs.get('case') and self.get_object().default_access == False:
            groupcontact = self.get_object()
            admins = list(VinceCommGroupAdmin.objects.filter(contact=groupcontact.contact.id).values_list('email__email', flat=True))
            casemember = CaseMember.objects.filter(case=self.kwargs.get('case'), group=groupcontact.group.id).first()
            emails = list(CaseMemberUserAccess.objects.filter(casemember=casemember).values_list('user__email', flat=True))
            emails = emails + admins
            context['case'] = User.objects.filter(email__in=emails).exclude(vinceprofile__service=True)
        if self.request.GET.get('quick'):
            context['template'] = 'vince/card.html'
        else:
            context['template'] = settings.VINCECOMM_BASE_TEMPLATE
            context['full'] = 1
        return context
    
class CaseRequestView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    template_name = 'vinny/cr.html'
    model = VTCaseRequest

    def test_func(self):
        self.case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def get_object(self):
        return self.case.cr
    
class VulNoteView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    template_name = 'vincepub/vudetailnew.html'
    model = VCVUReport
    
    def test_func(self):
        self.case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def get_object(self):
        return self.case.note
    
    def get_context_data(self, **kwargs):
        context = super(VulNoteView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['draft'] = True
        return context


class LoadVendorsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/allvendors.html"
    login_url="vinny:login"

    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def get_context_data(self, **kwargs):
        context = super(LoadVendorsView, self).get_context_data(**kwargs)
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        try:
            context['vendors'] = CaseMember.objects.filter(case=case, coordinator=False, reporter_group=False).order_by("group__groupcontact__contact__vendor_name")[5:]
        except:
            logger.debug("GOT EXCEPTION ON VENDOR NAME ORDERING")
            context['vendors'] = CaseMember.objects.filter(case=case, coordinator=False, reporter_group=False).order_by("group__name")[5:]
        context['case'] = case
        return context
    

class JsonVendorsView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/allvendors.html"
    login_url="vinny:login"

    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def get(self, request, *args, **kwargs):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        members = _case_participants(case)
        data = json.dumps(members)
        mimetype='application/json'
        return HttpResponse(data, mimetype)
    
class CaseView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/case.html"
    login_url="vinny:login"

    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        if self.kwargs.get('vendor'):
            cm = get_object_or_404(CaseMember, id=self.kwargs['vendor'])
            return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self) and self.request.user.is_staff
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)
    
    def get_context_data(self, **kwargs):
        context = super(CaseView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        #content = VendorNotificationContent.objects.filter(case=case).first()
        context['case'] = case
        context['casepage']=1
        context['today'] = timezone.now
        #context['content'] = content
        vuls = []
        if is_in_group_vincetrack(self.request.user):
            context['vincetrack'] = True

        vuls = CaseVulnerability.objects.filter(case=case)
        context['vuls'] = vuls
        try:
            context['vendors'] = CaseMember.objects.filter(case=case, coordinator=False, reporter_group=False).order_by("group__groupcontact__contact__vendor_name")
        except:
            logger.debug("GOT EXCEPTION ON VENDOR NAME ORDERING")
            context['vendors'] = CaseMember.objects.filter(case=case, coordinator=False, reporter_group=False).order_by("group__name")
        context['num_vendors'] = context['vendors'].count()

#        context['participants'] = User.objects.filter(groups__name=case.vuid)
        context['participants'] = CaseMember.objects.filter(case=case, participant__isnull=False, coordinator=False) | CaseMember.objects.filter(case=case, coordinator=False, reporter_group=True).order_by('added')
        context['coordinators'] = CaseMember.objects.filter(case=case, coordinator=True).order_by('added')
        context['form'] = PostForm()
        context['editform'] = EditPostForm()
        context['attachments'] = VinceCommCaseAttachment.objects.filter(action__case=case)

        threaded_posts = ThreadedPost.objects.filter(case=case).values_list('id', flat=True)
        posts = Post.objects.filter(case=case, pinned=False).exclude(id__in=threaded_posts).order_by('-created')
        context['num_posts'] = posts.count()
        p = Paginator(posts, 10)
        context['posts'] = p.page(1)
        context['paginate_by'] = 10

        context['pinned_posts'] = Post.objects.filter(case=case, pinned=True).order_by('created')
        context['total_posts'] = posts.count() + context['pinned_posts'].count()

        if len(context['posts']) == 0 and len(context['pinned_posts']) == 0:
            context['first_post'] = True

        context['case_muted'] = False
        if self.request.user.vinceprofile.settings.get('muted_cases'):
            muted_cases = self.request.user.vinceprofile.settings['muted_cases']
            if case.id in muted_cases:
                context['case_muted'] = True

        context['vendors'] = context['vendors'][:6]
        #what group am I in?
        if self.kwargs.get('vendor') and self.request.user.is_staff:
            # simulating another vendor's access to this case
            cm = get_object_or_404(CaseMember, id=self.kwargs['vendor'])
            group = cm.group.name
            if len(vuls) == 0:
                context['showstatus'] = False
            else:
                context['showstatus'] = True
            context['status'] = CaseMemberStatus.objects.filter(member=cm)
            if len(context['status']) == len(context['vuls']):
                context['showupdatestatus'] = True
            else:
                context['showupdatestatus'] = False
            context['tracking'] = CaseTracking.objects.filter(case=case, group=cm.group).first()
            context['auto_members'] = [] #_case_participants(case)[:50]
            context['simulation'] = cm

            return context

        group = _my_group_for_case(self.request.user, case)
        if len(vuls)==0 or is_in_group_vincetrack(self.request.user):
            context['showstatus'] = False
        else:
            if group:
                context['showstatus'] = True
                # else this is a participant/coordinator
            else:
                context['showstatus'] = False

        context['showupdatestatus'] = False
        if group:
            #show tracking id bc this user is a vendor
            context['showtracking'] = True
            if is_in_group_vincetrack(self.request.user):
                # coordinators dont need this
                context['showtracking'] = False

        #this should return all vendors/coordinators/reporter groups
        members = _my_groups_for_case(self.request.user, case)
        if members:
            if len(members) > 1:
                #if this person belongs to more than 1 vendor, don't present them with the form, make them
                #choose which vendor to submit status for
                context['multivendor'] = True
            else:
                context['tracking'] = CaseTracking.objects.filter(case=case, group=_my_group_id_for_case(self.request.user, case)).first()

        for member in members:
            if member.seen == False:
                create_action(f"{member.group.groupcontact.contact.vendor_name} viewed case {case.vu_vuid}", self.request.user, case) 
                vince_comm_send_sqs("VendorLogin", "CaseMemberStatus", case.vuid,
                                    self.request.user.username, member.group.name, "Vendor Viewed Case")
                member.seen = True
                member.save()
            if not context['showupdatestatus']:
                context['status'] = CaseMemberStatus.objects.filter(member=member)
                if len(context['status']) == len(context['vuls']):
                    context['showupdatestatus'] = True
                else:
                    context['showupdatestatus'] = False

        #this person could be a participant and a vendor
        member = CaseMember.objects.filter(case=case, participant=self.request.user).first()
        if member:
            if member.seen ==False:
                create_action(f"Case Participant viewed case {case.vu_vuid}", self.request.user, case) 
                vince_comm_send_sqs("VendorLogin", "CaseParticipant", case.vuid,
                                    self.request.user.username, "None", "Participant Viewed Case")
                member.seen = True
                member.save()

        #only return first 50 for faster loading
        context['auto_members'] = [] #_case_participants(case)[:50]
        #what's the last date this person viewed this case
        lv = CaseViewed.objects.filter(case=case, user=self.request.user).first()
        if lv:
            context['last_viewed'] = lv.date_viewed
            context['unseen_posts'] = Post.objects.filter(case=case, created__gte=lv.date_viewed).exclude(author=self.request.user).count()
            if context['unseen_posts']:
                posts_after = context['unseen_posts']
                unread = Post.objects.filter(case=case, created__gte=lv.date_viewed).exclude(author=self.request.user)
                #are any of these replies
                thread_unread = ThreadedPost.objects.filter(id__in=unread).order_by('created').first()
                first_unread = unread.order_by('created').first()
                if thread_unread:
                    if thread_unread.parent.created < first_unread.created:
                        first_unread = thread_unread.parent
                #get number of posts after this date
                posts_after = Post.objects.filter(case=case, created__gte=first_unread.created).count()
                    
                if posts_after > 10:
                    p = Paginator(posts, posts_after)
                    context['posts'] = p.page(1)
                    context['paginate_by'] = posts_after

        cviewed, created = CaseViewed.objects.update_or_create(case=case, user=self.request.user,
                                                               defaults={'date_viewed':timezone.now})
        if created:
            # if just created, this is the first time user is viewing case
            # show vul disclosure policy
            context['show_vul_policy'] = 1


        return context


def create_vendor_status_change(field, old_value, new_value, user, member, cv=None, case=None):
    if cv:
        action = VendorAction(title=f"{user.vinceprofile.vince_username} modified {field} for {cv.vul}",
                              user=user, member=member)
        action.case=cv.case
    elif case:
        action = VendorAction(title=f"{user.vinceprofile.vince_username} modified {field} for {case.vu_vuid}",
                              user=user, member=member)
        action.case=case
        
    action.save()

    change = VendorStatusChange(field=field,
                                old_value=old_value,
                                new_value=new_value,
                                action=action)
    if cv:
        change.vul=cv
    
    change.save()
    return change
    
def update_status(member, request, vulid=None, affected=[], unknown=[], unaffected=[]):

    try:
        affected = request.POST.getlist('affected', affected)
        unknown = request.POST.getlist('unknown', unknown)
        unaffected = request.POST.getlist('unaffected', unaffected)
    except:
        #API doesn't allow reading request.POST a second time, just ignore bc we're passing in lists
        pass

    if affected:
        for vul in affected:
            cv = CaseVulnerability.objects.filter(id=int(vul)).first()
            old_status = CaseMemberStatus.objects.filter(member=member, vulnerability=cv).first()
            if old_status:
                if old_status.status != 1:
                    create_vendor_status_change("status", old_status.status, 1, request.user, member, cv)
            else:
                create_vendor_status_change("status", None, 1, request.user, member, cv)
            status, created = CaseMemberStatus.objects.update_or_create(member=member, vulnerability=cv,
                                                                        defaults={'status':1, 'user':request.user,
                                                                                  'approved':False})
    if unknown:
        for vul in unknown:
            cv = CaseVulnerability.objects.filter(id=int(vul)).first()
            old_status = CaseMemberStatus.objects.filter(member=member, vulnerability=cv).first()
            if old_status:
                if old_status.status != 3:
                    create_vendor_status_change("status", old_status.status, 3, request.user, member, cv)
            else:
                create_vendor_status_change("status", None, 3, request.user, member, cv)
            status, created = CaseMemberStatus.objects.update_or_create(member=member, vulnerability=cv,
                                                                        defaults={'status':3, 'user':request.user,
                                                                                  'approved': False})
    if unaffected:
        for vul in unaffected:
            cv = CaseVulnerability.objects.filter(id=int(vul)).first()
            old_status = CaseMemberStatus.objects.filter(member=member, vulnerability=cv).first()
            if old_status:
                if old_status.status != 2:
                    create_vendor_status_change("status", old_status.status, 2, request.user, member, cv)
            else:
                create_vendor_status_change("status", None, 2, request.user, member, cv)
            
            status, created = CaseMemberStatus.objects.update_or_create(member=member, vulnerability=cv,
                                                               defaults={'status':2, 'user':request.user, 'approved':False})
                 
    vince_comm_send_sqs("UpdateStatus", "Case", member.case.vuid, request.user.username, member.group.name, f"Vendor {member.group.groupcontact.contact.vendor_name} updated Statement")

    return

class UpdateStatusView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/updatestatus.html"
    login_url="vinny:login"

    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        group = _my_group_for_case(self.request.user, case)
        member = CaseMember.objects.filter(case=case, group__name=group).first()
        if not member:
            return HttpResponse(status=404)

        affected = []
        unaffected=[]
        unknown=[]
        try:
            for k,v in self.request.POST.items():
                if k.startswith('status'):
                    vul_id = int(k.split('_')[1])
                    logger.debug(vul_id)
                    if v == "affected":
                        affected.append(vul_id)
                    elif v == "unaffected":
                        unaffected.append(vul_id)
                    else:
                        unknown.append(vul_id)
        except:
            pass
        update_status(member, self.request, affected=affected, unaffected=unaffected, unknown=unknown)

        return JsonResponse({'response': 'success'}, status=200)


class MuteCaseView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vinny/mutecase.html'
    login_url = "vinny:login"

    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        user = self.request.user
        unmute = False
        settings = user.vinceprofile.settings
        logger.debug(user.vinceprofile.settings)
        if user.vinceprofile.settings.get('muted_cases'):
            muted_cases = user.vinceprofile.settings['muted_cases']
            logger.debug(muted_cases)
            if case.id in muted_cases:
                #this case has already been muted, unmute this case:
                muted_cases.remove(case.id)
                logger.debug(muted_cases)
                settings.update({'muted_cases': muted_cases})
                user.vinceprofile.settings = settings
                user.vinceprofile.save()
                logger.debug(user.vinceprofile.settings)
                                
                unmute = True
            else:
                muted_cases.append(case.id)
                settings.update({'muted_cases': muted_cases})
                user.vinceprofile.settings = settings
                user.vinceprofile.save()
        else:
            # this user hasn't muted any cases yet
            settings.update({'muted_cases': [case.id]})
            user.vinceprofile.settings = settings
            user.vinceprofile.save()
            logger.debug(user.vinceprofile.settings)

        if unmute:
            button = "<i class=\"fas fa-volume-mute\"></i> Mute Case"
        else:
            button = "<i class=\"fas fa-volume-up\"></i> Unmute Case"

        return JsonResponse({'response': 'success', 'button': button}, status=200)
    
    
class ViewStatusView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    template_name = 'vinny/status.html'
    login_url = 'vinny:login'
    form_class = StatementForm

    def test_func(self):
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        # add the extra _my_group_for_case because reporters/participants shouldn't
        # provide a status
        return _is_my_case(self.request.user, self.kwargs['pk']) and _my_group_for_case(self.request.user, case) and PendingTestMixin.test_func(self)

    def dispatch(self, request, *args, **kwargs):
        if self.kwargs.get('vendor_id'):
            return super().dispatch(request, *args, **kwargs)
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        groups = _my_groups_for_case(self.request.user, case)
        if len(groups) > 1:
            return redirect("vinny:multiple_status", case.id)
        return super().dispatch(request, *args, **kwargs)
    
    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        if self.kwargs.get('vendor_id'):
            member = CaseMember.objects.filter(id=self.kwargs.get('vendor_id')).first()
        else:
            group = _my_group_for_case(self.request.user, case)
            member = CaseMember.objects.filter(case=case, group__name=group).first()
        if not member:
            return HttpResponse(status=500)

        affected = []
        unaffected=[]
        unknown=[]
        try:
            for k,v in self.request.POST.items():
                if k.startswith('status'):
                    vul_id = int(k.split('_')[1])
                    if v == "affected":
                        affected.append(vul_id)
                    elif v == "unaffected":
                        unaffected.append(vul_id)
                    else:
                        unknown.append(vul_id)
        except:
            logger.debug(traceback.format_exc())
            pass
        
        update_status(member, self.request, affected=affected, unaffected=unaffected, unknown=unknown)

        old_stmt = CaseStatement.objects.filter(case=case, member=member).first()

        if old_stmt:
            if old_stmt.statement != form.cleaned_data['statement']: 
                create_vendor_status_change("statement", old_stmt.statement,
                                            form.cleaned_data['statement'],
                                            self.request.user, member, case=case)
            if old_stmt.references != form.cleaned_data['references']:
                create_vendor_status_change("references", old_stmt.references,
                                            form.cleaned_data['references'],
                                            self.request.user, member, case=case)
            if old_stmt.share != form.cleaned_data['share']:
                create_vendor_status_change("share toggle", old_stmt.share, form.cleaned_data['share'],
                                            self.request.user, member, case=case)
        
        stmt = CaseStatement.objects.update_or_create(case=case, member=member,
                                                      defaults={'statement':form.cleaned_data['statement'],
                                                                'references':form.cleaned_data["references"],
                                                                'share':form.cleaned_data['share']})

        messages.success(
            self.request,
            _("Got it! Your status has been recorded and is pending approval by the coordination team."))

        return redirect("vinny:case", case.id)
                                 
    
    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = StatementForm(request.POST)

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)
    
    def get_context_data(self, **kwargs):
        context = super(ViewStatusView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        context['case'] = case
        context['casepage'] = 1
        context['vuls'] = CaseVulnerability.objects.filter(case=case)
        if self.kwargs.get('vendor_id'):
            member = CaseMember.objects.filter(id=self.kwargs.get('vendor_id')).first()
            context['action'] = reverse("vinny:status", args=[case.id, self.kwargs.get('vendor_id')])
            context['vendor_id'] = self.kwargs.get('vendor_id')
        else:
            group = _my_group_for_case(self.request.user, case)
            member = CaseMember.objects.filter(case=case, group__name=group).first()
            context['action'] = reverse("vinny:status", args=[case.id])
            
        context['org_name'] = member.group.groupcontact.contact.vendor_name

        context['status'] = CaseMemberStatus.objects.filter(vulnerability__in=context['vuls'], member=member)

        stmt = CaseStatement.objects.filter(case = case, member=member).first()
        if stmt:
            initial={'statement':stmt.statement, 'references':stmt.references, 'share': stmt.share, 'addendum':stmt.addendum}
        else:
            initial={}
        logger.debug(initial)
        
        contact_users = _users_in_group(member.group.groupcontact.contact)
        if contact_users:
            contact_users = contact_users.values_list('id', flat=True)
            actions = VendorAction.objects.filter(case=case).filter(Q(user__in=contact_users)|Q(member=member)).values_list('id', flat=True)
            #actions = VendorAction.objects.filter(case=case, member=member).values_list('id', flat=True)
            context['activity'] = VendorStatusChange.objects.filter(action__in=actions).order_by("-action__created")[:15]
        context['form'] = StatementForm(initial=initial)
        
        return context

class AddStatement(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, FormView):
    template_name = "vinny/provide_statement.html"
    login_url = "vinny:login"
    form_class = VulStatementForm

    def test_func(self):
        vul = get_object_or_404(CaseVulnerability, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, vul.case.id) and PendingTestMixin.test_func(self)
    

    def form_valid(self, form):
        vul = get_object_or_404(CaseVulnerability, id=self.kwargs['pk'])
        group = _my_group_for_case(self.request.user, vul.case)
        member = CaseMember.objects.filter(case=vul.case, group__name=group).first()
        if not member:
            return HttpResponse(status=500)
        status = CaseMemberStatus.objects.filter(vulnerability=vul, member=member).first()
        if status:
            if status.statement != form.cleaned_data['statement']:
                create_vendor_status_change("statement", status.statement,
                                            form.cleaned_data['statement'],
                                            self.request.user, member, cv=vul)
            if status.references != form.cleaned_data['references']:
            	create_vendor_status_change("references", status.references,
                                            form.cleaned_data['references'],
                                            self.request.user, member, cv=vul)
            status.references = form.cleaned_data["references"]
            status.statement = form.cleaned_data["statement"]
            status.approved = False
            status.save()
        else:
            status = CaseMemberStatus(vulnerability=vul,
                                      member=member,
                                      status=3,
                                      user=self.request.user,
                                      references= form.cleaned_data["references"],
                                      statement = form.cleaned_data["statement"])
            status.save()
        update_status(member, self.request, vul.vince_id)
        if form.cleaned_data['statement'] or form.cleaned_data['references']:
            statement = 1
        else:
            statement = 0

        return JsonResponse({'response': 'success', 'statement': statement, 'vul_id': vul.id}, status=200)
                                                 
    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = VulStatementForm(request.POST)

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(AddStatement, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        vul = get_object_or_404(CaseVulnerability, id=self.kwargs['pk'])
        if self.kwargs.get('vendor_id'):
            member = CaseMember.objects.filter(id=self.kwargs.get('vendor_id')).first()
            context['action'] = reverse("vinny:providestmt", args=[vul.id, self.kwargs.get('vendor_id')])
        else:
            group = _my_group_for_case(self.request.user, vul.case)
            member = CaseMember.objects.filter(case=vul.case, group__name=group).first()
            context['action'] = reverse("vinny:providestmt", args=[vul.id])
        
        status = CaseMemberStatus.objects.filter(vulnerability=vul, member=member).first()
        if status:
            initial = {'statement': status.statement, 'references':status.references}
        else:
            initial = {}

        context['vul'] = vul
        form = VulStatementForm(initial=initial)
        context['form'] = form
        context['title'] = "Provide Statement"

        return context

class ThreadedPostView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.ListView):
    template_name = "vinny/posts.html"
    login_url="vinny:login"
    context_object_name = 'posts'
    paginate_by = 10

    def test_func(self):
        self.case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)

    def get_queryset(self):
        return ThreadedPost.objects.filter(parent=self.kwargs['post']).order_by('created')

    def get_context_data(self, **kwargs):
        context = super(ThreadedPostView, self).get_context_data(**kwargs)
        context['auto_members'] = _case_participants(self.case)
        return context
    
class PostView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/posts.html"
    login_url="vinny:login"
    context_object_name = 'posts'
    paginate_by = 10

    def test_func(self):
        self.case = get_object_or_404(Case, id=self.kwargs['pk'])
        return _is_my_case(self.request.user, self.kwargs['pk']) and PendingTestMixin.test_func(self)
    
    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        case = get_object_or_404(Case, id=self.kwargs['pk'])
        form = PostForm(self.request.POST)
        find_post = None
        if form.is_valid():
            if self.request.POST.get("reply_to"):
                find_tp = ThreadedPost.objects.filter(id=int(self.request.POST.get('reply_to'))).first()
                if find_tp:
                    find_post = find_tp.parent
                else:
                    find_post = Post.objects.filter(id=int(self.request.POST.get('reply_to'))).first()
                if find_post:
                    logger.debug("THIS IS A THREADED POST!")
                    post = ThreadedPost(case=case,
                                        parent=find_post,
                                        author=self.request.user)
                    post.save()
                else:
                    post = Post(case=case,
                                author=self.request.user)
                    post.save()
            else:
                post = Post(case = case,
                            author = self.request.user)
                post.save()

            my_group = _my_group_id_for_case(self.request.user, case)
            if my_group:
                logger.debug(f"POST GROUP is {my_group.groupcontact.contact.vendor_name}")
                post.group = my_group
                post.save()
            post.add_revision(PostRevision(content=form.cleaned_data['content']), save=True)
            vince_comm_send_sqs("NewPost", "Case", case.vuid, self.request.user.username, str(post.id), "New Post from " + self.request.user.username)
            #emails = send_usermention_notification(post, form.cleaned_data['content'])
            #send_post_email(post, emails)
            data = {'auto_members': _case_participants(post.case),
                    'num_posts':self.get_queryset().count()}
            if find_post and find_post.pinned:
                data['posts'] = Post.objects.filter(case=self.case, pinned=True)
                data['page_obj'] = 1
            else:
                paginate_by = self.request.POST.get('paginate_by', self.paginate_by)
                # if paginate_by is not set for some reason, just use default
                try:
                    p = Paginator(self.get_queryset(), paginate_by)
                except:
                    p = Paginator(self.get_queryset(), self.paginate_by)
                data['posts'] = p.page(1)

            return render(request, self.template_name, data)
        else:
            return JsonResponse({'response': 'failure'}, status=400)

    def get_queryset(self):
        threaded_posts = ThreadedPost.objects.filter(case=self.case).values_list('id', flat=True)
        return Post.objects.filter(case=self.case, pinned=False).exclude(id__in=threaded_posts).order_by('-created')
    
    def get_context_data(self, **kwargs):
        context = super(PostView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['auto_members'] = _case_participants(self.case)
        posts = self.get_queryset()
        context['num_posts'] = posts.count()
        no_page = self.request.GET.get('no_page', False)
        if no_page:
            context['posts'] = posts
        else:
            page = self.request.GET.get('page', 1)
            paginate_by = int(self.request.GET.get('paginate_by', self.paginate_by))
            p = Paginator(posts, paginate_by)
            context['posts'] = p.page(page)
        return context

class DeletePostView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = "vinny/remove_post.html"
    login_url="vinny:login"

    def test_func(self):
        post = get_object_or_404(Post, id=self.kwargs['pk'])
        if self.request.user.is_staff:
            return True
        return _is_my_post(self.request.user, post) and PendingTestMixin.test_func(self)

    def get_context_data(self, **kwargs):
        context = super(DeletePostView, self).get_context_data(**kwargs)
        context['object'] = get_object_or_404(Post, id=self.kwargs['pk'])
        context['action'] = reverse('vinny:rmpost', args=[self.kwargs['pk']])
        return context

    def post(self, request, *args, **kwargs):
        post = get_object_or_404(Post, id=self.kwargs['pk'])
        case = post.case.id
        post.deleted = True
        post.save()
        action = create_action("Post deleted", self.request.user, post.case)
        action.post = post
        action.save()
        vince_comm_send_sqs("PostRemoved", "Case", post.case.vuid, self.request.user.username, str(post.id), "Post removed by " + self.request.user.username)
        return redirect("vinny:case", case)
    
class EditPostView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.FormView):
    template_name = "vinny/editpost.html"
    login_url="vinny:login"
    form_class= EditPostForm

    def test_func(self):
        post = get_object_or_404(Post, id=self.kwargs['pk'])
        if self.request.user.is_staff:
            return True
        return _is_my_post(self.request.user, post) and PendingTestMixin.test_func(self)

    def form_invalid(self, form):
        logger.debug(f"{self.__class__.__name__} errors: {form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        post = get_object_or_404(Post, id=self.kwargs['pk'])
        rev = PostRevision()
        rev.inherit_predecessor(post)
        rev.content = form.cleaned_data['post']
        rev.deleted = False
        rev.set_from_request(self.request)
        post.add_revision(rev)
        vince_comm_send_sqs("EditPost", "Case", post.case.vuid,
                            self.request.user.username,
                            str(post.id),
                            self.request.user.username + " Edited their Post")
#        ca = create_case_action(post.case.vuid, self.request.user.username, self.request.user.username + " Edited their Post", form.cleaned_data['post'], post.id)
        #create an action here?                                                                                            
        return JsonResponse({'response': 'success'}, status=200)
    
    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)
        post = get_object_or_404(Post, id=self.kwargs['pk'])
        if self.request.POST.get('pin'):
            if self.request.user.is_staff:
                #_remove_case_pinned_posts(post.case)
                if post.pinned == False:
                    post.pinned = True
                    post.save()
                else:
                    #unpin it
                    post.pinned=False
                    post.save()
                return JsonResponse({'response': 'success'}, status=200)
            return JsonResponse({'response': 'Forbidden'}, status=403)
        if self.request.POST.get('id'):
            #this is a delete request
            if self.request.user.is_staff:
                post.delete()
            else:
                post.deleted = True
                post.save()
            return JsonResponse({'response': 'success'}, status=200)
        
        form = EditPostForm(self.request.POST)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super(EditPostView, self).get_context_data(**kwargs)
        context['post'] = get_object_or_404(Post, id=self.kwargs['pk'])
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['form'] = EditPostForm(initial={'post':context['post'].current_revision.content})
        return context


class PostDiffView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.DetailView):
    model = PostRevision
    pk_url_kwarg = 'revision_id'
    login_url = "vinny:login"
    template_name = "vinny/postdiff.html"

    def test_func(self):
        revision = self.get_object()
        case = revision.post.case
        return _is_my_case(self.request.user, case.id) and PendingTestMixin.test_func(self)
    
    def get_context_data(self, **kwargs):
        context = super(PostDiffView, self).get_context_data(**kwargs)

        revision = self.get_object()
        other_revision = revision.previous_revision

        baseText = other_revision.content if other_revision is not None else ""
        newText = revision.content

        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        diff = differ.compare(
            baseText.splitlines(keepends=True), newText.splitlines(keepends=True)
        )
        context['object'] = revision
        context['other_changes'] = []
        context['diff'] = list(diff)
        return context

class ReporterFilter(LoginRequiredMixin, TokenMixin, PendingTestMixin, FormView):
    form_class = CaseFilterForm
    template_name = 'vinny/searchreports.html'
    login_url = "vinny:login"

    
class CaseFilter(LoginRequiredMixin, TokenMixin, PendingTestMixin, FormView):
    form_class = CaseFilterForm
    template_name = 'vinny/searchcases.html'
    login_url = "vinny:login"

    def get_context_data(self, **kwargs):
        context = super(CaseFilter, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['casepage']=1
        date_from = self.request.GET.get('date_from')
        initial = {}
        if date_from:
            initial['datestart'] = DateField().clean(date_from)
        date_to = self.request.GET.get('date_to')
        if date_to:
            initial['dateend'] = DateField().clean(date_to)
        else:
            initial['dateend'] = timezone.now
        owner = self.request.GET.get('owner')
        if owner:
            initial['owner'] = int(owner)
        form = CaseFilterForm(initial=initial)

        context['form'] = form
        return context

def process_query(s):

    query = re.sub(r'[!\'()|&]', ' ', s).strip()
    if query.startswith(settings.CASE_IDENTIFIER):
        query = query[len(settings.CASE_IDENTIFIER):]
    if query:
        query = re.sub(r'\s+', ' & ', query)
        # Support prefix search on the last word. A tsquery of 'toda:*' will
        # match against any words that start with 'toda', which is good for
        # search-as-you-type.                                          
        query += ':*'
    return query
    
class CaseFilterResults(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.ListView):
    template_name = 'vinny/searchresults.html'
    paginate_by = 10
    model = Case
    
    def get_context_data(self, **kwargs):
        context = super(CaseFilterResults, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['casepage']=1
        return context

    def get_queryset(self):
        if cognito_admin_user(self.request):
            return Case.objects.all().order_by('-modified')
        my_cases = _get_my_cases(self.request.user)
        my_cases = my_cases.annotate(last_post_date=Max('post__created')).order_by('-last_post_date')
        # sort by posts/no posts                                            
        cp = my_cases.exclude(last_post_date__isnull=True)
        cnop= my_cases.exclude(last_post_date__isnull=False)
        res = list(chain(cp, cnop))
        return res
                                 
    
    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        if cognito_admin_user(self.request):
            res = Case.objects.all().annotate(last_post_date=Max('post__created')).order_by('-last_post_date')
        else:
            res = _get_my_cases(self.request.user)
            res = res.annotate(last_post_date=Max('post__created')).order_by('-last_post_date')

        my_cases = res
        page = self.request.POST.get('page', 1)
        if 'status' in self.request.POST:
            statuslist = self.request.POST.getlist('status')
            if '3' in statuslist:
                res = res.exclude(note__datefirstpublished__isnull=True)
            if '3' in statuslist:
                statuslist.remove('3')
            if statuslist:
                res = res.filter(status__in=statuslist)

        if 'datestart' in self.request.POST:
            enddate = DateTimeField().clean(self.request.POST['dateend']) + timedelta(days=1)
            if self.request.POST['datestart']:
                res = res.filter(created__range=(DateTimeField().clean(self.request.POST['datestart']),enddate))
            elif 'dateend' in self.request.POST:
                if self.request.POST['dateend']:
                    res = res.filter(created__range=(DateTimeField().clean('1970-01-01'), enddate))
        if 'wordSearch' in self.request.POST:
            if self.request.POST['wordSearch']:
                wordSearch = process_query(self.request.POST['wordSearch'])
                res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[wordSearch])
                #search posts
                post_result = PostRevision.objects.filter(post__case__in=my_cases).extra(where=["search_vector @@ (to_tsquery('english', %s))=true"], params=[wordSearch]).values_list('post__case', flat=True)
                if post_result:
                    extra_cases = Case.objects.filter(id__in=post_result).exclude(id__in=res)
                    res = list(chain(res, extra_cases))
            else:
                # sort by posts/no posts
                cp = res.exclude(last_post_date__isnull=True)
                cnop=res.exclude(last_post_date__isnull=False)
                res = list(chain(cp, cnop))
        else:
            # sort by posts/no posts
            cp = res.exclude(last_post_date__isnull=True)
            cnop=res.exclude(last_post_date__isnull=False)            
            res = list(chain(cp, cnop))

        paginator = Paginator(res, 10)

        return render(request, self.template_name, {'object_list': paginator.page(page), 'total': len(res) })
    
class EditContactView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    model = VinceCommContact
    login_url = "vinny:login"
    template_name = 'vinny/editcontact.html'
    PostalFormSet = inlineformset_factory(VinceCommContact, VinceCommPostal, form=VCPostalForm, max_num=10, min_num=1, can_delete=True, extra=0)
    PhoneFormSet = inlineformset_factory(VinceCommContact, VinceCommPhone, form=VCPhoneForm, max_num=10, min_num=1, can_delete=True, extra=0)
    WebFormSet = inlineformset_factory(VinceCommContact, VinceCommWebsite, form=VCWebsiteForm, max_num=10, min_num=1, can_delete=True, extra=0)
    PgPFormSet = inlineformset_factory(VinceCommContact, VinceCommPgP, form=VCPgPForm, max_num=10, min_num=1, can_delete=True, extra=0)
    EmailFormSet = inlineformset_factory(VinceCommContact, VinceCommEmail, form=VCEmailForm,  max_num=30, min_num=1, can_delete=True, extra=0)

    def test_func(self):
        logger.debug("TESTING TESTING 1 2 3")
        self.contacts = _my_contact_group(self.request.user)
        logger.debug("IN TEST FUNC")
        if len(self.contacts) > 0:
            vendor_id = self.kwargs.get('vendor_id')
            self.contact = VinceCommContact.objects.filter(id=vendor_id).first()
            return _user_in_contact(self.request.user, self.contact) and PendingTestMixin.test_func(self)
        else:
            # this user does not belong to a group with contact info  
            return False
    
    def form_invalid(self, form):
        phones = VinceCommPhone.objects.filter(contact=self.contact)
        postal = VinceCommPostal.objects.filter(contact=self.contact)
        website = VinceCommWebsite.objects.filter(contact=self.contact)
        pgp = VinceCommPgP.objects.filter(contact=self.contact)
        email = VinceCommEmail.objects.filter(contact=self.contact,email_list=True).order_by('-email_function')
        forms = {'postal_formset': self.PostalFormSet(prefix='postal', queryset=postal, instance=self.contact),
                 'phone_formset': self.PhoneFormSet(prefix='phone', queryset=phones, instance=self.contact),
                 'web_formset': self.WebFormSet(instance=self.contact, prefix='web', queryset=website),
                 'pgp_formset': self.PgPFormSet(prefix='pgp', queryset=pgp, instance=self.contact),
                 'email_formset': self.EmailFormSet(prefix='email', queryset=email, instance=self.contact),
                 'contact':self.contact}
        return render(self.request, 'vince/editcontact.html', forms)

    def get_context_data(self, **kwargs):
        context = super(EditContactView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        phones = VinceCommPhone.objects.filter(contact=self.contact)
        postal = VinceCommPostal.objects.filter(contact=self.contact)
        website = VinceCommWebsite.objects.filter(contact=self.contact)
        pgp = VinceCommPgP.objects.filter(contact=self.contact)
        email = VinceCommEmail.objects.filter(contact=self.contact, email_list=True).order_by('-email_function')
        print(email.values())
        forms = {'postal_formset': self.PostalFormSet(prefix='postal', queryset=postal, instance=self.contact),
                 'phone_formset': self.PhoneFormSet(prefix='phone', queryset=phones, instance=self.contact),
                 'web_formset': self.WebFormSet(instance=self.contact, prefix='web', queryset=website),
                 'pgp_formset': self.PgPFormSet(prefix='pgp', queryset=pgp, instance=self.contact),
                 'email_formset': self.EmailFormSet(prefix='email', queryset=email, instance=self.contact)}
        context['contact'] = self.contact
        logger.debug(self.contact)
        logger.debug(self.contact.id)
        logger.debug(self.contact.vendor_id)
        context.update(forms)
        context['gc'] = GroupContact.objects.filter(contact=self.contact).first()
        context['form'] = UploadLogoForm(contact=self.contact.id, user=self.request.user)
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)

        phones = VinceCommPhone.objects.filter(contact=self.contact)
        postal = VinceCommPostal.objects.filter(contact=self.contact)
        website = VinceCommWebsite.objects.filter(contact=self.contact)
        pgp = VinceCommPgP.objects.filter(contact=self.contact)
        email = VinceCommEmail.objects.filter(contact=self.contact, email_list=True)

        postalformset = self.PostalFormSet(self.request.POST, prefix='postal', queryset=postal, instance=self.contact)
        phoneformset = self.PhoneFormSet(self.request.POST, prefix='phone', queryset=phones, instance=self.contact)
        webformset = self.WebFormSet(self.request.POST, prefix='web', queryset=website, instance=self.contact)
        pgpformset = self.PgPFormSet(self.request.POST, prefix='pgp', queryset=pgp, instance=self.contact)
        emailformset = self.EmailFormSet(self.request.POST, prefix='email', queryset=email, instance=self.contact)
        logger.debug(self.contact.version)
        logger.debug(self.request.POST['version'])

        if self.contact.version != int(self.request.POST['version']):
            error_str = "Someone beat you to editing your contact information. \
            View the most recent details and retry editing this contact."
            forms = {'collision': error_str,
                     'postal_formset': self.PostalFormSet(prefix='postal', queryset=postal),
                     'phone_formset': self.PhoneFormSet(prefix='phone', queryset=phones),
                     'web_formset': self.WebFormSet(prefix='web', queryset=website),
                     'pgp_formset': self.PgPFormSet(prefix='pgp', queryset=pgp),
                     'contact': self.contact,
                     'email_formset': self.EmailFormSet(prefix='email', queryset=email)}
            messages.error(
            self.request,
            _(error_str))
            return render(self.request, 'vinny/editcontact.html', forms)

        changes = []
        for f in emailformset:
            if f.is_valid():
                cd = f.cleaned_data
                old = cd.get('id')
                if (old):
                    nochanges = all([old.email==cd['email'],
                                     old.email_type==cd['email_type'],
                                     old.name==cd['name'],
                                     old.public == cd['public']])
                    if nochanges and not(cd['DELETE']):
                        continue
                    if cd['DELETE']:
                        # check if this email belongs to a vince user
                        vince_user = User.objects.filter(email=cd['email']).first()
                        if vince_user:
                            messages.error(
                                self.request,
                                _("The email you are attempting to remove is associated with a VINCE user account. The group administrator can remove this user on the <a href=\""+reverse("vinny:admin")+"\">User Management</a> page."))
                            return redirect("vinny:contact")
                        changes.append(contact_update.remove_email_contact(self.contact, old, self.request.user))
                        old.delete()
                        continue
                    else:
                        changes.extend(contact_update.change_email_contact(self.contact, old, cd, self.request.user))
                else:
                    #Does this email already exist?
                    oe = VinceCommEmail.objects.filter(contact=self.contact, email=cd['email']).first()
                    if oe:
                        messages.error(
                            self.request,
                            _("The email you are attempting to add is already associated with this contact. Personal emails should be modified by a group admin on the <a href=\""+reverse("vinny:admin")+"\">User Management</a> page."))
                        return redirect("vinny:contact")
                    # this is a new one
                    changes.append(contact_update.add_email_contact(self.contact, cd, self.request.user))
                    
                f.save()

            else:
                logger.debug(f.errors)

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
                                     old.zip_code == cd['zip_code'],
                                     old.public == cd['public']])
                    if nochanges and not(cd['DELETE']):
                        continue
                    if cd['DELETE']:
                        changes.append(contact_update.remove_postal_contact(self.contact, old, self.request.user))
                        old.delete()
                        continue
                    else:
                        changes.extend(contact_update.change_postal_contact(self.contact, old, cd, self.request.user))
                else:
                    if not(cd.get('street')):
                        continue
                    changes.append(contact_update.add_postal_contact(self.contact, cd, self.request.user))

                f.save()
            else:
                logger.debug(f.errors)

        for f in phoneformset:
            if f.is_valid():
                cd = f.cleaned_data
                old=cd.get('id')
                if old:
                    nochanges = all([old.country_code == cd['country_code'],
                                     old.phone == cd['phone'],
                                     old.phone_type == cd['phone_type'],
                                     old.comment == cd['comment'],
                                     old.public == cd['public']])
                    if nochanges and not(cd['DELETE']):
                        continue
                    if cd['DELETE']:
                        changes.append(contact_update.remove_phone_contact(self.contact, old, self.request.user))
                        old.delete()
                        continue
                    else:
                        changes.extend(contact_update.change_phone_contact(self.contact, old, cd, self.request.user))
                else:
                    changes.append(contact_update.add_phone_contact(self.contact, cd, self.request.user))

                f.save()
            else:
                for x in phoneformset.errors:
                    for k,v in x.items():
                        if 'This field is required.' not in v:
                            messages.error(self.request,
                                           f"Phone Number Validation Error: {k}: {v}")
                logger.debug(f.errors)

        for f in pgpformset:
            if f.is_valid():
                cd = f.cleaned_data
                old=cd.get('id')
                if old:
                    nochanges = all([old.pgp_key_id == cd['pgp_key_id'],
                                     old.pgp_key_data == cd.get('pgp_key_data'),
                                     old.pgp_email == cd.get('pgp_email'),
                                     old.public == cd['public']])
                    if nochanges and not(cd['DELETE']):
                        continue
                    if cd['DELETE']:
                        changes.append(contact_update.remove_pgp_contact(self.contact, old, self.request.user))
                        old.delete()
                        continue
                    else:
                        cd = contact_update.extract_pgp_info(cd)
                        if cd:
                            obj, created = VinceCommPgP.objects.update_or_create(id=old.id,
                                                                                 defaults={'pgp_key_id':cd['pgp_key_id'],
                                                                                           'contact': self.contact,
                                                                                           'pgp_key_data':cd['pgp_key_data'],
                                                                                           'pgp_fingerprint':cd['pgp_fingerprint'],
                                                                                           'pgp_email': cd['pgp_email'],
                                                                                           'startdate': cd['startdate'],
                                                                                           'enddate': cd['enddate'],
                                                                                           'public': cd['public']})
                            changes.extend(contact_update.change_pgp_contact(self.contact, old, cd, self.request.user))
                        else:
                            messages.error(
                                self.request,
                                _("PGP key not added: Invalid PGP Key Data"))
                else:
                    cd = contact_update.extract_pgp_info(cd)
                    if cd:
                        obj = VinceCommPgP(pgp_key_id=cd['pgp_key_id'],
                                           contact=self.contact,
                                           pgp_key_data=cd['pgp_key_data'],
                                           pgp_fingerprint=cd['pgp_fingerprint'],
                                           startdate=cd['startdate'],
                                           pgp_email=cd['pgp_email'],
                                           enddate = cd['enddate'],
                                           public = cd['public'])
                        obj.save()
                        changes.append(contact_update.add_pgp_contact(self.contact, cd, self.request.user))
                    else:
                        messages.error(
	                    self.request,
                            _("PGP Key not added: Invalid PGP Key Data"))


            else:
                for x in pgpformset.errors:
                    for k,v in x.items():
                        if 'This field is required.' not in v:
                            if "Either PGP Key or ID is required" in v and not(f.cleaned_data.get('pgp_key_data') or f.cleaned_data.get('pgp_key_id')):
                                continue

                            messages.error(self.request,
                                           f"PGP Key Validation Error: {v}")
                logger.debug(f.errors)

        for f in webformset:
            if f.is_valid():
                cd = f.cleaned_data
                old = cd.get('id')
                if old:
                    nochanges = all([old.url == cd['url'],
                                     old.description == cd['description'],
                                     old.public == cd['public']])
                    if nochanges and not(cd['DELETE']):
                        continue
                    if cd['DELETE']:
                        changes.append(contact_update.remove_website(self.contact, old, self.request.user))
                        old.delete()
                        continue
                    else:
                        changes.extend(contact_update.change_website_contact(self.contact, cd, old, self.request.user))
                else:
                    changes.append(contact_update.add_website(self.contact, cd, self.request.user))

                f.save()
            else:
                logger.debug(f.errors)
                                     

        if changes:
            # send ticket
            contact_update.send_ticket(changes, self.contact, self.request.user)
            tm = messages.get_messages(self.request)
            if len(tm) == 0:
                messages.success(
                    self.request,
                    "Got it! Thanks for updating your contact information."
                )
                
        return redirect("vinny:contact", self.contact.id)
        

class PreferencesView(LoginRequiredMixin, TokenMixin, PendingTestMixin, FormView):
    template_name='vinny/preferences.html'
    login_url="vinny:login"
    form_class=PreferencesForm
    success_url=reverse_lazy("vinny:preferences")

    def get_initial(self):
        s = self.request.user.vinceprofile
        return s.settings

    def form_valid(self, form):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        s = self.request.user.vinceprofile
        settings = s.settings
        for k,v in form.cleaned_data.items():
            settings[k] = v
        s.settings = settings
        s.save()
        messages.success(
            self.request,
            "Got it! Your preferences have been saved."
            )
        return super().form_valid(form)

    
class GenerateNewRandomColor(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.TemplateView):
    template_name = 'vinny/notemplate.html'
    login_url="vinny:login"

    def get(self, request, *args, **kwargs):
        self.request.user.vinceprofile.logocolor = "#"+''.join([random.choice('0123456789ABCDEF') for j in range(6)])
        self.request.user.vinceprofile.save()
        messages.success(
            self.request,
            "Hope you like your new color!"
        )
        return redirect("cogauth:profile")
    

class UnderConstruction(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.TemplateView):
    template_name = 'vinny/construction.html'
    login_url="vinny:login"
    
    def get_context_data(self, **kwargs):
        context = super(UnderConstruction, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        return context

class CRView(LoginRequiredMixin, TokenMixin, PendingTestMixin, UserPassesTestMixin, generic.TemplateView):
    template_name = 'vinny/cr_report.html'
    login_url = "vinny:login"

    def test_func(self):
        report = get_object_or_404(VTCaseRequest, id=self.kwargs['pk'])
        return _is_my_report(self.request.user, report)
    
    def get_context_data(self, **kwargs):
        context = super(CRView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['crpage'] = 1
        context['report'] = VTCaseRequest.objects.filter(id=self.kwargs['pk']).first()
        context['attachments'] = ReportAttachment.objects.filter(action__cr=context['report'])
        if hasattr(context['report'], "case"):
            context['case_permission'] = _is_my_case(self.request.user, context['report'].case.id)
        return context


class UpdateReportView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"

    def test_func(self):
        self.report = get_object_or_404(VTCaseRequest, id=self.kwargs['pk'])
        return _is_my_report(self.request.user, self.report) and PendingTestMixin.test_func(self)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")

        cr = CRFollowUp(cr = self.report,
                        title = "commented on report",
                        user = self.request.user,
                        comment = self.request.POST['comment'])
        cr.save()
        messages.success(
            self.request,
            _("Your comment has been recorded."))
        vince_comm_send_sqs("CRUpdate", "Ticket", self.report.vrf_id,
                            self.request.user.username, str(cr.id), "New Comment on CR")
        
        return redirect("vinny:cr_report", self.kwargs['pk'])

class AdminReportsView(LoginRequiredMixin, TokenMixin, PendingTestMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = 'vinny/allreports.html'

    def test_func(self):
        return self.request.user.is_superuser
    
    def get_context_data(self, **kwargs):
        context = super(AdminReportsView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['crpage'] = 1
        auth_reports =  VTCaseRequest.objects.all()
        unauth_reports = VulCoordRequest.objects.using('vincecomm').all()
        all_reports = chain(auth_reports, unauth_reports)
        context['object_list'] = sorted(all_reports,
                                        key=lambda instance: instance.id,
                                        reverse=True)
        return context
    
class ReportsView(LoginRequiredMixin, TokenMixin, PendingTestMixin, generic.ListView):
    template_name = 'vinny/myreports.html'
    login_url = "vinny:login"
    model = VTCaseRequest

    def get_queryset(self):
        return VTCaseRequest.objects.filter(user=self.request.user).order_by('-date_submitted')
    
    def get_context_data(self, **kwargs):
        context = super(ReportsView, self).get_context_data(**kwargs)
        context['unread_msg_count'] = _unread_msg_count(self.request.user)
        context['crpage'] = 1
        form = ReportStatusForm()
        context['form'] = form

        return context
    
GOOGLE_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

def vrf_id_generator(vrf_id_size=5, chars='BCDFGHJKLMNPQRSTVWXYZ'):
    return ''.join(random.choice(chars) for _ in range(5))

def get_vrf_id():
    today = datetime.now(EST())
    # Reports are in format: {REPORT_IDENTIFIER}YY-MM-XXXX (YY = 2digit year, MM = month)
    vrf_id_rnd = vrf_id_generator()
    vrf_id_month = str(today.month) if today.month > 9 else ('0' + str(today.month))
    vrf_id = str(today.year)[2:] + '-' + vrf_id_month + '-' + vrf_id_rnd
    return vrf_id




class ReportView(LoginRequiredMixin, TokenMixin, generic.FormView):
    template_name = 'vincepub/reportcoord.html'
    model = VTCaseRequest
    form_class = CaseRequestForm
    login_url="vinny:login"
    success_url = 'results.html'

    def get_context_data(self, **kwargs):
        context = super(ReportView, self).get_context_data(**kwargs)
        context['reportpage'] = 3
        initial = {'contact_name': self.request.user.get_full_name(),
                   'contact_org': self.request.user.vinceprofile.org,
                   'contact_email': self.request.user.email}
        context['form'] = CaseRequestForm(initial=initial)
        return context

    def form_valid(self, form):
        #Begin reCAPTCHA validation                                                                         
        recaptcha_response = self.request.POST.get('g-recaptcha-response')
        logger.debug(recaptcha_response)
        data = {
            'secret' : settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        r = requests.post(GOOGLE_VERIFY_URL, data=data)
        result = r.json()
        if result['success']:
            logger.debug("successful recaptcha validation")
        else:
            logger.debug("invalid recaptcha validation")
            form._errors[forms.forms.NON_FIELD_ERRORS] = ErrorList([
                u'Invalid reCAPTCHA.  Please try again'
		])
            return super().form_invalid(form)

        # process the data in form.cleaned_data as required                                                 
        vrf_id = get_vrf_id()
        form.instance.vrf_id = vrf_id
        newrequest = form.save(commit=False)
        newrequest.user = self.request.user
        newrequest.save()
        context = form.cleaned_data
        coord_choice=[]
        context['vrf_id']=vrf_id
        context['vc_id'] = newrequest.id
        for selection in context['coord_status']:
            coord_choice.append(form.fields['coord_status'].choices[int(selection)][1])
        if context['why_no_attempt']:
            context['coord_choice']= form.fields['why_no_attempt'].choices[int(context['why_no_attempt'])-1][1]

        context['vrf_id'] = vrf_id
        context['vrf_date_submitted'] = datetime.now(EST()).isoformat()
        # get some meta info about who submitted this                                                       
        # construct email                                                                                   
        context['submission_type'] = 'Vulnerability Report'
        subject = f"[{settings.REPORT_IDENTIFIER}{vrf_id}] "
        if context['product_name']:
            subject += context['product_name']
        else:
            subject += "New Report Submission (No Title Provided)"
        if context['tracking']:
            subject += "[" + context['tracking'] + "]"

        if len(subject) > 99:
            subject = subject[:99]
                    
        context["title"] = subject

        cc_recipients = []

        s3Client = boto3.client('s3', region_name=settings.AWS_REGION, config=Config(signature_version='s3v4'))
        attachment = context.get('user_file')
        if attachment:
            logger.debug(attachment)
            context['s3_file_name'] = newrequest.user_file.name
            logger.debug(newrequest.user_file.name)
            try:
                # tag object with vrf id
                # copy from private to incoming reports directory
                rd = s3Client.copy_object(CopySource=f'/{settings.PRIVATE_BUCKET_NAME}/{settings.AWS_PRIVATE_MEDIA_LOCATION}/{newrequest.user_file.name}',
                                          Bucket=settings.VP_PRIVATE_BUCKET_NAME,
                                          Key=settings.VRF_PRIVATE_MEDIA_LOCATION+'/'+newrequest.user_file.name,
                                          Tagging=f'ID={vrf_id}')
                logger.debug(rd)
                logger.debug(f"trying to put file in {settings.VRF_PRIVATE_MEDIA_LOCATION}") 
            except:
                send_sns(vrf_id, "tagging uploaded file", traceback.format_exc())

        if context.get('first_contact'):
            context['first_contact'] = str(context['first_contact'])

        try:
            report_template = get_template("vincepub/email-md.txt")

            s3Client.put_object(Body=report_template.render(context=context),
                                Bucket=settings.VP_PRIVATE_BUCKET_NAME, Key=f'{settings.VRF_REPORT_DIR}/{vrf_id}.txt')
        except:
            send_sns(vrf_id, "writing report to s3 bucket", traceback.format_exc())
            logger.debug(report_template.render(context=context))

        context.pop('user_file')
        send_sns_json("vul", subject, json.dumps(context))
        context['user_file'] = attachment

        # create crfollowup
        cr = CRFollowUp(cr = newrequest,
                        title = "submitted vulnerability reporting form",
                        user=self.request.user)
        cr.save()

                        
        # if reporter provided an email, send an ack email 
        reporter_email = context.get('contact_email')
        if reporter_email:
            autoack_email_template = get_template("vincepub/email-general.txt")
            sesclient = boto3.client('ses', 'us-east-1')
            try:
                response = sesclient.send_email(
                    Destination={
                        'ToAddresses': [context['contact_email']],
                    },
                    Message= {
                        'Body': {
                            'Text': {
                                'Data': html.unescape(autoack_email_template.render(context=context)),
                                'Charset': 'UTF-8',
                            },
                        },
                        'Subject': {
                            'Charset': 'UTF-8',
                            'Data': f'Thank you for submitting {settings.REPORT_IDENTIFIER}{vrf_id} to VINCE'
                        },
                    },
                    Source= f'{settings.DEFAULT_VISIBLE_NAME} DONOTREPLY <{settings.DEFAULT_FROM_EMAIL}>'
                )
            except ClientError as e:
                logger.debug("ERROR SENDING EMAIL")
                send_sns(vrf_id, "Sending ack email for vul reporting form", e.response['Error']['Message'])
                logger.debug(e.response['Error']['Message'])
            except:
                logger.debug("ERROR SENDING EMAIL - Not a ClientError")
                send_sns(vrf_id, "Sending ack email for vul reporting form", "something")
                logger.debug(traceback.format_exc())
            else:
                logger.debug("Email Sent! Message ID: "),
                logger.debug(response['MessageId'])

            # redirect to a new URL                                                                             
        return render(self.request, 'vincepub/success.html', context)

    def form_invalid(self, form):
        logger.debug(form.errors)
        return render(self.request, self.template_name, {'form': form, 'reportpage': 3})
    #return super().form_invalid(form)


class CaseAccessPermission(BasePermission):
    message = "Forbidden"

    def has_permission(self, request, view):
        case = get_object_or_404(Case, vuid=view.kwargs.get('vuid'))
        return _is_my_case(request.user, case.id)

class LimitedCaseAccessPermission(BasePermission):
    message = "Forbidden"

    def has_permission(self, request, view):
        if (is_in_group_vincelimited(request.user)):
            return True
        
        case = get_object_or_404(Case, vuid=view.kwargs.get('vuid'))
        return _is_my_case(request.user, case.id)
    
class PendingUserPermission(BasePermission):
    message = "Access is Denied. User is in pending state"

    def has_permission(self, request, view):
        if request.user.vinceprofile.pending == True:
            return False
        else:
            return True
    
class CasesAPIView(generics.ListAPIView):
    #authentication_classes = (JSONWebTokenAuthentication,)
    serializer_class = CaseSerializer
    permission_classes = (IsAuthenticated,PendingUserPermission)
    
    def get_view_name(self):
        return "My Cases"

    def get_queryset(self):
        if (is_in_group_vincelimited(self.request.user)):
            return Case.objects.all().order_by('-modified')
        
        my_cases = _get_my_cases(self.request.user)
        return my_cases.order_by('-modified')
        

class CaseAPIView(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
#    authentication_classes = (JSONWebTokenAuthentication,)
    serializer_class = CaseSerializer
    permission_classes = (IsAuthenticated,PendingUserPermission,LimitedCaseAccessPermission,)
    lookup_field = "vuid"
    
    def get_view_name(self):
        return f"Case Detail"

    def get_queryset(self):
        if (is_in_group_vincelimited(self.request.user)):
            return Case.objects.all().order_by('-modified')
        
        my_cases = _get_my_cases(self.request.user)
        return my_cases.order_by('-modified')

class CasePostAPIView(generics.ListAPIView):
#    authentication_classes = (JSONWebTokenAuthentication,)
    serializer_class = PostSerializer
    permission_classes = (IsAuthenticated,CaseAccessPermission,PendingUserPermission)

    def get_view_name(self):
        return f"Posts for Case"

    def get_queryset(self):
        case = get_object_or_404(Case, vuid=self.kwargs['vuid'])
        return Post.objects.filter(case=case, current_revision__isnull=False).order_by('-created')

class CaseReportAPIView(generics.RetrieveAPIView):
#    authentication_classes = (JSONWebTokenAuthentication,)
    serializer_class = OrigReportSerializer
    permission_classes = (IsAuthenticated,LimitedCaseAccessPermission,PendingUserPermission)
    lookup_field = "vuid"
    
    def get_view_name(self):
        return f"Original Report for Case"

    def get_object(self):
        case = get_object_or_404(Case, vuid=self.kwargs['vuid'])
        return case.cr
    
    
class CaseVulAPIView(generics.ListAPIView):
#    authentication_classes = (JSONWebTokenAuthentication,)
    serializer_class = VulSerializer
    permission_classes = (IsAuthenticated,LimitedCaseAccessPermission,PendingUserPermission)

    def get_view_name(self):
        return f"Case Vulnerabilities"

    def get_queryset(self):
        case = get_object_or_404(Case, vuid=self.kwargs['vuid'])
        return CaseVulnerability.objects.filter(case=case, deleted=False)


class CaseVendorVulStatusAPIView(generics.ListAPIView):
#    authentication_classes = (JSONWebTokenAuthentication,)
    serializer_class = VendorStatusSerializer
    permission_classes = (IsAuthenticated,CaseAccessPermission,PendingUserPermission)

    def get_view_name(self):
        return f"Vulnerability Specific Vendor Status for Case"

    def get_queryset(self):
        case = get_object_or_404(Case, vuid=self.kwargs['vuid'])
        return CaseMemberStatus.objects.filter(member__case=case)
    
class CaseVendorStatusAPIView(generics.ListAPIView):
#    authentication_classes = (JSONWebTokenAuthentication,)
    serializer_class = VendorSerializer
    permission_classes = (IsAuthenticated,LimitedCaseAccessPermission,PendingUserPermission)

    def get_view_name(self):
        return f"Case Vendors"

    def get_queryset(self):
        case = get_object_or_404(Case, vuid=self.kwargs['vuid'])
        return CaseMember.objects.filter(case=case, coordinator=False, reporter_group=False).exclude(group__groupcontact__isnull=True).order_by("group__groupcontact__contact__vendor_name")


class CVEVulAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,PendingUserPermission)

    def get_view_name(self):
        return f"CVE Lookup View"

    def get(self, request, *args, **kwargs):
        cve = f"CVE-{self.kwargs['year']}-{self.kwargs['pk']}"
        cvewo = f"{self.kwargs['year']}-{self.kwargs['pk']}"
        report = None
        old_report = VUReport.objects.raw(f"SELECT * from vincepub_vureport where cveids::text like '%%{cve}%%'")
        for x in old_report:
            cveids = x.cveids
            if cve in cveids:
                #psql will match on CVE-2020-1398 on CVE-2020-13984 and that's not what we want
                # so doublecheck here
                report = VUReportSerializer(x)

        vul = NoteVulnerability.objects.filter(cve=cvewo).first()
        if vul:
            #VINCE published vul
            vuln = VPVulSerializer(vul)
            vendors = VendorVulStatus.objects.filter(vul=vul)
            if vendors:
                vv = VendorVulSerializer(vendors, many=True)
                return Response({'vulnerability':vuln.data,
                                 'note':report.data,
                                 'vendors':vv.data})
            else:
                return Response({'vulnerability':vuln.data,
                                 'note':report.data,
                                 'vendors':[]})
        if report:
            #OLD pre-vince report
            #make a vul record:
            vul = {'note':x.idnumber,
                   'cve':cvewo,
                   'description':f"http://web.nvd.nist.gov/vuln/detail/{ cve }",
                   'uid': cve,
                   'case_increment':1,
                   'date_added':x.datefirstpublished,
                   'dateupdated':x.dateupdated}
            # check for vendors
            vendors = VendorRecord.objects.filter(vuid=x.vuid)
            if vendors:
                vv = NewVendorRecordSerializer(vendors, many=True)
                return Response({'vulnerability': vul,
                                 'note':report.data,
                                 'vendors':vv.data})
            else:
                return Response({'vulnerability': vul,
                                 'note':report.data,
                                 'vendors':[]})
        else:
            # is this a VINCEComm vul?
            vul = CaseVulnerability.objects.filter(cve=cvewo).first()
            if vul:
                #does this person have access to it?
                if _is_my_case(self.request.user, vul.case.id):
                    vuln = VulSerializer(vul)
                    case = CaseSerializer(vul.case)
                    vendors = CaseMemberStatus.objects.filter(vulnerability=vul)
                    if vendors:
                        vv = VendorStatusSerializer(vendors, many=True)

                        return Response({'vulnerability': vuln.data,
                                         'note':'NOT Public',
                                         'vendors': vv.data,
                                         'case': case.data})
                    else:
                        return Response({'vulnerability':vuln.data,
                                         'note':'NOT Public',
                                         'vendors':[],
                                         'case': case.data})

        raise Http404


    
class UpdateVendorStatusAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,CaseAccessPermission,PendingUserPermission)
    serializer_class = VendorStatusUpdateSerializer
    
    def post(self, request, *args, **kwargs):
        case = get_object_or_404(Case, vuid=self.kwargs['vuid'])
        my_groups = _my_groups_for_case(self.request.user, case)
        vendor_groups = my_groups.filter(coordinator=False, reporter_group=False)
        print(vendor_groups)
        if not(vendor_groups):
            raise exceptions.PermissionDenied(_('User not in vendor group'))
        vuls = CaseVulnerability.objects.filter(case=case)
        if not(vuls):
            raise exceptions.MethodNotAllowed(_('No vuls identified. Status not needed.'))
        data = JSONParser().parse(request)
        print(data)
        affected = []
        unknown = []
        notaffected = []
        for vu in data:
            # get vendor id
            vul_status = None
            status_serializer = VendorStatusUpdateSerializer(data=vu)
            if status_serializer.is_valid():
                if len(vendor_groups) > 1:
                    vendor_id = status_serializer.data.get("vendor")
                    if vendor_id:
                        my_org = vendor_groups.filter(group__groupcontact__contact__id=vendor_id).first()
                        if not(my_org):
                            raise Http404
                    else:
                        return JsonResponse({'type':'multiple-vendors',
                                             'title': 'Vendor ID is required',
                                             'status': rest_status.HTTP_400_BAD_REQUEST,
                                             'detail': 'User belongs to multiple groups. Use vendor information API to retrieve vendor ID for organization'}, status=rest_status.HTTP_400_BAD_REQUEST)
                else:
                    my_org = vendor_groups[0]
                    
                status = get_status_int(status_serializer.data["status"])
                if status == None:
                    return JsonResponse({'type': 'invalid-status',
                                         'status': rest_status.HTTP_400_BAD_REQUEST,
                                         'title':f'{status_serializer.data["status"]} is an invalid status', 'detail': 'Affected/Not Affected/Unknown are valid statuses'}, status = rest_status.HTTP_400_BAD_REQUEST)
                if re.match('cve-', status_serializer.data["vulnerability"], re.I):
                    cve_id = status_serializer.data["vulnerability"][4:]
                    vul_status = vuls.filter(cve=cve_id).first()
                    if not(vul_status):
                        return JsonResponse({'type': 'invalid-vulnerability',
                                             'status': rest_status.HTTP_400_BAD_REQUEST,
                                             'title': f'{status_serializer.data["vulnerability"]} is an invalid vulnerability', 'detail': 'Use vulnerability API to find vulnerability name or CVE ID'}, status=rest_status.HTTP_400_BAD_REQUEST)
                elif re.match(settings.CASE_IDENTIFIER, status_serializer.data["vulnerability"], re.I):
                    vul_status = vuls.filter(case_increment = status_serializer.data["vulnerability"][-1:]).first()
                    if not(vul_status):
                        return JsonResponse({'type': 'invalid-vulnerablity',
                                             'status': rest_status.HTTP_400_BAD_REQUEST,
                                             'title': f'{status_serializer.data["vulnerability"]} is an invalid vulnerability', 'detail': 'Use vulnerability API to find vulnerability name or CVE ID'}, status=rest_status.HTTP_400_BAD_REQUEST)
                else:
                    return JsonResponse({'type': 'invalid-vulnerability',
                                         'status': rest_status.HTTP_400_BAD_REQUEST,
                                         'title': f'{status_serializer.data["vulnerability"]} is an invalid vulnerability', 'detail': 'Use vulnerability API to find vulnerability name or CVE ID'}, status=rest_status.HTTP_400_BAD_REQUEST)
            else:
                errors = {'type': 'invalid-format', 'detail': status_serializer.errors,
                          'status': rest_status.HTTP_400_BAD_REQUEST, 'title':'missing required fields or invalid format'}
                return JsonResponse(errors, status=rest_status.HTTP_400_BAD_REQUEST)

            if status == 1:
                affected.append(vul_status.id)
            elif status == 2:
                notaffected.append(vul_status.id)
            elif status == 3:
                unknown.append(vul_status.id)

            references = "\n".join(item for item in status_serializer.data["references"])
            if len(vuls) == 1:
                old_stmt = CaseStatement.objects.filter(case=case, member=my_org).first()
                if old_stmt:
                    if old_stmt.statement != status_serializer.data["statement"]:
                        create_vendor_status_change("statement", old_stmt.statement,
                                                    status_serializer.data["statement"],
                                                    self.request.user, my_org, case=case)
                    if old_stmt.references != references:
                        create_vendor_status_change("references", old_stmt.references,
                                                    references,
                                                    self.request.user, my_org, case=case)
                    if old_stmt.share != status_serializer.data["share"]:
                        create_vendor_status_change("share toggle", old_stmt.share, status_serializer.data["share"],
                                                    self.request.user, my_org, case=case)
                stmt = CaseStatement.objects.update_or_create(case=case, member=my_org,
                                                              defaults={'statement':status_serializer.data["statement"],
                                                                        'references':references,
                                                                        'share':status_serializer.data["share"]})
            else:
                cstat = 3
                status = CaseMemberStatus.objects.filter(vulnerability=vul_status, member=my_org).first()
                if status:
                    cstat = status.status
                    if status.statement != status_serializer.data["statement"]:
                        create_vendor_status_change("statement", status.statement,
                                                    status_serializer.data["statement"],
                                                    self.request.user, my_org, cv=vul_status)
                    if status.references != references:
                        create_vendor_status_change("references", status.references,
                                                    references,
                                                    self.request.user, my_org, cv=vul_status)
                    
                status = CaseMemberStatus.objects.update_or_create(vulnerability=vul_status,
                                                                   member=my_org,
                                                                   defaults = {'statement':status_serializer.data["statement"],
                                                                               'references':references,
                                                                               'status': cstat,
                                                                               'user': self.request.user})
                            
        update_status(my_org, self.request, None, affected=affected, unknown=unknown, unaffected=notaffected)

        return JsonResponse({'response': 'success', 'message':'Your status has been successfully recorded.'}, status=200)
            
            
class CaseVulNoteAPIView(generics.RetrieveAPIView):
    serializer_class = VulNoteSerializer
    permission_classes = (IsAuthenticated,CaseAccessPermission,PendingUserPermission)
    lookup_field = "vuid"
    
    def get_view_name(self):
        return "Draft Vulnerability Note for Case"

    def get_object(self):
        case = get_object_or_404(Case, vuid=self.kwargs['vuid'])
        if case.note:
            return case.note.vulnote

class VendorInfoAPIView(generics.ListAPIView):
    serializer_class = VendorInfoSerializer
    permission_classes = (IsAuthenticated, PendingUserPermission)

    def get_view_name(self):
        return f"Vendor Information"

    def get_queryset(self):
        email = VinceCommEmail.objects.filter(email=self.request.user.email, status=True).values_list('contact__id', flat=True)
        return VinceCommContact.objects.filter(id__in=email)


class VendorLookupView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, generic.TemplateView):
    login_url = "vinny:login"
    template_name = "test.html"
    
    def test_func(self):
        return is_in_group_vincetrack(self.request.user)

    def post(self, request, *args, **kwargs):
        g_users = []
        if self.request.POST.get('tag'):
            # get all emails for this tag
            contacts = VinceCommContact.objects.filter(vendor_name=self.request.POST['tag']).values_list('groupcontact__group__id', flat=True)
            if contacts:
                g_users = list(User.objects.filter(groups__id__in=contacts).values_list('email', flat=True))
            elif self.request.POST.get('case'):
                #lookup user
                users = User.objects.filter(vinceprofile__preferred_username=self.request.POST['tag'])
                for u in users:
                    if _is_my_case(u, self.request.POST.get('case')):
                        g_users.append(u.email)
            return JsonResponse({'emails': g_users}, status=200)
        else:
            return JsonResponse({'response': "invalid"}, status=400)


class CreateServiceAccountView(LoginRequiredMixin,TokenMixin,UserPassesTestMixin,FormView):
    template_name = 'vinny/serviceaccount.html'
    login_url =	"vinny:login"
    form_class = CreateServiceAccount
    #only group admins have access
    
    def test_func(self):
        self.admin = None
        if is_in_group_vincegroupadmin(self.request.user):
            gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
            self.admin = VinceCommGroupAdmin.objects.filter(contact__id=gc.contact.id, email__email=self.request.user.email).first()
            if self.admin:
                return PendingTestMixin.test_func(self)
        return False

    def get_context_data(self, **kwargs):
        context = super(CreateServiceAccountView, self).get_context_data(**kwargs)
        gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
        context['gc'] = gc
        initial = {'preferred_username': f'{gc.contact.vendor_name}_service'}
        form = CreateServiceAccount(initial=initial)
        context['form'] = form
        return context

    def get_success_url(self):
        return reverse_lazy("vince:admin")
    
    def post(self, request, *args, **kwargs):
        logger.debug(self.request.POST)

        #does a service account already exist for this group?
        gc = get_object_or_404(GroupContact, id=self.kwargs.get('vendor_id'))
        if User.objects.filter(groups__in=[gc.group], vinceprofile__service=True).exists():
            return JsonResponse({'response': 'This group already has a service account.'}, status=200)
        
        form = CreateServiceAccount(self.request.POST)

        if form.is_valid():
            if form.cleaned_data["password1"] != form.cleaned_data["password2"]:
                return JsonResponse({'response': 'Passwords did not match.'}, status=200)

            #Check users                                                                                              
            old_user = User.objects.using('vincecomm').filter(email=form.cleaned_data['email']).first()

            if old_user:
                return JsonResponse({'response': 'This user may already exist.  Please check email and try again.'}, status=200)
                        
            response, error = create_service_account(request)
            if response == None:
                return JsonResponse({'response': f'Error creating account. {error}'}, status=200)

            messages.success(
                self.request,
                _('The account was successfully created.'))
                
            # now create the user in VINCE
            service = User.objects.create_user(username=form.cleaned_data['email'],
                                               email=form.cleaned_data['email'],
                                               password=form.cleaned_data['password1'])

            service.vinceprofile.service = True
            service.vinceprofile.multifactor = True
            service.vinceprofile.pending = False
            service.vinceprofile.preferred_username = form.cleaned_data['preferred_username']
            service.vinceprofile.save()

            #add this account to the group
            gc.group.user_set.add(service)

            vcemail, created = VinceCommEmail.objects.update_or_create(contact=gc.contact,
                                                                       email=form.cleaned_data['email'],
                                                                       defaults = {'name': form.cleaned_data['preferred_username'],
                                                                          'status':True,
                                                                          'email_list':True})
            if form.cleaned_data['send_email'] == False:
                vcemail.email_function = 'EMAIL'
                vcemail.save()

            action = VendorAction(title=f"{self.request.user.vinceprofile.vince_username} created service account {service.email}",
                               	  user=self.request.user)
            action.save()
            changes = ContactInfoChange(contact=gc.contact,
                                        model="Service Account",
                                        action=action,
                                        field="NEW",
                                        old_value="",
                                        new_value=service.email)
            changes.save()

            contact_update.send_ticket([changes], gc.contact, self.request.user)

            self.request.session['CONFIRM_ID'] = service.id
            self.request.session['SERVICE'] = gc.contact.id
            # email group to let them know that this change was made

            group_users = User.objects.filter(groups__in=[gc.group], is_active=True, vinceprofile__pending=False).exclude(vinceprofile__service=True)
            for u in group_users:
                send_courtesy_email("service_account_created", u)
            
            return JsonResponse({'response':'success', 'action': reverse("cogauth:account_activation_sent")}, status=200)

        
        return JsonResponse({'response': 'Invalid Form Entry. Please try again.'}, status=200)

    
    
def csrf_failure_view(request, reason=""):
    ctx = {'message': 'Error'}
    return render_to_response("vinny/csrf_fail.html", ctx)


class CaseCSAFAPIView(generics.RetrieveAPIView):
    serializer_class = CSAFSerializer
    permission_classes = (IsAuthenticated,CaseAccessPermission,PendingUserPermission)

     
    def get_view_name(self):
        return "Vulnerability Advisory in CSAF format"
 
    def get_object(self):
        svuid = self.kwargs['vuid']
        case = get_object_or_404(Case, vuid=svuid)
        casevuls = CaseVulnerability.objects.filter(case=case, deleted=False)
        if casevuls:
            return case
