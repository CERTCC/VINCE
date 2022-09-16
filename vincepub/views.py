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
from __future__ import print_function
from django.shortcuts import render, get_object_or_404, render_to_response, redirect
from django.views import generic
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, Http404
from django.views.generic.edit import FormView, UpdateView, CreateView, FormMixin
from vincepub.models import *
from vincepub.forms import *
from bakery.views import BuildableDetailView, BuildableListView, Buildable404View
from django.template.defaulttags import register
from django.forms.fields import CheckboxInput, SelectMultiple, DateField
from django.template import RequestContext
from django.contrib.postgres.search import SearchVector, SearchRank
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_text
from django.core.paginator import Paginator
from django.db import connection
from django.db.models import Q
from django.forms.utils import ErrorList
from django.template.loader import get_template
from django import forms
from rest_framework import viewsets, mixins
from . import serializers
from rest_framework.response import Response
from rest_framework import generics
from rest_framework.permissions import IsAdminUser, AllowAny
from itertools import chain
from django.conf import settings
import random
import html
from datetime import datetime, date, timedelta, tzinfo
import requests
import tempfile
import shutil
import subprocess
import unicodedata
import json
import re
import shlex
import boto3
import traceback
from botocore.exceptions import ClientError
from botocore.client import Config
from django.views.decorators.csrf import csrf_exempt
from dateutil.parser import parse
from operator import __or__ as OR
from functools import reduce
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

GOOGLE_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

@register.filter(name="strip_list")
def strip_list(var):
    return ", ".join(var)

@register.filter(name="is_affected")
def is_affected(var, obj):
    if var == "Affected" or var == "Vulnerable":
        return True
    else:
        return False

@register.filter(name="exists")
def exists(var):
    if var and var != "None":
        return True

@register.filter(name="prov_statement")
def prov_statement(stmt, vendor):
    bp = False
    if stmt and stmt != "None":
        if stmt == "No statement is currently available from the vendor regarding this vulnerability.":
            bp = False
        elif stmt == "We have not received a statement from the vendor.":
            bp = False
        else:
            bp = True

    for item in vendor:
        if item.statement:
            return True

    # no other statement
    return bp
    
@register.filter(name="other_statement")
def other_statement(stmt, vendor):
    bp = False
    if stmt and stmt != "None":
        if stmt == "No statement is currently available from the vendor regarding this vulnerability.":
            bp = True
        elif stmt == "We have not received a statement from the vendor.":
            bp = True
    else:
        bp = True
        
    for item in vendor:
        if item.statement:
            if bp:
                return False
            else:
                return True
    # no other statement
    return True

@register.filter(name="get_affected")
def get_affected(var, obj):
    if var == "Affected" or var == "Vulnerable":
        return "<i class=\"fas fa-exclamation-triangle\" aria-hidden=\"true\" style=\"color:red;\" title=\"Status: Affected\"></i>"
    elif var == "Unknown":
        return "<i class=\"fas fa-question-circle\" aria-hidden=\"true\" title=\"Status: Unknown\"></i>"
    else:
        return "<i class=\"fas fa-check-circle\" aria-hidden=\"true\" style=\"color:green;\" title=\"Status: Unaffected\"></i>"

@register.filter(name="splitlines")
def splitlines(var):
    return var.splitlines()

@register.filter(name='sortvuls')
def sortvuls(vuls):
    if vuls:
        return vuls.order_by('uid')
    return None

@register.simple_tag()
def show_vp_status(status="Unknown"):
    if status == "Affected" or status == "Vulnerable":
        return "<span class=\"label alert\">Affected</span>"
    elif status in ["Unaffected", "Not Affected", "Not Vulnerable"]:
        return "<span class=\"label success\">Not Affected</span>"
    else:
        return "<span class=\"label warning\">Unknown</span>"
    
@register.filter(name="get_statement")
def get_statement(var, obj):
    statement = var.filter(vendorrecordid=obj).values('statement').first()
    if statement:
        if statement["statement"] == "<p>No statement is currently available from the vendor regarding this vulnerability.</p>":
            return "<p>We have not received a statement from the vendor.</p>"
        return statement["statement"]
    else:
        statement= VendorRecord.objects.filter(vendorrecordid=obj).values('statement').first()
        if statement:
            if statement["statement"] != "":
                return statement["statement"]
            else:
                return "We have not received a statement from the vendor."

@register.filter(name="get_information")
def get_information(var, obj):
    information = var.filter(vendorrecordid=obj).values('information').first()
    if information:
        if information["information"] != "<p></p>":
            return information["information"]
        else:
            return "We are not aware of further vendor information regarding this vulnerability."
    else:
        information = VendorRecord.objects.filter(vendorrecordid=obj).values('vendorinformation').first()
        if information:
            if information["vendorinformation"] != "":
                return information["vendorinformation"]
            else:
                return "We are not aware of further vendor information regarding this vulnerability."

@register.filter(name="get_addendum")
def get_addendum(var, obj):
    addendum = var.filter(vendorrecordid=obj).values('addendum').first()
    if addendum:
        if addendum["addendum"]:
            return addendum["addendum"]
    else:
        addendum = VendorRecord.objects.filter(vendorrecordid=obj).values('addendum').first()
        if addendum:
            return addendum["addendum"]

@register.filter(name="get_references")
def get_references(var, obj):
#    urls = var.filter(vendorrecordid=obj).values('urls').first()
#    if urls:
#        if urls["urls"]:
#            return urls["urls"]
#    else:
    html = "<ul class='ul_nobullet'>"
    references = VendorRecord.objects.filter(vendorrecordid=obj).values('vendorurls').first()
    if references:
        try:
            urls = references['vendorurls'].split('http')
            for url in urls:
                if url != "":
                    url = "http" + url.replace(" ", "")
                    html += "<li><a href=\""+url+"\">"+url+"</a></li>"
        except:
            pass
    html += "</ul>"
    return html

@register.filter(name="get_summary")
def get_summary(value):
    if not(value.startswith("###")):
        return value
    lines = value.split('\r\n')
    summary = []
    #skip first line should be overview
    for l in lines[1:]:
        if "###" in l:
            break
        if l:
            summary.append(l)
    if summary:
        return "\n".join(summary)
    return value
            

@register.filter(name="addendum_boilerplate")
def addendum_boilerplate(value):
    if value:
        if value == "There are no additional comments at this time.":
            return False
        else:
            return True
    else:
        return False

@register.filter(name="subCAN")
def subCAN(value):
    if value:
        value = re.sub(r'^CAN', 'CVE', value)
        return value
    return

@register.filter(name="is_list")
def is_list(var, obj):
    return isinstance(var, list)

@register.filter(name='is_checkbox')
def is_checkbox(value):
    return isinstance(value, CheckboxInput)

@register.filter(name='is_multi_checkbox')
def is_multi_checkbox(value):
    return isinstance(value, SelectMultiple)

@register.filter(name='vi_bullhorn')
def vi_bullhorn(value):
    if value:
        if value == "We are not aware of further vendor information regarding this vulnerability.":
            return False
        elif value == "The vendor has not provided us with any further information regarding this vulnerability.":
            return False
        elif value == "VendorInformation":
            return False

        return True
    return False

@register.filter(name='htmlcut')
def htmlcut(value):
    if value:
        value = re.sub(r'^\\"', '', value)
        value = re.sub(r'=\\"', '="', value)
        value = re.sub(r'<font color="#0000FF\\">', '', value)
        value = re.sub(r'</font>', '', value)

        value = value.replace('\\n','').replace('\\"', '"').replace('\\u200e','&#x200e;').replace('\\u00a0','&#x00a0;').replace('\\u','&#x').replace('\"\"', '').replace('\\t', '').replace("\\\\", "\\")
#        value = value.replace('\\n','').replace('\\"', '').replace('\\u200e','&#x200e;').replace('\\u00a0','&#x00a0;').replace('\\u','&#x').replace('\"\"', '').replace('\\t', '')
        imgs = re.findall(r'<img ([^>]*)>', value, flags=0)
        attachments = re.findall(r'<a href=(\"\/CERT\/services\/vul-notes\.nsf/[a-z0-9\/]+\$FILE\/([-_a-zA-Z0-9\.%]+)\") ', value, flags=0)

        for attach in attachments:
            fa = attach[1].replace('%20', ' ')
            value = value.replace(attach[0], "\"/static/vincepub/files/"+fa+"\"")


        for img in imgs:
            srcstr = re.search(r'src="([^ ]*)"', img, flags=0)
            logger.debug(srcstr.group(0))


            if srcstr:
                imgname = srcstr.group(1)
                logger.debug(imgname)
                imgname = imgname[(imgname.rfind('/')):]
                finalimgname = imgname[1:(imgname.rfind('?'))]
                logger.debug(imgname)
                logger.debug(finalimgname)

                fformat = imgname[(imgname.find('=')+1):]
                imgname = "%s.%s" % (finalimgname, fformat)

                value = value.replace(srcstr.group(0), "src=\"/static/vincepub/images/"+imgname+"\"")

        return value
    else:
        return


@register.filter(name='vs_bullhorn')
def vs_bullhorn(value):
    if value:
        if value == "No statement is currently available from the vendor regarding this vulnerability.":
            return False
        elif value == "We have not received a statement from the vendor.":
            return False
        return True
    return False

@register.filter(name='va_bullhorn')
def va_bullhorn(value):
    if value:
        if value == "There are no additional comments at this time.":
            return False
        elif value == f"The {settings.ORG_NAME} has no additional comments at this time.":
            return False
        return True
    return False

@register.filter(name='get_filter')
def get_filter(value):
    filt="vinfo"
    info = False
    if is_affected(value.status, ""):
        filt = filt + " affected"
    elif value.status == "Unknown":
        filt = filt + " unknown"
    else:
        filt = filt + " notaffected"
    if vs_bullhorn(value.statement):
        filt = filt + " info"
        info = True
    if not(info) and vi_bullhorn(value.vendorinformation):
        filt = filt + " info"
        info = True
    if not(info) and va_bullhorn(value.addendum):
        filt = filt = " info"
    return filt

@register.filter(name='get_vt_filter')
def get_vt_filter(value, item):
    filt = 'vinfo'
    stmt = False
    if value.filter(status=1):
        filt = filt + " affected"
    elif value.filter(status=2):
        filt = filt + " notaffected"
    else:
        filt = filt + " unknown"
    if value.exclude(statement__isnull=True):
        filt = filt + " info"
        stmt = True

    if not(stmt):
        if value.exclude(references__isnull=True):
            filt = filt + " info"
            stmt = True
    if not(stmt):
        if vs_bullhorn(item.statement):
            filt = filt + " info"
            stmt = True

    if not(stmt):
        if va_bullhorn(item.addendum):
            filt = filt + " info"
            stmt = True

    if not(stmt):
        if item.references and item.references != "None":
            filt = filt + " info"

    return filt

@register.filter(name='filter_by_status')
def filter_by_status(vendors):
    affected = vendors.filter(vendorvulstatus__status=VendorVulStatus.AFFECTED_STATUS).distinct('vendor').order_by('vendor')
    a = list(affected.values_list('id', flat=True))
    notaffected = vendors.filter(vendorvulstatus__status=VendorVulStatus.UNAFFECTED_STATUS).distinct('vendor').order_by('vendor')
    if a:
        notaffected = notaffected.exclude(id__in=a)
    na = list(notaffected.values_list('id', flat=True))
    unknown = vendors.filter(Q(vendorvulstatus__status=VendorVulStatus.UNKNOWN_STATUS)|Q(vendorvulstatus__isnull=True)).distinct('vendor').order_by('vendor')
    if a or na:
        alist =	a + na
        unknown = unknown.exclude(id__in=alist)
    unknown_w_info = []
    for vendor in unknown:
        filt = get_vt_filter(vendor.vendorvulstatus.all(), vendor)
        #space is intentional - need to distinguish between vinfo and info
        if " info" in filt:
            unknown = unknown.exclude(id=vendor.id)
            unknown_w_info.append(vendor.id)
    unknown_w_info = vendors.filter(id__in=unknown_w_info).distinct('vendor').order_by('vendor')
    x = list(chain(affected, notaffected, unknown_w_info, unknown))
    return x


@register.filter
def vendor_vul_status(status, vul):
    s = status.filter(vul=vul).first()
    return s

@register.filter
def cvevuls(vuls):
    return vuls.filter(cve__isnull=False)

class EST(tzinfo):
    def utcoffset(self, dt):
        return timedelta(hours=-5)

    def dst(self, dt):
        return timedelta(0)

# this function does not check for collisions; the chances of a collision within
# a short period of time are low enough that we should be able to distinguish and
# find a relevant email in the archive.
# NOTE: get Form error when use variable in the random statement, why?
#         for now, just use range(6) instead of range(var)
def vrf_id_generator(vrf_id_size=5, chars='BCDFGHJKLMNPQRSTVWXYZ'):
    return ''.join(random.choice(chars) for _ in range(5))

def get_vrf_id():
    today = datetime.now(EST())
    # Vul Reports use format: {REPORT_IDENTIFIER}YY-MM-XXXX (YY = 2digit year, MM = month)
    vrf_id_rnd = vrf_id_generator()
    vrf_id_month = str(today.month) if today.month > 9 else ('0' + str(today.month))
    vrf_id = str(today.year)[2:] + '-' + vrf_id_month + '-' + vrf_id_rnd
    return vrf_id

class VinceView(generic.TemplateView):
    template_name = 'vincepub/vince.html'

    def get_context_data(self, **kwargs):
        context = super(VinceView, self).get_context_data(**kwargs)
        context['vincepage'] = 1
        return context

class SearchView(generic.TemplateView):
    template_name = 'vincepub/index.html'

    def get_context_data(self, **kwargs):
        context = super(SearchView, self).get_context_data(**kwargs)
        context['pub_list'] = VUReport.objects.order_by('-datefirstpublished')[:5]
        context['homepage'] = 1
        return context


class DatePublicView(generic.ListView):
    template_name = 'vincepub/viewby.html'
    model = VUReport
    paginate_by = 15

    def get_queryset(self):
        if self.kwargs['asc_or_desc'] == "asc":
            return VUReport.objects.order_by('publicdate')
        else:
            return VUReport.objects.order_by('-publicdate')

    def get_context_data(self, **kwargs):
        context = super(DatePublicView, self).get_context_data(**kwargs)
        context['tableheader'] = 'Date Public'
        context['title'] = "Notes by Date Public"
        context['page'] = 1
        context['notespage'] = 1
        if self.kwargs['asc_or_desc'] == "asc":
            context['asc_or_desc'] = 'desc'
            context['publicclass'] = 'sortasc'
        else:
            context['asc_or_desc'] = 'asc'
            context['publicclass'] = 'sortdesc'
        context['publishclass']= 'sortheader'
        context['updateclass'] = 'sortheader'
        context['cvssclass'] = 'sortheader'
        return context

class DateUpdatedView(generic.ListView):
    template_name = 'vincepub/viewby.html'
    model = VUReport
    paginate_by = 15

    def get_queryset(self):
        if self.kwargs['asc_or_desc'] == "asc":
#            return VUReport.objects.exclude(dateupdated__isnull=True).exclude(datefirstpublished__isnull=True).exclude(publicdate__isnull=True).order_by('dateupdated')
            return VUReport.objects.order_by('dateupdated')
        else:
            return VUReport.objects.order_by('-dateupdated')

    def get_context_data(self, **kwargs):
        context = super(DateUpdatedView, self).get_context_data(**kwargs)
        context['tableheader'] = 'Date Updated'
        context['title'] = "Notes by Date Last Updated"
        context['page'] = 2
        context['notespage'] = 1
        if self.kwargs['asc_or_desc'] == "asc":
            context['asc_or_desc'] = 'desc'
            context['updateclass'] = 'sortasc'
        else:
            context['asc_or_desc'] = 'asc'
            context['updateclass'] = 'sortdesc'
        context['publishclass'] = 'sortheader'
        context['publicclass'] = 'sortheader'
        context['cvssclass'] = 'sortheader'
        return context

class DatePublishedView(generic.ListView):
    template_name = 'vincepub/viewby.html'
    model = VUReport
    paginate_by = 15

    def get_queryset(self):
        if self.kwargs['asc_or_desc'] == "asc":
            return VUReport.objects.order_by('datefirstpublished')
        else:
            return VUReport.objects.order_by('-datefirstpublished')

    def get_context_data(self, **kwargs):
        context = super(DatePublishedView, self).get_context_data(**kwargs)
        context['tableheader'] = 'Date Published'
        context['title'] = "Notes by Date Published"
        context['page'] = 3
        context['notespage'] = 1
        if self.kwargs['asc_or_desc'] == "asc":
            context['asc_or_desc'] = 'desc'
            context['publishclass']= 'sortasc'
        else:
            context['asc_or_desc'] = 'asc'
            context['publishclass']= 'sortdesc'
        context['publicclass'] = 'sortheader'
        context['updateclass'] = 'sortheader'
        context['cvssclass'] = 'sortheader'
        return context

class CVSSScoreView(generic.ListView):
    template_name = 'vincepub/viewby.html'
    model = VUReport
    paginate_by = 15

    def get_queryset(self):
        if self.kwargs['asc_or_desc'] == "asc":
            return VUReport.objects.exclude(cvss_environmentalscore="N/A").exclude(cvss_environmentalscore__isnull=True).order_by('cvss_environmentalscore')
        else:
            return VUReport.objects.exclude(cvss_environmentalscore="N/A").exclude(cvss_environmentalscore__isnull=True).order_by('-cvss_environmentalscore')


    def get_context_data(self, **kwargs):
        context = super(CVSSScoreView, self).get_context_data(**kwargs)
        context['tableheader'] = 'CVSS Score'
        context['title'] = "Notes by CVSS Score"
        context['page'] = 4
        context['notespage'] = 1
        if self.kwargs['asc_or_desc'] == "asc":
            context['asc_or_desc'] = 'desc'
            context['cvssclass'] = 'sortasc'
        else:
            context['asc_or_desc'] = 'asc'
            context['cvssclass'] = 'sortdesc'
        context['publishclass']= 'sortheader'
        context['publicclass'] = 'sortheader'
        context['updateclass'] = 'sortheader'
        context['cvssclass'] = 'sortdesc'
        return context

RE_POSTGRES_ESCAPE_CHARS = re.compile(r'[&:(|)!><]', re.UNICODE)
RE_SPACE = re.compile(r"[\s]+", re.UNICODE)


def escape_query(text, re_escape_chars):
    text = force_text(text)
    text = RE_SPACE.sub(" ", text)  # Standardize spacing.
    text = re_escape_chars.sub(" ", text)  # Replace harmful characters with space.
    text = text.strip()
    return text

    
def process_query(s):
    try:
        query = "&" .join("$${0}$$:*".format(word) for word in shlex.split(escape_query(s, RE_POSTGRES_ESCAPE_CHARS)))
    except ValueError:
        #shlex returns a ValueError when it doesn't have closing quote
        if s.endswith('\\'):
            if not s.endswith('\\\\'):
                s = s + '\\'
        s = s + '"'
        query = "&" .join("$${0}$$:*".format(word) for word in shlex.split(escape_query(s, RE_POSTGRES_ESCAPE_CHARS)))

    # this is for prefix searches
    query = re.sub(r'\s+', '<->', query)
    return query


class SearchResultView(generic.ListView):
    template_name = 'vincepub/searchresults.html'
    paginate_by = 10
    model = VUReport

    def get_context_data(self, **kwargs):
        context = super(SearchResultView, self).get_context_data(**kwargs)
        return context

    def get_queryset(self):
        return VUReport.objects.order_by('-datefirstpublished')

    def post(self, request, *args, **kwargs):
        if 'page' in self.request.POST:
            page = self.request.POST['page']
            if page == "":
                page = 1
        else:
            page = 1

        datefilter = []
        if 'years' in self.request.POST:
            yearlist = self.request.POST.getlist('years')
            for year in yearlist:
                if year != "":
                    datefilter.append(Q(datefirstpublished__year=year))

        #if self.request.POST['datestart']:
        #    datefilter.append(Q(publicdate__range=(DateField().clean(self.request.POST['datestart']),
 #                                                  DateField().clean(self.request.POST['dateend']))))

        res = VUReport.objects.all()

        wordSearch = None
        if 'wordSearch' in self.request.POST:
            if self.request.POST['wordSearch']:
                wordSearch = process_query(self.request.POST['wordSearch'])

        if 'vendor' in self.request.POST:
            if self.request.POST['vendor']:
                vendors = VendorRecord.objects.filter(vendor__icontains=self.request.POST['vendor']).values_list('vuid', flat=True)
                res = VUReport.objects.filter(vuid__in = vendors)

        if wordSearch:
            res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],
                            params=[wordSearch])

        if len(datefilter):
            res = res.filter(reduce(OR, datefilter))

        res = res.order_by('-datefirstpublished')
        total = len(res)
        paginator = Paginator(res, 10)

        try:
            results = paginator.page(page)
        except:
            results = paginator.page(1)
        
        return render(request, self.template_name, { 'object_list': results, 'total':total })


class IndexView(generic.FormView):
    template_name = 'vincepub/index_public.html'
    model = VUReport
    form_class = SearchForm
    success_url = 'vincepub/searchresults.html'

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        search = self.request.GET.get('q', False)
        if search:
            context['form'] = self.form_class(initial={'wordSearch':search})
            context['search'] = search

        context['publishclass']= 'sortheader'
        context['publicclass'] = 'sortdesc'
        context['updateclass'] = 'sortheader'
        context['cvssclass'] = 'sortheader'
        context['asc_or_desc'] = 'desc'
        context['pub_list'] = VUReport.objects.order_by('-datefirstpublished')[:5]                       
        context['homepage'] = 1 
        return context


    def form_invalid(self, form):
        logger.debug(form.errors)

        return super().form_invalid(form)


    def form_valid(self, form):
        logger.debug(self.request.POST)

        page = self.request.GET.get('page', 1)
        if self.request.POST['datestart']:
            startdate = DateField().clean(self.request.POST['datestart'])
            enddate = DateField().clean(self.request.POST['dateend'])
        else:
            startdate = DateField().clean('1975-01-01')
            enddate = timezone.now()

        wordSearch = None
        if self.request.POST['wordSearch']:
            wordSearch = process_query(self.request.POST['wordSearch'])

        if self.request.POST['vendor']:
            vendors = VendorRecord.objects.filter(vendor__icontains=self.request.POST['vendor']).values_list('vuid', flat=True)
            res = VUReport.objects.filter(vuid__in = vendors, publicdate__range=(startdate, enddate))
            if wordSearch:
                res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],
                                params=[wordSearch])

        else:
            res = VUReport.objects.filter(publicdate__range=(startdate, enddate))
            res = res.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],
                            params=[wordSearch])

        res = res.order_by('-datefirstpublished')
        paginator = Paginator(res, 15)
        res = paginator.page(page)

        return render(self.request, 'vincepub/searchresults.html', {'object_list': res, 'searchpage':2})


def send_sns(vul_id, issue, error):
    subject = "Problem with %s for %s" % (issue, vul_id)
    try:
        client = boto3.client('sns', settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_ERROR_SNS_ARN,
	    Subject=subject,
            Message=error)
        logger.debug("Response:{}".format(response))

    except:
        logger.debug('Error publishing to SNS')

def send_sns_json(form, subject, message):
    try:
        client = boto3.client('sns', settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_TRACK_SNS_ARN,
            Subject=subject,
            Message=message,
            MessageAttributes = {
                'ReportType': {
                    'DataType': 'String',
                    'StringValue': form
                    }
                })
        logger.debug(f"Response:{response}")
    except:
        send_sns('publishing json', 'send_sns_json failed', traceback.format_exc())
        logger.debug(traceback.format_exc())
        
        

def CloseAnnouncementCallout(request):
    response = HttpResponse("Hello vuls")
    response.set_signed_cookie("close_announcement", True)

    return response



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
        response = redirect("vincepub:search")
        input=input.replace('#', '%23')
        response['Location'] += '?q='+input
        return response
    else:
        return redirect("vincepub:search")

class InitialReportView(generic.TemplateView):
    template_name = 'vincepub/report.html'

    def get_context_data(self, **kwargs):
        context = super(InitialReportView, self).get_context_data(**kwargs)
        context['reportpage'] = 3
        return context


class VulCoordRequestView(generic.FormView):
    template_name = 'vincepub/reportcoord.html'
    model = VulCoordRequest
    form_class = VulCoordForm
    success_url = 'results.html'

    def get_context_data(self, **kwargs):
        context = super(VulCoordRequestView, self).get_context_data(**kwargs)
        context['reportpage'] = 3
        if self.request.GET.get('ics'):
            initial = {'ics_impact': True}
            context['form'] = VulCoordForm(initial=initial)
        return context

    def form_valid(self, form):

        #Begin reCAPTCHA validation
        recaptcha_response = self.request.POST.get('g-recaptcha-response')

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
        newrequest.save()
        context = form.cleaned_data
        coord_choice=[]
        context['vrf_id']=vrf_id
        for selection in context['coord_status']:
            coord_choice.append(form.fields['coord_status'].choices[int(selection)][1])
        if context['why_no_attempt']:
            context['coord_choice']= form.fields['why_no_attempt'].choices[int(context['why_no_attempt'])-1][1]

#        context['coord_choice'] = coord_choice
        context['vrf_id'] = f"{settings.REPORT_IDENTIFIER}{vrf_id}"
        context['vrf_date_submitted'] = datetime.now(EST()).isoformat()
        # get some meta info about who submitted this
        context['remote_addr'] = self.request.META['REMOTE_ADDR'] if 'REMOTE_ADDR' in self.request.META else "unknown"
        context['remote_host'] = self.request.META['REMOTE_HOST'] if 'REMOTE_HOST' in self.request.META else "unknown"
        context['http_user_agent'] = self.request.META['HTTP_USER_AGENT'] if 'HTTP_USER_AGENT' in self.request.META else "unknown"
        context['http_referer'] = self.request.META['HTTP_REFERER'] if 'HTTP_REFERER' in self.request.META else "unknown"
        # construct email
        context['submission_type'] = 'Vulnerability Report'
        subject = f"[{settings.REPORT_IDENTIFIER}{vrf_id}] "
        if context['product_name']:
            subject += context['product_name']
        else:
            subject += "New Report Submission (No Title Provided)"
        if context['tracking']:
            subject += " [" + context['tracking'] + "]"

        context["title"] = subject

        if len(subject) > 99:
            subject = subject[:99]

        cc_recipients = []

        s3Client = boto3.client('s3', region_name=settings.AWS_REGION, config=Config(signature_version='s3v4'))

        attachment = context.get('user_file')

        if attachment:

            context['s3_file_name'] = newrequest.user_file.name
            try:
                # tag object with vrf id
                rd = s3Client.put_object_tagging(Bucket=settings.VP_PRIVATE_BUCKET_NAME,
                                                 Key=settings.VRF_PRIVATE_MEDIA_LOCATION+'/'+newrequest.user_file.name,
                                                 Tagging={'TagSet':[{'Key': 'ID', 'Value':vrf_id}]})
            except:
                send_sns(vrf_id, "tagging uploaded file", traceback.format_exc())

        if context.get('first_contact'):
            context['first_contact'] = str(context['first_contact'])

        context['vrf_id'] = f"{settings.REPORT_IDENTIFIER}{vrf_id}"
            
        try:
            report_template = get_template("vincepub/email-md.txt")
            fkey = f'{settings.VRF_REPORT_DIR}/{vrf_id}.txt'
            s3Client.put_object(Body=report_template.render(context=context),
                                Bucket=settings.VP_PRIVATE_BUCKET_NAME, Key=fkey)
        except:
            send_sns(vrf_id, "writing report to s3 bucket", traceback.format_exc())
            logger.debug(report_template.render(context=context))


        #reset this back to just the numbers and not with the identifier                
        context['vrf_id'] = vrf_id
        context.pop('user_file')
        send_sns_json("vul", subject, json.dumps(context))

        context['user_file'] = attachment

        # if reporter provided an email, send an ack email
        reporter_email = context.get('contact_email')
        if reporter_email:
            autoack_email_template = get_template(settings.ACK_EMAIL_TEMPLATE)
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
                            'Data': f'Thank you for submitting {settings.REPORT_IDENTIFIER}{vrf_id}'
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
                send_sns(vrf_id, "Sending ack email for vul reporting form", traceback.format_exc())
                logger.debug(traceback.format_exc())
            else:
                logger.debug("Email Sent! Message ID: "),
                logger.debug(response['MessageId'])
        # redirect to a new URL
        return render(self.request, 'vincepub/success.html', context)

    def form_invalid(self, form):
        logger.debug(form.errors)
        return super().form_invalid(form)

class VUView(generic.DetailView):
    template_name = 'vincepub/vudetailnew.html'
    model = VUReport
    slug_field="idnumber"

    def get_context_data(self, **kwargs):
        context = super(VUView, self).get_context_data(**kwargs)
        vendors = VendorRecord.objects.values_list('vendor', flat=True).filter(idnumber=self.kwargs['slug'])
        context['notespage'] = 2
        return context


class VUDetailView(BuildableDetailView):
    queryset = VUReport.objects.all()
    template_name = 'vincepub/vudetailnew.html'
    slug_field = 'idnumber'

    def get_url(self, obj):
        return '/vuls/id/%s' % obj.idnumber

    def get_context_data(self, **kwargs):
        context = super(VUDetailView, self).get_context_data(**kwargs)
        context['notespage'] = 2
        return context

class VUDetail404(Buildable404View):
    build_path = '404.html'
    template_name = 'vincepub/404.html'

class SecurityTxtView(Buildable404View):
    build_path = '.well-known/security.txt'
    template_name = 'vincepub/security.txt'
    
class VendorView(generic.ListView):
    template_name = 'vincepub/vendorinfo.html'
    model = VendorRecord

    def get_template_names(self):
        report = VUReport.objects.filter(vuid=self.kwargs['vuid']).first()
        if report:
            if report.vulnote:
                return ['vincepub/vincepubvendorinfo.html']
        return [self.template_name]
    
    def get_queryset(self):
        self.newvulnote = False
        report = VUReport.objects.filter(vuid=self.kwargs['vuid']).first()
        if report:
            if report.vulnote:
                self.newvulnote = True
                return Vendor.objects.filter(note__vureport__vuid = self.kwargs['vuid']).order_by('vendor')
        return VendorRecord.objects.filter(vuid=self.kwargs['vuid']).order_by('vendor')

    def get_context_data(self, **kwargs):
        context = super(VendorView, self).get_context_data(**kwargs)
        vendorids=[]
        context['vendors'] = len(self.get_queryset())
        if not self.newvulnote:
            for vendor in self.get_queryset():
                vendorids.append(vendor.vendorrecordid)
            context['vendorhtml'] = VendorHTML.objects.filter(vendorrecordid__in=vendorids)
        return context

class VendorStatusView(generic.ListView):
    template_name = 'vincepub/vendorinfo.html'
    model = VendorRecord

    def get_template_names(self):
        report = VUReport.objects.filter(vuid=self.kwargs['vuid']).first()
        if report:
            if report.vulnote:
                return ['vincepub/vincepubvendorinfo.html']
        return [self.template_name]
    
    def get_queryset(self):
        vuid = self.kwargs['vuid']
        self.newvulnote = False
        report = VUReport.objects.filter(vuid=vuid).first()
        if report:
            if report.vulnote:
                self.newvulnote = True
                vendors = Vendor.objects.filter(note__vureport__vuid = vuid)
                return filter_by_status(vendors)
        notaffected = VendorRecord.objects.filter(vuid=vuid, status="Not Affected") | VendorRecord.objects.filter(vuid=vuid, status="Not Vulnerable")
        notaffected = notaffected.order_by('vendor')
        affected = VendorRecord.objects.filter(vuid=vuid, status="Affected") | VendorRecord.objects.filter(vuid=vuid, status="Vulnerable")
        affected = affected.order_by('vendor')
        unknown =  VendorRecord.objects.filter(vuid=vuid, status="Unknown").order_by('vendor')
        x = list(chain(affected, notaffected, unknown))
        return x

    def get_context_data(self, **kwargs):
        context = super(VendorStatusView, self).get_context_data(**kwargs)
        vendorids=[]
        context['vendors'] = len(self.get_queryset())
        if not self.newvulnote:
            for vendor in self.get_queryset():
                vendorids.append(vendor.vendorrecordid)
            context['vendorhtml'] = VendorHTML.objects.filter(vendorrecordid__in=vendorids)
        return context


class VUNoteViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = serializers.VUReportSerializer
    queryset = VUReport.objects.all()
    lookup_field = "idnumber"

    def get_view_name(self):
        return "Vulnerability Note Instance Details"

    
class VulViewAPI(generics.GenericAPIView, mixins.ListModelMixin):
    queryset = NoteVulnerability.objects.all()
    serializer_class = serializers.VulSerializer
    permission_classes = (AllowAny,)

    def get_queryset(self):
        return NoteVulnerability.objects.all()

    def list(self, request, *args, **kwargs):
        vu = get_object_or_404(VUReport, idnumber=self.kwargs['pk'])
        if vu.vulnote:
            queryset = NoteVulnerability.objects.filter(note__vureport__idnumber = self.kwargs['pk'])
            serializer = serializers.VulSerializer(queryset, many=True)
            return Response(serializer.data)
        else:
            rv = []
            loop = 1
            for x in vu.cveids:
                if re.match('cve-', x, re.I):
                    cvewo = x[4:]
                else:
                    cvewo = x
                rv.append({'cve':cvewo, 'description':f'https://nvd.nist.gov/vuln/detail?vulnId={x}',
                           'uid':x, 'note':self.kwargs['pk'],
                           'case_increment': loop,
                           'date_added': vu.datefirstpublished,
                           'dateupdated': vu.dateupdated})
                loop += 1
            serializer = serializers.VulSerializer(rv, many=True)
            return Response(serializer.data)

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

class VUNoteViewByMonth(generics.ListAPIView):
    serializer_class = serializers.VUReportSerializer

    def get_view_name(self):
        return "Vulnerability Notes Published by Month"
    
    def get_queryset(self):
        year = self.kwargs['year']
        month = self.kwargs['month']
        return VUReport.objects.filter(datefirstpublished__year=year, datefirstpublished__month=month)

class VUNoteViewByYear(generics.ListAPIView):
    serializer_class = serializers.VUReportSerializer

    def get_queryset(self):
        year = self.kwargs['year']
        return VUReport.objects.filter(datefirstpublished__year=year)

class VUNoteViewByMonthSummary(VUNoteViewByMonth):

    def get_view_name(self):
        return "Vulnerability Notes Published Summary"
    
    def summarize(self, request, *args, **kwargs):
        # make sure the filters of the parent class get applied
        queryset = self.filter_queryset(self.get_queryset())
        # do statistics here, e.g.
        stats = {'count': queryset.count(),
                 'notes': queryset.values_list('vuid', flat=True)}
        # not using a serializer here since it is already a
        # form of serialization
        return Response(stats)

    def get(self, request, *args, **kwargs):
        return self.summarize(request, *args, **kwargs)

class VUNoteViewByYearSummary(VUNoteViewByYear):

    def get_view_name(self):
        return "Vulnerability Notes Published Summary"
    
    def summarize(self, request, *args, **kwargs):
        # make sure the filters of the parent class get applied
        queryset = self.filter_queryset(self.get_queryset())
        # do statistics here, e.g.
        stats = {'count': queryset.count(),
                 'notes': queryset.values_list('vuid', flat=True)}
        # not using a serializer here since it is already a
        # form of serialization
        return Response(stats)

    def get(self, request, *args, **kwargs):
        return self.summarize(request, *args, **kwargs)

class VendorViewByMonth(generics.ListAPIView):
    serializer_class = serializers.NewVendorRecordSerializer

    def get_view_name(self):
        return "Vendors By Month"

    def get_queryset(self):
        year = self.kwargs['year']
        month = self.kwargs['month']
        reports = VUReport.objects.filter(datefirstpublished__year=year, datefirstpublished__month=month).values_list('vuid', flat=True)
        return VendorRecord.objects.filter(vuid__in=reports)
    
    def get(self, request, *args, **kwargs):
        year = self.kwargs['year']
        month = self.kwargs['month']
        reports = VUReport.objects.filter(datefirstpublished__year=year, datefirstpublished__month=month).values_list('idnumber', flat=True)
        oldrecs = VendorRecord.objects.filter(idnumber__in=reports)
        x = serializers.VendorRecordSerializer(oldrecs, many=True)
        vendor = Vendor.objects.filter(note__vuid__in=reports)
        y = serializers.VRSerializer(vendor, many=True)
        return Response(x.data+y.data)

class VendorViewByYear(generics.ListAPIView):
    serializer_class = serializers.VendorRecordSerializer

    def get_queryset(self):
        year = self.kwargs['year']
        reports = VUReport.objects.filter(datefirstpublished__year=year).values_list('vuid', flat=True)
        return VendorRecord.objects.filter(vuid__in=reports)

class VendorViewByMonthSummary(VendorViewByMonth):

    def get_view_name(self):
        return "Vendor Summary"
    
    def	summarize(self, request, *args, **kwargs):
        # make sure the filters of the parent class get applied
        year = self.kwargs['year']
        month = self.kwargs['month']
        reports = VUReport.objects.filter(datefirstpublished__year=year, datefirstpublished__month=month).values_list('idnumber', flat=True)
        oldrecs = VendorRecord.objects.filter(idnumber__in=reports).distinct('vendor')
        vendor = Vendor.objects.filter(note__vuid__in=reports).distinct('vendor')
        #queryset = self.filter_queryset(self.get_queryset())
        # do statistics here, e.g.
        stats = {'count': oldrecs.count() + vendor.count(),
                 'vendors': list(oldrecs.values_list('vendor', flat=True))+list(vendor.values_list('vendor', flat=True))}
        # not using a serializer here since it is already a
        # form of serialization
        return Response(stats)

    def	get(self, request, *args, **kwargs):
        return self.summarize(request, *args, **kwargs)

class VendorViewByYearSummary(VendorViewByYear):

    def get_view_name(self):
        return "Vendor Summary"
    
    def summarize(self, request, *args, **kwargs):
        # make sure the filters of the parent class get applied
        queryset = self.filter_queryset(self.get_queryset())
        # do statistics here, e.g.
        stats = {'count': queryset.count(),
                 'vendors': queryset.values_list('vendor', flat=True)}
        # not using a serializer here since it is already a
        # form of serialization
        return Response(stats)

    def get(self, request, *args, **kwargs):
        return self.summarize(request, *args, **kwargs)

class VendorViewAPI(generics.GenericAPIView, mixins.ListModelMixin):
    queryset = VendorRecord.objects.all()
    serializer_class = serializers.VendorRecordSerializer
    permission_classes = (AllowAny,)

    def get_queryset(self):
        return VendorRecord.objects.all()

    def list(self, request, *args, **kwargs):
        vu = get_object_or_404(VUReport, idnumber=self.kwargs['pk'])
        if vu.vulnote:
            queryset = Vendor.objects.filter(note__vureport__idnumber = self.kwargs['pk'])
            serializer = serializers.VendorSerializer(queryset, many=True)
            return Response(serializer.data)
        queryset = VendorRecord.objects.filter(idnumber = self.kwargs['pk'])
        serializer = serializers.VendorRecordSerializer(queryset, many=True)
        return Response(serializer.data)

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

class VendorVulViewAPI(generics.GenericAPIView, mixins.ListModelMixin):
    queryset = VendorVulStatus.objects.all()
    serializer_class = serializers.VendorVulSerializer
    permission_classes = (AllowAny,)

    def get_queryset(self):
        return VendorRecord.objects.all()

    def list(self, request, *args, **kwargs):
        vu = get_object_or_404(VUReport, idnumber=self.kwargs['pk'])
        if vu.vulnote:
            queryset = VendorVulStatus.objects.filter(vul__note__vureport__idnumber = self.kwargs['pk'])
            serializer = serializers.VendorVulSerializer(queryset, many=True)
            return Response(serializer.data)
        queryset = VendorRecord.objects.filter(idnumber = self.kwargs['pk'])
        serializer = serializers.VendorRecordSerializer(queryset, many=True)
        return Response(serializer.data)

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)


class CVEVulViewAPI(generics.GenericAPIView):

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
                report = serializers.VUReportSerializer(x)

        vul = NoteVulnerability.objects.filter(cve=cvewo).first()
        if vul:
            #VINCE published vul
            vuln = serializers.VulSerializer(vul)
            vendors = VendorVulStatus.objects.filter(vul=vul)
            if vendors:
                vv = serializers.VendorVulSerializer(vendors, many=True)
                return Response({'vulnerability':vuln.data,
                                 'note':report.data,
                                 'vendors':vv.data})
            else:
                return Response({'vulnerability':vuln.data,
                                 'note':report.data,
                                 'vendors':[]})
        if report:
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
                vv = serializers.NewVendorRecordSerializer(vendors, many=True) 
                return Response({'vulnerability': vul,
                                 'note':report.data,
                                 'vendors':vv.data})
            else:
                return Response({'vulnerability': vul,
                                 'note':report.data,
                                 'vendors':[]})
        else:
            raise Http404
                                           
    
class OldVendorView(generic.TemplateView):
    template_name='vincepub/vudetail.html'

    def dispatch(self, request, *args, **kwargs):
        vendor = VendorRecord.objects.filter(vendorrecordid=self.kwargs['vendorid']).first()
        if vendor:
            return redirect('/vuls/id/'+vendor.idnumber)
        return render(request, 'vincepub/404.html', {}, status=404)

def autocomplete_vendor(request):
    vendorlist = list(VendorRecord.objects.values_list('vendor', flat=True).distinct())
    data = json.dumps(vendorlist)
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)

def error_404(request):
    data = {}
    return render(request, 'vincepub/404.html', data, status=404)

class CaseCSAFAPIView(generics.RetrieveAPIView):
    serializer_class = serializers.CSAFSerializer

    def get_view_name(self):
        return "Public Vulnerability Advisory in CSAF format"

    def get_object(self):
        svuid = re.sub('[^\d]','',self.kwargs['vuid'])
        vr = get_object_or_404(VUReport, vuid=f"VU#{svuid}")
        vrs = VUReport.objects.filter(vuid=f"VU#{svuid}")
        if vrs:
            return vr

