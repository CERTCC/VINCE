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
from django.urls import include, path, re_path
from vincepub import views
from django.conf import settings
from bakery.static_views import serve
from rest_framework import routers
from vincepub.feeds import LatestVulReportActivity
from django.views.generic import RedirectView

router = routers.DefaultRouter()
router.register('notes', views.VUNoteViewSet)
router.register('api', views.VUNoteViewSet)

urlpatterns = [
    re_path('^$', views.IndexView.as_view(), name='index'),
    path('search/', views.SearchView.as_view(), name='search'),
    re_path('^search$', RedirectView.as_view(pattern_name='vincepub:search')),
    re_path('^html/search/?$', RedirectView.as_view(pattern_name='vincepub:search', query_string=True, permanent=True)),
    path('results/', views.SearchResultView.as_view(), name='results'),
    path('report/', views.InitialReportView.as_view(), name='initreport'),
    re_path('^report$', RedirectView.as_view(pattern_name='vincepub:initreport')),
    re_path('^report/VulReport/$', RedirectView.as_view(pattern_name='vincepub:initreport')),
    path('vulcoordrequest/', views.VulCoordRequestView.as_view(), name='vulcoordrequest'),
    path('quickSearch/', views.quickSearch, name='quickSearch'),
    re_path('^byid$', RedirectView.as_view(pattern_name='vincepub:quickSearch', query_string=True)),
    re_path('^api/vendors/(?P<pk>\d+)/$', views.VendorViewAPI.as_view(), name='vendorview'),
    re_path('^api/(?P<pk>\d+)/vendors/$', views.VendorViewAPI.as_view(), name='vendorview'),
    re_path('^vendors/(?P<pk>\d+)/$', RedirectView.as_view(pattern_name="vincepub:vendorview")),
    re_path('^api/vuls/(?P<pk>\d+)/$', views.VulViewAPI.as_view(), name='vulview'),
    re_path('^api/vuls/cve/(?P<year>\d+)-(?P<pk>\d+)/$', views.CVEVulViewAPI.as_view(), name='cvevulview'),
    re_path('^api/(?P<pk>\d+)/vuls/$', views.VulViewAPI.as_view(), name='vulview'),
    re_path('^api/vendors/vuls/(?P<pk>\d+)/$', views.VendorVulViewAPI.as_view(), name='vendorvulview'),
    re_path('^api/(?P<pk>\d+)/vendors/vuls/$', views.VendorVulViewAPI.as_view(), name='vendorvulview'),
    re_path('^api/(?P<year>(?!0000)\d{4})/(?P<month>0?[1-9]|1[012])/$', views.VUNoteViewByMonth.as_view()),
    re_path('^api/(?P<year>(?!0000)\d{4})/(?P<month>0?[1-9]|1[012])/summary/$', views.VUNoteViewByMonthSummary.as_view()),
    re_path('^api/(?P<year>(?!0000)\d{4})/summary/$', views.VUNoteViewByYearSummary.as_view()),
    re_path('^api/vendors/(?P<year>(?!0000)\d{4})/(?P<month>0?[1-9]|1[012])/$', views.VendorViewByMonth.as_view()),
    re_path('^api/vendors/(?P<year>(?!0000)\d{4})/(?P<month>0?[1-9]|1[012])/summary/$', views.VendorViewByMonthSummary.as_view()),
    re_path('^api/vendors/(?P<year>(?!0000)\d{4})/summary/$', views.VendorViewByYearSummary.as_view()),
    re_path('^id/(?P<vendorid>[A-Z0-9]+-[A-Z0-9]+)/?$', views.OldVendorView.as_view(), name='oldvendorview'),
    re_path('^id/(?P<slug>\d+)/?$', views.VUView.as_view(), name='vudetail'),
    re_path('^vendor/(?P<vuid>VU#[0-9]+)/$', views.VendorView.as_view(), name='vendor'),
    re_path('^vendorstatus/(?P<vuid>VU#[0-9]+)/$', views.VendorStatusView.as_view(), name='vendorstatus'),
    re_path('^bypublic/(?P<asc_or_desc>asc)/$', views.DatePublicView.as_view(), name='viewbypublic'),
    re_path('^bypublic/(?P<asc_or_desc>desc)/$', views.DatePublicView.as_view(), name='viewbypublic'),
    path('bypublic/', RedirectView.as_view(url='bypublic/desc/')),
    re_path('^byupdate/(?P<asc_or_desc>asc)/$', views.DateUpdatedView.as_view(), name='viewbyupdate'),
    re_path('^byupdate/(?P<asc_or_desc>desc)/$', views.DateUpdatedView.as_view(), name='viewbyupdate'),
    path('byupdate/', RedirectView.as_view(url='byupdate/desc/')),
    re_path('^bypublished/(?P<asc_or_desc>asc)/$', views.DatePublishedView.as_view(), name='viewbypublish'),
    re_path('^bypublished/(?P<asc_or_desc>desc)/$', views.DatePublishedView.as_view(), name='viewbypublish'),
    re_path('^bypublished$', RedirectView.as_view(url='/vuls/bypublished/desc/')),
    path('bypublished/', RedirectView.as_view(url='/vuls/bypublished/desc/')),
    re_path('^byCVSS/(?P<asc_or_desc>asc)/$', views.CVSSScoreView.as_view(), name='viewbycvss'),
    re_path('^byCVSS/(?P<asc_or_desc>desc)/$', views.CVSSScoreView.as_view(), name='viewbycvss'),
    path('byCVSS/', RedirectView.as_view(url='byCVSS/desc/')),
    path('ajax_calls/search/', views.autocomplete_vendor),
    re_path('^', include(router.urls)),
    path('atomfeed/', LatestVulReportActivity(), name='vulfeed'),
#    url(r"^id/(.*)$", serve, {"document_root": settings.BUILD_DIR+'/vuls/id',
#                           'show_indexes': True,
#                           'default': 'index.html'
#                       }, name="test"),
#
]




