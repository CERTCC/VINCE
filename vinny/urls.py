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
from django.urls import include, path, re_path
from django.contrib.auth import views as auth_views
from vinny import views
from cogauth import views as cogauth_views
from django.conf import settings
from django.contrib import admin
from django.views.generic import TemplateView, RedirectView

urlpatterns = [
    re_path('^$', RedirectView.as_view(pattern_name="vinny:dashboard"), name='index'),
    #path('login/', RedirectView.as_view(pattern_name='cogauth:login'), name="login"),
#    path('logout/', auth_views.LogoutView.as_view(template_name='vince/logout.html'), name='logout'),
    path('signup/', cogauth_views.RegisterView.as_view(), name='signup'),
    path('pending/', TemplateView.as_view(template_name='vinny/pending.html'), name='pending'),
    path('service/', TemplateView.as_view(template_name='vinny/service.html'), name='serviceaccount'),
    path('login/', cogauth_views.COGLoginView.as_view(), name='login'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('viewall/', views.LimitedAccessView.as_view(), name='limited'),
    path('limited/report', views.VinceCommReportView.as_view(), name='vcreport'),
    re_path(r'^vrf/attachments/(?P<pk>\d+)/$', views.VinceVRFAttachmentView.as_view(), name='vrf_attachment'),
    re_path(r'attachments/(?P<type>(case|msg|report|track))/(?P<path>.*)$', views.VinceAttachmentView.as_view(), name='attachment'),
    re_path('limited/reports/print/(?P<month>[0-9]+)/(?P<year>[0-9]+)/$', views.VinceCommPrintReportsView.as_view(), name='printreport'),
    re_path('^case/summary/(?P<pk>\d+)/$', views.CaseSummaryView.as_view(), name='case_summary'),
    re_path('^case/request/(?P<pk>\d+)/$', views.RequestAccessView.as_view(), name='requestaccess'),
    path('preferences/', views.PreferencesView.as_view(), name='preferences'),
    path('dashboard/filter/', views.DashboardCaseView.as_view(), name='dashboardfilter'),
    path('limited/filter/', views.LimitedAccessSearch.as_view(), name='limitedfilter'),
    path('reports/filter/', views.MyReportsFilterView.as_view(), name='myreportsfilter'),
    path('contact/', views.ContactView.as_view(), name='contact'),
    path('profile/newcolor/', views.GenerateNewRandomColor.as_view(), name='newcolor'),
    re_path('^contact/(?P<vendor_id>\d+)/$', views.ContactView.as_view(), name='contact'),
    path('contact/multi/', views.MultipleContactView.as_view(), name='multiple_contacts'),
    re_path('^vc/contact/edit/(?P<vendor_id>\d+)/$', views.EditContactView.as_view(), name='editcontact'),
    re_path('^contact/(?P<vendor_id>\d+)/add/logo/$', views.ContactAddLogoView.as_view(), name='addlogo'),
    re_path('^groupadmin/change/access/(?P<vendor_id>\d+)/', views.ChangeDefaultCaseAccess.as_view(), name='changeaccess'),
    re_path('^groupadmin/caseaccess/(?P<vendor_id>\d+)/(?P<user_id>\d+)/', views.CaseAccessView.as_view(), name='caseaccess'),
    path('groupadmin/', views.AdminView.as_view(), name='admin'),
    path('groupadmin/multi/', views.MultipleGroupAdminView.as_view(), name='multiple_admins'),
    re_path('^groupadmin/(?P<vendor_id>\d+)/promote/(?P<uid>\d+)/$', views.PromoteUserView.as_view(), name='promoteuser'),
    re_path('^groupadmin/(?P<vendor_id>\d+)/$', views.AdminView.as_view(), name='admin'),
    re_path('^groupadmin/users/(?P<vendor_id>\d+)/$', views.UserCaseAccessView.as_view(), name='adminusers'),
    re_path('^groupadmin/service/create/(?P<vendor_id>\d+)/$', views.CreateServiceAccountView.as_view(), name='createservice'),
    re_path('groupadmin/(?P<vendor_id>\d+)/adduser/', views.AdminAddUserView.as_view(), name='adduser'),
    re_path('^groupadmin/(?P<vendor_id>\d+)/rmuser/(?P<type>(contact|user))/(?P<uid>\d+)/$', views.AdminRemoveUser.as_view(), name='rmuser'),
    re_path('^groupadmin/(?P<vendor_id>\d+)/email/modify/(?P<type>(email|user))/(?P<uid>\d+)/$', views.ModifyEmailNotifications.as_view(), name='changeemail'),
    path('inbox/', views.InboxView.as_view(), name='inbox'),
    re_path('^inbox/(?P<deleted>(sent))/$', views.InboxView.as_view(), name='inbox'),
    path('inbox/filter/', views.SearchThreadsView.as_view(), name='filterthreads'),
    re_path('^thread/(?P<pk>\d+)/$', views.ThreadView.as_view(), name='thread_detail'),
    re_path('^thread/msg/(?P<pk>\d+)/$', views.MessageView.as_view(), name='msg_detail'),
    re_path('^thread/messages/(?P<pk>\d+)/$', views.MessagesView.as_view(), name='messages'),
    re_path('^thread/(?P<pk>\d+)/delete/$', views.ThreadDeleteView.as_view(), name='thread_delete'),
    re_path('^sendmsg/(?P<type>[1-9]|10)?/$', views.SendMessageView.as_view(), name='sendmsg'),
    re_path('^sendmsg/(?P<type>[2])/(?P<case>\d+)/$', views.SendMessageView.as_view(), name='sendmsg'),
    path('sendmsg/all/', views.SendMessageAllView.as_view(), name='sendmsgall'),
    path('auto/api/allvendors/', views.autocomplete_allvendors, name='all_vendors'),
    path('auto/api/vlookup/', views.VendorLookupView.as_view(), name='vendorlookup'),
    path('auto/api/vendors/', views.autocomplete_vendor, name='auto_vendor'),
    path('auto/api/users/', views.autocomplete_users, name='auto_user'),
    path('api/userapprove/', views.userapproverequest, {"caller": "vinny"},name='userapprove'),    
    re_path('^auto/api/coord/(?P<pk>\d+)/$', views.autocomplete_coordinators, name='auto_coord'),
    path('sendmsg/', views.SendMessageView.as_view(), name='sendmsg'),
    path('sendmsg/user/', views.SendMessageUserView.as_view(), name='sendmsguser'),
    re_path('^sendmsg/user/(?P<user_id>\d+)/$', views.SendMessageUserView.as_view(), name='sendmsgus'),
    re_path('^sendmsg/group/(?P<group_id>\d+)_(?P<case>\d+)?/$', views.SendMessageUserView.as_view(), name='sendmsggroup'),
    re_path('^sendmsg/admins/(?P<admin_id>\d+)_(?P<case>\d+)?/$', views.SendMessageUserView.as_view(), name='sendmsgadmins'),
    #path('groupchat/', views.GroupChatView.as_view(), name='groupchat'),
    re_path('^groupchat/case/(?P<case_id>\d+)/$', views.GroupChatView.as_view(), name='groupchatcase'),
    #path('redirect/vintrack/', views.RedirectVince.as_view(), name='redirect_vince'),
    re_path('^case/(?P<pk>[0-9]+)?/$', views.CaseView.as_view(), name='case'),
    re_path('^case/(?P<pk>[0-9]+)?/vv/(?P<vendor>[0-9]+)?/$', views.CaseView.as_view(), name='vendorcase'),
    re_path('^case/vin/(?P<pk>[0-9]+)?/$', views.VinceCaseView.as_view(), name='vincase'),
    re_path('^case/post/(?P<pk>[0-9]+)?/$', views.PostCaseView.as_view(), name='postcase'),
    re_path('^post/(?P<pk>[0-9]+)/$', views.PostView.as_view(), name='post'),
    #re_path('^post/(?P<pk>[0-9]+)/(?P<post>[0-9]+)/$', views.ThreadedPostView.as_view(), name='replies'),
    re_path('^post/diff/(?P<revision_id>[0-9]+)/$', views.PostDiffView.as_view(), name='diff'),
    re_path('^post/edit/(?P<pk>[0-9]+)/$', views.EditPostView.as_view(), name='editpost'),
    re_path('^post/edit/confirm/(?P<pk>[0-9]+)/$', views.DeletePostView.as_view(), name='rmpost'),
    re_path('^case/(?P<pk>[0-9]+)?/status/$', views.ViewStatusView.as_view(), name='status'),
    re_path('^case/(?P<pk>[0-9]+)?/vendors/all/$', views.LoadVendorsView.as_view(), name='loadvendors'),
    re_path('^case/(?P<pk>[0-9]+)?/vendors/json/$', views.JsonVendorsView.as_view(), name='loadjson'),
    re_path('^case/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/status/$', views.ViewStatusView.as_view(), name='status'),
    re_path('^case/(?P<pk>[0-9]+)/multiple/$', views.MultipleStatusView.as_view(), name='multiple_status'),
    re_path('^case/(?P<pk>[0-9]+)?/mute/$', views.MuteCaseView.as_view(), name='mute'),
    re_path('^case/(?P<pk>[0-9]+)/add/document/$', views.CaseDocumentCreateView.as_view(), name='addfile'),
    re_path('^case/(?P<pk>[0-9]+)/rm/(?P<doc>[0-9]+)/document/$', views.RemoveFileView.as_view(), name='rmfile'),
    re_path('^case/tracking/$', views.casetracking, name='casetracking'),
    re_path('^case/(?P<pk>[0-9]+)/status/update/$', views.UpdateStatusView.as_view(), name='update_status'),
    re_path('^case/(?P<pk>[0-9]+)/report/$', views.CaseRequestView.as_view(), name='cr'),
    re_path('^case/(?P<pk>[0-9]+)/vuls/$', views.VulnerabilityDetailView.as_view(), name='vuls'),
    re_path('^case/vulns/(?P<pk>[0-9]+)/$', views.SingleVulDetailView.as_view(), name='vuldetail'),
    re_path('^case/(?P<pk>[0-9]+)/notedraft/$', views.VulNoteView.as_view(), name='vulnote'),
    re_path('^vul/(?P<pk>[0-9]+)/providestmt/$', views.AddStatement.as_view(), name='providestmt'),
    re_path('^vul/(?P<pk>[0-9]+)/providestmt/(?P<vendor_id>[0-9]+)/$', views.AddStatement.as_view(), name='providestmt'),
    re_path('^case_search/$', views.CaseFilter.as_view(), name='casesearch'),
    re_path('^case/(?P<pk>[0-9]+)/member/(?P<member>[0-9]+)/$', views.GetStatementView.as_view(), name='statement'),
    path('case/results/', views.CaseFilterResults.as_view(), name='caseresults'),
    path('construction/', views.UnderConstruction.as_view(), name='construction'),
    re_path('^cr/(?P<pk>[0-9]+)/$', views.CRView.as_view(), name='cr_report'),
    path('report/', views.ReportView.as_view(), name='report'),
    re_path('^report/(?P<pk>[0-9]+)?/add/file/$', views.ReportDocumentCreateView.as_view(), name='addreportfile'),
    re_path('^report/(?P<pk>[0-9]+)?/update/$', views.UpdateReportView.as_view(), name='reportupdate'),
    re_path('profile/user_card/(?P<euid>[0-9a-fA-F]+)?/$', views.UserCardView.as_view(), name='usercard'),
    re_path('profile/group_card/(?P<egid>[0-9a-fA-F]+)?/$', views.GroupCardView.as_view(), name='groupcard'),
    #note: var "vinny:groupcardcase" is not used in templates anymore
    # use {{groupcontact.url}}{{case.id}} to build groupcardcase URLs
    re_path('profile/group_card/(?P<egid>[0-9a-fA-F]+)?/(?P<case>[0-9]+)?/$', views.GroupCardView.as_view(), name='groupcardcase'),
    path('reports/pub/', views.AdminReportsView.as_view(), name='adminreports'),
    path('reports/', views.ReportsView.as_view(), name='reports'),
    path('api/vendor/', views.VendorInfoAPIView.as_view(), name='vendor_api'),
    path('api/cases/', views.CasesAPIView.as_view(), name='cases_api'),
    re_path('api/case/(?P<vuid>\d+)/$', views.CaseAPIView.as_view({'get':'retrieve'}), name='case_api'),
    re_path('api/case/posts/(?P<vuid>\d+)/$', views.CasePostAPIView.as_view(), name='case_post_api'),
    re_path('api/case/(?P<vuid>\d+)/posts/$', views.CasePostAPIView.as_view(), name='case_post_api'),
    re_path('api/case/report/(?P<vuid>\d+)/$', views.CaseReportAPIView.as_view(), name='case_report_api'),
    re_path('api/case/(?P<vuid>\d+)/report/$', views.CaseReportAPIView.as_view(), name='case_report_api'),
    re_path('api/case/vuls/(?P<vuid>\d+)/$', views.CaseVulAPIView.as_view(), name='case_vul_api'),
    re_path('api/case/(?P<vuid>\d+)/vuls/$', views.CaseVulAPIView.as_view(), name='case_vul_api'),
    re_path('api/case/vendor/statement/(?P<vuid>\d+)/$', views.UpdateVendorStatusAPIView.as_view(), name='update_stmt_api'),
    re_path('api/case/(?P<vuid>\d+)/vendor/statement/$', views.UpdateVendorStatusAPIView.as_view(), name='update_stmt_api'),
    re_path('api/case/vendors/(?P<vuid>\d+)/$', views.CaseVendorStatusAPIView.as_view(), name='case_vendor_api'),
    re_path('api/case/(?P<vuid>\d+)/vendors/$', views.CaseVendorStatusAPIView.as_view(), name='case_vendor_api'),
    re_path('api/case/vendors/vuls/(?P<vuid>\d+)/$', views.CaseVendorVulStatusAPIView.as_view(), name='case_vendor_vul_api'),
    re_path('api/case/(?P<vuid>\d+)/vendors/vuls/$', views.CaseVendorVulStatusAPIView.as_view(), name='case_vendor_vul_api'),
    re_path('api/case/note/(?P<vuid>\d+)/$', views.CaseVulNoteAPIView.as_view(), name='case_vulnote_api'),
    re_path('api/case/(?P<vuid>\d+)/note/$', views.CaseVulNoteAPIView.as_view(), name='case_vulnote_api'),
    re_path('api/vuls/cve/(?P<year>\d+)-(?P<pk>\d+)/$', views.CVEVulAPIView.as_view(), name='cve_lookup_api'),
    re_path('api/case/(?P<vuid>\d+)/csaf/$', views.CaseCSAFAPIView.as_view(), name='case_csaf_api'),
    re_path('api/case/csaf/(?P<vuid>\d+)/$', views.CaseCSAFAPIView.as_view(), name='case_csaf_api'),
    re_path('api/unread_msg_count/$', views.UnreadCountAjax.as_view(), name='unread_msg_count'),
]

if settings.DEBUG:
    urlpatterns.extend([
        path('tokens/', views.VinceTokens.as_view(), name='get_token'),
        path('token/login/', views.TokenLogin.as_view(), name='tokenlogin'),
    ])
