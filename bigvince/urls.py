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
"""bigvince URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from vinny.admin import vinnyadmin
from vincepub.feeds import LatestVulReportActivity
from vincepub import views as vincepub_views
from vince import views as vince_views
from vinceworker import views as vtworker_views
from vincecommworker import views as vcworker_views
from kbworker import views as kbworker_views


urlpatterns = [
    path('vuls/', include(('vincepub.urls', 'vincepub'), namespace="vincepub")),
    path('vince/', include(('vincepub.vince_urls', 'pub'), namespace='pub')),
    re_path('^CERT_WEB/services/vul-notes.nsf/bypublished/?$', RedirectView.as_view(url='/vuls/bypublished/desc')),
    re_path('^CERT_WEB/services/vul-notes.nsf/byupdate/?$', RedirectView.as_view(url='/vuls/byupdate/desc')),
    re_path('^CERT_WEB/services/vul-notes.nsf/?$', RedirectView.as_view(url='/vuls/')),
    re_path('^vulcatalog/?$', RedirectView.as_view(url='/vuls/')),
    re_path('^sc/?$', RedirectView.as_view(url='/vuls/')),
    re_path('^vulfeed/?$', LatestVulReportActivity()),
    path('vince/admin/', admin.site.urls),
    path('vince/comm/', include(('vinny.urls', 'vinny'), namespace="vinny")),
    path('vince/',include(('vince.urls', 'vince'), namespace="vince")),
    path('vince/comm/auth/', include(('cogauth.urls', 'cogauth'), namespace='cogauth')),
    path('vince/comm/admin/', vinnyadmin.urls),
#    path('vince/admin/django-ses/', include('django_ses.urls')),
]

if settings.MULTIURL_CONFIG and settings.VINCE_NAMESPACE == "vince":
    urlpatterns.append(
        re_path('^$', RedirectView.as_view(url='vince/login/'))
    )
else:
    urlpatterns.append(
        re_path('^$', RedirectView.as_view(url='vuls/')),
    )

if settings.IS_VINCEWORKER:
    urlpatterns.extend([
        path('vinceworker/', include(('vinceworker.urls', 'vinceworker'), namespace="vinceworker")),
        path('vcworker/daily/',  vtworker_views.vc_daily_digest)
    ])

if settings.IS_KBWORKER:
    urlpatterns.extend([
        path('kbworker/', include(('kbworker.urls', 'kbworker'), namespace="kbworker")),
        path('vcworker/daily/',  kbworker_views.vc_daily_digest),
        path('vinceworker/daily/', kbworker_views.vt_daily_digest),
        path('vinceworker/reminder/', kbworker_views.vt_daily_digest),
    ])

if settings.IS_VCWORKER:
    urlpatterns.extend([
        path('vcworker/', include(('vincecommworker.urls', 'vincecommworker'), namespace='vincecommworker')),
        path('vinceworker/daily/', vcworker_views.vt_daily_digest),
        path('vinceworker/reminder/', vcworker_views.vt_daily_digest),
    ])
    
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

handler404 = vince_views.error_404
handler500 = vince_views.error_500
handler403 = vince_views.error_403
handler400 = vince_views.error_400
