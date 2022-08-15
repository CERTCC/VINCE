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
from django.contrib.auth import views as auth_views
from django.urls import path, re_path
from cogauth import views
from django.views.generic import TemplateView
from django.conf import settings

urlpatterns = [
    path('login/', views.COGLoginView.as_view(), name='login'),
    path('api-token-auth/', views.CustomAuthToken.as_view()),
    path('profile/setmfa/', views.EnableMFAView.as_view(), name='mfa'),
    path('profile/', views.ProfileView.as_view(),name='profile'),
    path('profile/setmfa/totp/', views.AssociateTOTPView.as_view(), name='totp'),
    path('profile/setmfa/sms/', views.AssociateSMSView.as_view(), name='sms'),
    path('profile/mfa/rm/', views.RemoveMFAView.as_view(), name='rmmfa'),
    path('profile/update/', views.UpdateProfileView.as_view(), name='update-profile'),
    #path('profile/subscriptions/', views.MySubscriptions.as_view(), name='subscriptions'),
    #path('admin/cognito-users/', views.AdminListUsers.as_view(),name='admin-cognito-users'),
    path('confirm/register/', views.RegisterView.as_view(), name='confirm_register'),
    path('login/mfa/', views.MFAAuthRequiredView.as_view(), name='mfaauth'),
    path('verify/email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('verify/phone/', views.VerifyPhoneView.as_view(), name='verify_phone'),
    path('verify/error/', views.LimitExceededView.as_view(), name='limitexceeded'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('genapikey/', views.GenerateTokenView.as_view(), name='gentoken'),
    path('delapikey/', views.DeleteTokenView.as_view(), name='deltoken'),    
    re_path(r'^genapikey/service/(?P<vendor_id>\d+)/', views.GenerateServiceTokenView.as_view(), name='genservicetoken'),
    path('account/help/', views.LoginHelpView.as_view(), name='loginhelp'),
    path('confirmed/', TemplateView.as_view(template_name='cogauth/account_confirmed.html'), name='account_confirmed'),
    path('resetpassword/confirmed/', TemplateView.as_view(template_name='cogauth/pw_confirmed.html'), name='pw_reset_confirmed'),
    path('changePassword/', views.ChangePasswordView.as_view(template_name='cogauth/password_change_form.html'),name='password_change'),
    path('changePassword/done/', TemplateView.as_view(template_name='cogauth/password_change_done.html'), name='password_change_done'),
    path('init/resetpassword/', views.InitialPasswordResetView.as_view(), name='init_password_reset'),
    path('resetpassword/', views.ResetPasswordView.as_view(), name='passwordreset'),
    path('reset/mfa/unauth/', views.ResetMFAView.as_view(), name='resetmfa'),
    path('changePasswordRegister/', views.ChangePasswordandRegisterView.as_view(),name='password_register'),
    path('account_activation_sent/', views.ConfirmRegister.as_view(), name='account_activation_sent'),
    path('resend/', views.ResendConfirmationCode.as_view(), name='resend'),
]

try:
    if settings.MULTIURL_CONFIG:
        urlpatterns.extend([
            path('logout/', auth_views.LogoutView.as_view(template_name='cogauth/logout.html'), name='logout'),
        ])
    else:
        urlpatterns.extend([
            path('logout/', auth_views.LogoutView.as_view(extra_context={'token_login':1}, template_name='cogauth/logout.html'), name='logout'),
        ])

except:
    urlpatterns.extend([
        path('logout/', auth_views.LogoutView.as_view(extra_context={'token_login':1}, template_name='cogauth/logout.html'), name='logout'),
    ])
