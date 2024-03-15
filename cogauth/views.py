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

# Create your views here.
from django.contrib.auth.mixins import LoginRequiredMixin, AccessMixin, UserPassesTestMixin
from django.forms.utils import ErrorList
from django.http import Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.translation import ugettext as _
from django.utils.decorators import method_decorator
from django.core.exceptions import PermissionDenied

try:
    from django.urls import reverse_lazy, reverse
except ImportError:
    from django.core.urlresolvers import reverse_lazy, reverse
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from django.views.generic import FormView, TemplateView
from django.contrib import messages
from django.urls import resolve
from django.contrib.auth import authenticate, login as auth_login
from django.views.decorators.cache import never_cache
from django.contrib.auth.views import LogoutView as CALogoutView
from django.conf import settings
from django.contrib.auth import logout
from lib.warrant import UserObj, Cognito
from django.template.defaulttags import register
from cogauth.utils import (
    get_cognito,
    password_challenge_dance,
    get_group,
    cognito_verify_email,
    cognito_check_permissions,
    mfa_challenge,
    rm_mfa,
    send_courtesy_email,
)
from cogauth.forms import *
from vinny.models import Thread, VinceAPIToken, VinceCommGroupAdmin, GroupContact
from vinny.permissions import is_in_group_vincegroupadmin
from vinny.lib import vince_comm_send_sqs
from django.core.exceptions import SuspiciousOperation
import boto3
import os
import binascii
import requests
import logging
import traceback
from boto3.exceptions import Boto3Error
from botocore.exceptions import ClientError, ParamValidationError
from django.utils.http import is_safe_url
from django.http.response import JsonResponse
from bigvince.utils import get_cognito_url, get_cognito_pool_url
from vinny.models import VinceCommEmail
from lib.vince import utils as vinceutils

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

GOOGLE_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def _unread_msg_count(user):
    return len(Thread.ordered(Thread.unread(user)))


def _my_contact_group(user):
    groups = user.groups.filter(groupcontact__contact__vendor_type__in=["Coordinator", "Vendor"]).exclude(
        groupcontact__isnull=True
    )
    return groups


def _other_groups(user):
    groups = user.groups.exclude(groupcontact__isnull=False)
    return groups


def generate_key():
    return binascii.hexlify(os.urandom(20)).decode()


@register.filter("username")
def username(user):
    return user._metadata.get("username")


@register.filter("mfafilter")
def mfafilter(mfa_name):
    return ",".join(mfa_name).replace("_", " ")


class TokenMixin(AccessMixin):

    def dispatch(self, request, *args, **kwargs):
        if hasattr(settings, "ALT_VERIFY_TOKEN") and settings.ALT_VERIFY_TOKEN(request.user, request.session):
            """If alternate token verify method provided for Automated
            Tests, use it"""
            return super(TokenMixin, self).dispatch(request, *args, **kwargs)
        if not request.session.get("REFRESH_TOKEN"):
            return self.handle_no_permission()
        try:
            c = get_cognito(request)
        except (Boto3Error, ClientError) as e:
            # likely that refresh token has expired so re-auth is required
            logout(request)
            logger.debug(f"Failed Token request {request} with error {e}")
            return redirect(self.get_login_url())
        except SuspiciousOperation:
            logout(request)
            logger.debug(f"Suspicous operation - invalid Token request {request}")
            return redirect(self.get_login_url())
        return super(TokenMixin, self).dispatch(request, *args, **kwargs)


class GetUserMixin(object):
    cognito = None

    def get_token_groups(self):
        if self.cognito is None:
            self.cognito = get_cognito(self.request)
        return get_group(self.request.session.get("ACCESS_TOKEN"))

    def get_user(self):
        if self.cognito is None:
            self.cognito = get_cognito(self.request)
        user = self.cognito.get_user(attr_map=settings.COGNITO_ATTR_MAPPING)
        if hasattr(settings, "LOCALSTACK") and settings.LOCALSTACK:
            user.phone_number_verified = True
            user.mfa = "SMS"
        return user


class PendingTestMixin(UserPassesTestMixin):

    def handle_no_permission(self):
        if self.raise_exception:
            raise PermissionDenied(self.get_permission_denied_message())
        if self.request.user.is_authenticated and self.request.user.vinceprofile.multifactor == False:
            return redirect("cogauth:totp")
        if self.request.user.is_authenticated and self.request.user.vinceprofile.pending:
            return redirect("vinny:pending")
        if self.request.user.is_authenticated and self.request.user.vinceprofile.service:
            return redirect("vinny:serviceaccount")
        elif self.request.user.is_authenticated:
            raise PermissionDenied(self.get_permission_denied_message())
        return redirect("%s?next=%s" % (reverse("vinny:login"), self.request.path))

    def test_func(self):
        if self.request.user.vinceprofile.multifactor == False:
            return False
        if self.request.user.vinceprofile.service:
            return False
        if self.request.user.vinceprofile.pending:
            if hasattr(settings, "LOCALSTACK") and settings.LOCALSTACK:
                self.request.user.vinceprofile.pending = False
                return True
            return False
        else:
            return True


class ProfileView(LoginRequiredMixin, TokenMixin, GetUserMixin, PendingTestMixin, TemplateView):
    template_name = "cogauth/profile.html"
    login_url = "cogauth:login"

    def get_context_data(self, **kwargs):
        context = super(ProfileView, self).get_context_data(**kwargs)
        # group = get_group(self.request.session.get('ACCESS_TOKEN'))
        context["coguser"] = self.get_user()
        context["unread_msg_count"] = _unread_msg_count(self.request.user)
        grs = _my_contact_group(self.request.user)
        grs = grs.exclude(groupcontact__contact__vendor_name__isnull=True)
        context["my_groups"] = ", ".join(grs.values_list("groupcontact__contact__vendor_name", flat=True))
        context["other_groups"] = ", ".join(_other_groups(self.request.user).values_list("name", flat=True))
        return context


class AssociateSMSView(LoginRequiredMixin, TokenMixin, GetUserMixin, FormView):
    template_name = "cogauth/sms.html"
    login_url = "cogauth:login"
    form_class = MFASMSForm

    def get_success_url(self):
        return reverse("cogauth:profile")

    def get_context_data(self, **kwargs):
        context = super(AssociateSMSView, self).get_context_data(**kwargs)
        context["form"] = MFASMSForm()
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = MFASMSForm(request.POST)
        if form.is_valid():
            return self.form_valid(form)
        else:
            form._errors.setdefault("phone_number", ErrorList(["Invalid phone number format."]))

            return render(request, "cogauth/sms.html", {"form": form})

    def form_valid(self, form):
        ip = vinceutils.get_ip(self.request)
        coguser = self.get_user()
        client = boto3.client("cognito-idp", endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
        u = Cognito(
            settings.COGNITO_USER_POOL_ID,
            settings.COGNITO_APP_ID,
            user_pool_region=settings.COGNITO_REGION,
            id_token=coguser.id_token,
            refresh_token=coguser.refresh_token,
            access_token=coguser.access_token,
        )
        phone = form.cleaned_data["phone_number"]
        logger.info(f"User {self.request.user.username} SMS update request as {phone} from ip {ip}")
        try:
            u.update_profile({"phone_number": form.cleaned_data["phone_number"]})
        except (Boto3Error, ClientError) as e:
            form._errors.setdefault("phone_number", ErrorList(["Invalid phone number format."]))
            messages.error(self.request, "Invalid phone number format.")
            return super().form_invalid(form)
        try:
            u.send_verification(attribute="phone_number")
        except (Boto3Error, ClientError) as e:
            logger.debug(f"Error returned in cogauth for SMS Update as {e}")
            return redirect("cogauth:limitexceeded")
        return redirect("cogauth:verify_phone")


class AssociateTOTPView(LoginRequiredMixin, TokenMixin, GetUserMixin, FormView):
    template_name = "cogauth/totp.html"
    login_url = "cogauth:login"
    form_class = TOTPForm

    def get_success_url(self):
        return reverse("cogauth:profile")

    def get_context_data(self, **kwargs):
        context = super(AssociateTOTPView, self).get_context_data(**kwargs)
        coguser = self.get_user()
        client = boto3.client("cognito-idp", endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
        response = client.associate_software_token(AccessToken=coguser.access_token)
        context["secretcode"] = response["SecretCode"]
        context["form"] = TOTPForm()
        context["qrtext"] = (
            f"otpauth://totp/VINCE:{self.request.user.username}?secret={context['secretcode']}&issuer=VINCE"
        )
        return context

    def form_valid(self, form):
        ip = vinceutils.get_ip(self.request)
        logger.info(f"User {self.request.user.username} TOTP update request from ip {ip}")
        coguser = self.get_user()
        client = boto3.client("cognito-idp", endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
        try:
            response = client.verify_software_token(
                AccessToken=coguser.access_token,
                UserCode=form.cleaned_data["temp_password"],
                FriendlyDeviceName=form.cleaned_data["device_name"],
            )
            logger.debug(
                f"Cognito responds to User {self.request.user.username} TOTP update request as follows: {response}"
            )
        except (Boto3Error, ClientError) as e:
            logger.debug(
                f"while processing TOTP update request from {self.request.user.username} AssociateTOTPView encountered this exception: {e}"
            )
            messages.error(
                self.request,
                "An error occurred when verifying your software token. The code you entered was incorrect.",
            )
            form._errors.setdefault("code", ErrorList(["Code mismatch error. The code you entered was incorrect."]))
            context = self.get_context_data()
            context["form"] = form
            return render(self.request, "cogauth/totp.html", context)

        if response["Status"] == "SUCCESS":
            client.set_user_mfa_preference(
                SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True}, AccessToken=coguser.access_token
            )
            self.request.user.vinceprofile.multifactor = True
            self.request.user.vinceprofile.save()
            messages.success(self.request, "You have successfully enabled TOTP MFA on your account")
            send_courtesy_email("enable_mfa", self.request.user)
        else:
            logger.debug(
                f"Cognito does not report success for User {self.request.user.username} TOTP update request. The response is as follows: {response}"
            )
            messages.error(self.request, "An error occurred when verifying the software token.")
        return super(AssociateTOTPView, self).form_valid(form)

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        form = TOTPForm(request.POST)
        if form.is_valid():
            return self.form_valid(form)
        else:
            context = {}
            context["form"] = form
            context["secretcode"] = self.request.POST.get("secretcode")
            context["qrtext"] = (
                f"otpauth://totp/VINCE:{self.request.user.username}?secret={context['secretcode']}&issuer=VINCE"
            )
            return render(request, "cogauth/totp.html", context)


class ResetMFAView(FormView, AccessMixin):
    template_name = "cogauth/resetmfa.html"
    form_class = COGResetMFA
    login_url = "cogauth:login"

    def dispatch(self, request, *args, **kwargs):
        if not (request.session.get("MFAREQUIRED") and request.session.get("username")):
            return self.handle_no_permission()
        return super(ResetMFAView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ResetMFAView, self).get_context_data(**kwargs)
        return context

    def form_valid(self, form):
        del self.request.session["MFAREQUIRED"]

        vince_comm_send_sqs(
            "ResetMFA", "MFA", "None", self.request.session["username"], None, form.cleaned_data["reason"]
        )

        del self.request.session["username"]

        messages.success(self.request, "Please check your email for further instructions on resetting your MFA.")
        ip = vinceutils.get_ip(self.request)
        logger.info(f"Reset MFA request for User {self.request.user.username} from ip {ip}")
        return redirect("cogauth:login")


class RemoveMFAView(LoginRequiredMixin, TokenMixin, GetUserMixin, PendingTestMixin, TemplateView):
    template_name = "cogauth/rmmfa.html"
    login_url = "cogauth:login"

    def get_context_data(self, **kwargs):
        context = super(RemoveMFAView, self).get_context_data(**kwargs)
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        password = self.request.POST.get("password", None)
        ip = vinceutils.get_ip(self.request)
        logger.info(f"Remove MFA request for User {self.request.user.username} from ip {ip}")

        if password:
            logger.debug(f"Trying to authenticate {self.request.user.username} for MFA Removal")
            user = authenticate(request, username=self.request.user.username, password=password)
            if (user is None) and request.session.get("MFAREQUIRED"):
                request.session["CHANGEMFA"] = True
                request.session.save()
                return redirect(settings.MFA_REDIRECT_URL)
        messages.error(request, "Password was incorrect.  MFA not removed")
        return redirect("cogauth:profile")


class DeleteTokenView(LoginRequiredMixin, TokenMixin, GetUserMixin, TemplateView):

    template_name = "cogauth/gentoken.html"
    login_url = "cogauth:login"

    def get(self, request, *args, **kwargs):
        dresponse = {"delete": 0}
        ip = vinceutils.get_ip(self.request)
        logger.info(f"Remove Token request for User {self.request.user.username} from ip {ip}")
        try:
            token = VinceAPIToken.objects.get(user=self.request.user)
            token.delete()
            dresponse["delete"] = 1
            logger.info(f"The User's previous token was deleted  { self.request.user.username }")
        except VinceAPIToken.DoesNotExist:
            logger.debug(f"The User's token does not exist { self.request.user.username }")
            dresponse["delete"] = 0
        return JsonResponse(dresponse)


class GenerateTokenView(LoginRequiredMixin, TokenMixin, GetUserMixin, TemplateView):
    template_name = "cogauth/gentoken.html"
    login_url = "cogauth:login"

    def get_context_data(self, **kwargs):
        context = super(GenerateTokenView, self).get_context_data(**kwargs)
        context["coguser"] = self.get_user()
        # generate a token
        context["token"] = generate_key()
        # If the user already has a token
        # the action to check and delete key happens
        # in Javascript by request /delapikey url
        # identified by var vinny:deltoken
        token = VinceAPIToken(user=self.request.user)
        token.save(context["token"])
        c = get_cognito(self.request)
        c.update_profile({"custom:api_key": str(token)})
        ip = vinceutils.get_ip(self.request)
        logger.debug(f"New API key generated for { self.request.user.username } from ip {ip}")
        return context


class GenerateServiceTokenView(LoginRequiredMixin, TokenMixin, UserPassesTestMixin, TemplateView):
    template_name = "cogauth/gentoken.html"
    login_url = "cogauth:login"

    def test_func(self):
        if is_in_group_vincegroupadmin(self.request.user):
            gc = get_object_or_404(GroupContact, id=self.kwargs.get("vendor_id"))
            admin = VinceCommGroupAdmin.objects.filter(
                contact__id=gc.contact.id, email__email=self.request.user.email
            ).first()
            if admin:
                return PendingTestMixin.test_func(self)
        return False

    def get_context_data(self, **kwargs):
        ip = vinceutils.get_ip(self.request)
        context = super(GenerateServiceTokenView, self).get_context_data(**kwargs)
        # get service account
        gc = get_object_or_404(GroupContact, id=self.kwargs.get("vendor_id"))
        logger.debug(
            f"New Service Token create request from user {self.request.user.username} for Group {gc.group} from ip {ip}"
        )
        service = User.objects.filter(groups__in=[gc.group], vinceprofile__service=True).first()
        if service is None:
            raise Http404

        # generate a token
        context["token"] = generate_key()

        # does user already have a token
        try:
            token = VinceAPIToken.objects.get(user=service)
            token.delete()
        except VinceAPIToken.DoesNotExist:
            pass

        token = VinceAPIToken(user=service)
        token.save(context["token"])

        send_courtesy_email("service_account_change", self.request.user)
        send_courtesy_email("service_account_change", service)

        service.vinceprofile.api_key = str(token)
        service.vinceprofile.save()

        return context


class EnableMFAView(LoginRequiredMixin, TokenMixin, GetUserMixin, TemplateView):
    template_name = "cogauth/mfa.html"
    login_url = "cogauth:login"

    def dispatch(self, request, *args, **kwargs):
        self.cognito_user = self.get_user()
        if self.cognito_user.mfa:
            logger.debug("MFA already enabled for self.request.user")
            self.request.user.vinceprofile.multifactor = True
            self.request.user.vinceprofile.save()
            return redirect("vinny:dashboard")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(EnableMFAView, self).get_context_data(**kwargs)
        context["coguser"] = self.cognito_user
        return context

    def post(self, request, *args, **kwargs):
        logger.debug(f"{self.__class__.__name__} post: {self.request.POST}")
        mfa = self.request.POST.get("mfa", None)
        if mfa == "TOTP":
            return redirect("cogauth:totp")

        # set TOTP preferences
        elif mfa == "SMS":
            # set SMS preference
            return redirect("cogauth:sms")

        return redirect("cogauth:mfa")


class IndexView(TemplateView):

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        code = self.request.GET.get("code", False)
        if code:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {
                "grant_type": "authorization_code",
                "client_id": settings.COGNITO_APP_ID,
                "redirect_uri": settings.COGNITO_REDIRECT_TO,
                "code": code,
            }
            r = requests.post(COGNITO_OAUTH_URL, headers=headers, data=data)
            if not (r == None or (r.status_code != requests.codes.ok)):
                rj = r.json()
                access_token = rj["access_token"]
                refresh_token = rj["refresh_token"]
                id_token = rj["id_token"]
                u = Cognito(
                    settings.COGNITO_USER_POOL_ID,
                    settings.COGNITO_APP_ID,
                    user_pool_region=settings.COGNITO_REGION,
                    id_token=id_token,
                    refresh_token=refresh_token,
                    access_token=access_token,
                )

                u.check_token()
                self.request.session["ACCESS_TOKEN"] = access_token
                self.request.session["ID_TOKEN"] = id_token
                self.request.session["REFRESH_TOKEN"] = refresh_token
                self.request.session.save()
                client = boto3.client(
                    "cognito-idp", endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION
                )
                user = client.get_user(AccessToken=access_token)
                userauth = authenticate(self.request, username=user["Username"])
                if userauth:
                    redirect("vinny:dashboard")
        return context


class COGLoginView(FormView):
    template_name = "cogauth/login.html"
    form_class = COGAuthenticationForm

    def get_success_url(self):

        return reverse("vinny:dashboard")

    def get_context_data(self, **kwargs):
        context = super(COGLoginView, self).get_context_data(**kwargs)
        if settings.DEBUG:
            context["token_login"] = True

        return context

    def form_valid(self, form):
        return super(COGLoginView, self).form_valid(form)

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        for key in list(request.session.keys()):
            del request.session[key]
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            next_url = request.GET.get("next")
            user = authenticate(request, username=username, password=password)
            if user is not None:
                if user.last_login:
                    self.request.session["LAST_LOGIN"] = str(user.last_login)
                else:
                    self.request.session["LAST_LOGIN"] = "New"
                auth_login(request, user)
                logger.debug(
                    f"Login success! Now checking permissions for user {self.request.user.username} - is authenticated ? {self.request.user.is_authenticated} "
                )
                cognito_check_permissions(self.request)
                return super().form_valid(form)
                # return redirect("vinny:dashboard")
            else:
                if request.session.get("FORCEPASSWORD", False):
                    logger.debug(f"Redirecting due to force password change for {self.request.user}")
                    return redirect("cogauth:password_register")
                if request.session.get("MFAREQUIRED", False):
                    logger.debug(f"Redirecing for MFA, user is {self.request.user}")
                    if next_url:
                        url = reverse(settings.MFA_REDIRECT_URL) + f"?next={next_url}"
                        return redirect(url)
                    else:
                        return redirect(settings.MFA_REDIRECT_URL)

                elif request.session.get("RESETPASSWORD", False):
                    return redirect("cogauth:passwordreset")
                elif request.session.get("NOTCONFIRMED", False):
                    return redirect("cogauth:account_activation_sent")
                else:
                    form._errors.setdefault(
                        "username",
                        ErrorList(
                            [
                                "Please enter a correct username and password. "
                                "Note that both fields are case-sensitive."
                            ]
                        ),
                    )
                    return super().form_invalid(form)

                return redirect("cogauth:register")
        else:
            return super().form_invalid(form)


class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        return Response({"token": request.session.get("ID_TOKEN"), "email": user.username})


class LimitExceededView(LoginRequiredMixin, TemplateView):
    login_url = "cogauth:login"
    template_name = "cogauth/limitexceeded.html"


class ResendConfirmationCode(TemplateView):
    template_name = "cogauth/resend.html"

    def dispatch(self, request, *args, **kwargs):
        if self.request.session.get("CONFIRM_ID"):
            username = User.objects.filter(id=self.request.session.get("CONFIRM_ID")).first()
            if username:
                client = boto3.client(
                    "cognito-idp", endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION
                )
                try:
                    user = client.resend_confirmation_code(ClientId=settings.COGNITO_APP_ID, Username=username.email)
                    print(user)
                    details = user.get("CodeDeliveryDetails", None)
                    if details:
                        destination = details.get("Destination", None)
                        messages.success(request, "Resent confirmation code to %s" % destination)
                except:
                    messages.success(request, "User is already verified. Please Login")
                    return redirect("cogauth:login")
                self.request.session["RESEND"] = True
                return redirect("cogauth:account_activation_sent")
            else:
                return redirect("cogauth:register")
        else:
            return redirect("cogauth:login")


class InitialPasswordResetView(FormView):
    template_name = "cogauth/pwreset.html"
    form_class = COGInitialPWResetForm

    def form_valid(self, form):
        ip = vinceutils.get_ip(self.request)
        c = Cognito(
            settings.COGNITO_USER_POOL_ID,
            settings.COGNITO_APP_ID,
            user_pool_region=settings.COGNITO_REGION,
            username=form.cleaned_data["username"],
        )
        try:
            c.initiate_forgot_password()
            logger.warning("Initiate password reset for  %s from %s" % (form.cleaned_data["username"], ip))
        except (Boto3Error, ClientError) as e:
            logger.warning("User %s does not exist from %s" % (form.cleaned_data["username"], ip))
        # If the user_pool PreventUserExistenceErrors is NOT LEGACY
        # there will be no exception thrown. Below two are for logging only
        if not User.objects.using("vincecomm").filter(email__iexact=form.cleaned_data["username"]):
            logger.warning("User %s does not exist in VinceComm from %s" % (form.cleaned_data["username"], ip))
        if not User.objects.filter(email__iexact=form.cleaned_data["username"]):
            logger.warning("User %s does not exist in VinceTrack from %s" % (form.cleaned_data["username"], ip))
        self.request.session["RESETPASSWORD"] = True
        self.request.session["username"] = form.cleaned_data["username"]
        return redirect("cogauth:passwordreset")


class VerifyPhoneView(LoginRequiredMixin, TokenMixin, FormView):
    template_name = "cogauth/verify_phone.html"
    form_class = COGVerifyEmailForm
    login_url = "cogauth:login"

    # def get(self, request, *args, **kwargs):
    #    try:
    #        cognito_verify_sms(request)
    #    except (Boto3Error, ClientError) as e:
    #        logger.debug(traceback.format_exc())
    #        return redirect("cogauth:limitexceeded")
    #    return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        client = boto3.client("cognito-idp", endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
        user = None
        try:
            user = client.verify_user_attribute(
                AccessToken=self.request.session["ACCESS_TOKEN"],
                AttributeName="phone_number",
                Code=form.cleaned_data["code"],
            )
        except (Boto3Error, ClientError) as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "CodeMismatchException":
                form._errors.setdefault("code", ErrorList(["Your code is incorrect."]))
            elif error_code == "ExpiredCodeException":
                form._errors.setdefault("code", ErrorList(["Your code has expired. Try again."]))
            else:
                logger.debug(f"Error in cognito-idp validation {e}")
                form._errors.setdefault("code", ErrorList(["Your code is incorrect.."]))
            return render(self.request, "cogauth/verify_phone.html", {"form": form})
        if user:
            client.set_user_mfa_preference(
                SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
                AccessToken=self.request.session["ACCESS_TOKEN"],
            )
            self.request.user.vinceprofile.multifactor = True
            self.request.user.vinceprofile.save()
            messages.success(self.request, "You have successfully verified your phone number and enabled MFA.")
            send_courtesy_email("enable_mfa", self.request.user)
        else:
            messages.error(self.request, "An error occurred when verifying your software token.")
        return redirect("cogauth:profile")


class VerifyEmailView(LoginRequiredMixin, TokenMixin, FormView):
    template_name = "cogauth/verify_email.html"
    form_class = COGVerifyEmailForm
    login_url = "cogauth:login"

    def get(self, request, *args, **kwargs):
        try:
            cognito_verify_email(request)
        except (Boto3Error, ClientError) as e:
            return redirect("cogauth:limitexceeded")
        return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        client = boto3.client("cognito-idp", endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
        try:
            user = client.verify_user_attribute(
                AccessToken=self.request.session["ACCESS_TOKEN"], AttributeName="email", Code=form.cleaned_data["code"]
            )
        except (Boto3Error, ClientError) as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "CodeMismatchException":
                form._errors.setdefault("code", ErrorList(["Your code is incorrect."]))
            elif error_code == "ExpiredCodeException":
                form._errors.setdefault("code", ErrorList(["Your code has expired. Try again."]))
            elif error_code == "NotAuthorizedException":
                messages.error(self.request, e.response["Error"]["Message"])
                return redirect("cogauth:login")
            else:
                logger.debug(f"Error in cognito-idp access token validation {e}")
                messages.error(self.request, e.response["Error"]["Message"])
                form._errors.setdefault("code", ErrorList(["An error occurred when verifying your code."]))
            return super().form_invalid(form)

        self.request.user.vinceprofile.email_verified = True
        self.request.user.vinceprofile.save()
        return redirect("vinny:dashboard")

    def get_context_data(self, **kwargs):
        context = super(VerifyEmailView, self).get_context_data(**kwargs)
        email = self.request.user.email[:2]
        for x in range(2, len(self.request.user.email) - 4):
            email = email + "*"
        context["email"] = email + self.request.user.email[-2:]
        return context


class MFAAuthRequiredView(FormView, AccessMixin):
    template_name = "cogauth/mfarequired.html"
    form_class = COGVerifyEmailForm
    login_url = "cogauth:login"

    def dispatch(self, request, *args, **kwargs):
        if not (request.session.get("MFAREQUIRED") and request.session.get("username")):
            return self.handle_no_permission()
        return super(MFAAuthRequiredView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(MFAAuthRequiredView, self).get_context_data(**kwargs)
        if self.request.session.get("DEVICE_NAME"):
            context["device"] = self.request.session.get("DEVICE_NAME")

        try:
            # try to get app name and url so we stay in the same namespace and add next param
            app_name = resolve(self.request.path_info).view_name.split(":")[0]
            context["action"] = reverse(f"{app_name}:{self.request.resolver_match.url_name}")
            if self.request.GET.get("next"):
                context["action"] = "%s?next=%s" % (context["action"], self.request.GET.get("next"))
        except:
            pass
        return context

    def form_valid(self, form):
        c = Cognito(
            settings.COGNITO_USER_POOL_ID,
            settings.COGNITO_APP_ID,
            user_pool_region=settings.COGNITO_REGION,
            username=self.request.session["username"],
        )
        try:
            tokens = mfa_challenge(self.request, form.cleaned_data["code"])
        except (Boto3Error, ClientError) as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "CodeMismatchException":
                form._errors.setdefault("code", ErrorList(["Your code is incorrect."]))
            elif error_code == "ExpiredCodeException":
                form._errors.setdefault("code", ErrorList(["Your code has expired. Try again."]))
            elif error_code == "NotAuthorizedException":
                messages.error(self.request, e.response["Error"]["Message"])
                return redirect("cogauth:login")
            else:
                logger.debug(f"Error in MFA validation validation {e}")
                messages.error(self.request, e.response["Error"]["Message"])
                form._errors.setdefault("code", ErrorList(["An error occurred when verifying your code."]))
            return super().form_invalid(form)
        if tokens:
            self.request.session["ID_TOKEN"] = tokens["AuthenticationResult"]["IdToken"]
            self.request.session["REFRESH_TOKEN"] = tokens["AuthenticationResult"]["RefreshToken"]
            self.request.session["ACCESS_TOKEN"] = tokens["AuthenticationResult"]["AccessToken"]
            user = authenticate(self.request, username=self.request.session["username"])
            if user:
                del self.request.session["username"]
                auth_login(self.request, user)
                self.cognito = get_cognito(self.request)
                coguser = self.cognito.get_user(attr_map=settings.COGNITO_ATTR_MAPPING)
                # set session timezone
                self.request.session["timezone"] = coguser.timezone

                if self.request.session.get("CHANGEMFA"):
                    rm_mfa(self.request)
                    self.request.user.vinceprofile.multifactor = False
                    self.request.user.vinceprofile.save()
                    del self.request.session["MFASession"]
                    del self.request.session["CHANGEMFA"]
                    messages.success(self.request, "MFA successfully disabled. Please choose another type of MFA.")
                    send_courtesy_email("mfa_removed", self.request.user)
                    del self.request.session["MFAREQUIRED"]
                    return redirect("cogauth:profile")
                cognito_check_permissions(self.request)
                del self.request.session["MFAREQUIRED"]

                next_url = self.request.GET.get("next")
                if next_url:
                    logger.debug(f"NEXT URL provided by GET request {next_url}")
                    try:
                        if is_safe_url(next_url, set(settings.ALLOWED_HOSTS), True):
                            return redirect(next_url)
                        else:
                            return redirect(settings.LOGIN_REDIRECT_URL)
                    except Exception as e:
                        logger.debug(f"Error in redirection validator {e}")
                        pass
                logger.debug(f"Redirecting to default LOGIN_URL {settings.LOGIN_REDIRECT_URL}")
                return redirect(settings.LOGIN_REDIRECT_URL)
        else:
            logger.debug(f"Login redirection error no tokens provided, error is {e}")
            form._errors.setdefault("code", ErrorList(["Your code is incorrect."]))
            return super().form_invalid(form)

        return redirect("cogauth:pw_reset_confirmed")


class ResetPasswordView(FormView, AccessMixin):
    template_name = "cogauth/reset_password.html"
    form_class = COGResetPasswordForm

    def form_valid(self, form):
        ip = vinceutils.get_ip(self.request)
        c = Cognito(
            settings.COGNITO_USER_POOL_ID,
            settings.COGNITO_APP_ID,
            user_pool_region=settings.COGNITO_REGION,
            username=self.request.session["username"],
        )
        try:
            c.confirm_forgot_password(form.cleaned_data["code"], form.cleaned_data["new_password1"])
        except (Boto3Error, ClientError) as e:
            logger.warning(
                "User %s Password reset failed error is %s from ip %s" % (self.request.session["username"], e, ip)
            )
            error_code = e.response["Error"]["Code"]
            if error_code == "CodeMismatchException":
                form._errors.setdefault("code", ErrorList(["Your code is incorrect."]))
            elif error_code == "InvalidPasswordException":
                form._errors.setdefault(
                    "new_password1", ErrorList([f"New password is unacceptable: {e.response['Error']['Message']}"])
                )
            else:
                form._errors.setdefault(
                    "new_password1",
                    ErrorList([f"Error occurred: {e.response['Error']['Code']}: {e.response['Error']['Message']}"]),
                )

            return super().form_invalid(form)
        del self.request.session["username"]
        del self.request.session["RESETPASSWORD"]

        return redirect("cogauth:pw_reset_confirmed")

    def dispatch(self, request, *args, **kwargs):
        if not (request.session.get("RESETPASSWORD") and request.session.get("username")):
            return self.handle_no_permission()
        return super(ResetPasswordView, self).dispatch(request, *args, **kwargs)


class ConfirmRegister(FormView):
    template_name = "cogauth/account_activation_sent.html"
    form_class = VerificationForm
    success_url = "vince/index.html"

    def dispatch(self, request, *args, **kwargs):
        if self.request.session.get("CONFIRM_ID"):
            return super(ConfirmRegister, self).dispatch(request, *args, **kwargs)
        else:
            return redirect("cogauth:login")

    def form_valid(self, form):
        c = Cognito(settings.COGNITO_USER_POOL_ID, settings.COGNITO_APP_ID, user_pool_region=settings.COGNITO_REGION)
        if self.request.session.get("CONFIRM_ID"):
            username = User.objects.using("vincecomm").filter(id=self.request.session.get("CONFIRM_ID")).first()
            try:
                c.confirm_sign_up(form.cleaned_data["code"], username=username.username)
                username.vinceprofile.email_verified = True
                username.vinceprofile.save()
            except ClientError as e:
                return render(
                    self.request, "cogauth/account_error.html", {"error_msg": e.response["Error"]["Message"]}
                )
            del self.request.session["CONFIRM_ID"]
            if self.request.session.get("SERVICE"):
                service = self.request.session.get("SERVICE")
                del self.request.session["SERVICE"]
                if self.request.session.get("RESEND"):
                    del self.request.session["RESEND"]

                messages.success(self.request, _("The account was successfully confirmed."))
                return redirect("vinny:admin", service)
            return redirect("cogauth:account_confirmed")
        else:
            return render(self.request, "cogauth/account_error.html", {"error_msg": "Invalid User/Code"})

    def get_context_data(self, **kwargs):
        context = super(ConfirmRegister, self).get_context_data(**kwargs)
        if self.request.session.get("CONFIRM_ID"):
            username = User.objects.using("vincecomm").filter(id=self.request.session["CONFIRM_ID"]).first()
            if username:
                email = username.username[:2]
                for x in range(2, len(username.email) - 4):
                    email = email + "*"
                    context["email"] = email + username.email[-2:]
        if self.request.session.get("SERVICE"):
            if not self.request.session.get("RESEND"):
                self.template_name = "cogauth/service_activation_sent.html"
        return context


class ChangePasswordView(LoginRequiredMixin, TokenMixin, PendingTestMixin, FormView):
    template_name = "cogauth/password_change_form.html"
    form_class = COGPasswordChangeForm
    login_url = "cogauth:login"

    def get_success_url(self):
        return reverse("cogauth:password_change_done")

    # def get_form_kwargs(self):
    #    kwargs = super(ChangePasswordView, self).get_form_kwargs()
    #    kwargs['user'] = self.request.user
    #    if self.request.method == 'POST':
    #        kwargs['data'] = self.request.POST
    #    return kwargs

    # def post(self, request, *args, **kwargs):
    #    logger.debug(request.POST)
    #    form = COGPasswordChangeForm(request.user, request.POST)
    #    if form.is_valid():
    #        return self.form_valid(form)
    #    else:
    #        return super().form_invalid(form)

    def form_valid(self, form):
        # user = form.save()
        # update_session_auth_hash(self.request, user)

        c = get_cognito(self.request)
        ip = vinceutils.get_ip(self.request)
        try:
            c.change_password(form.cleaned_data["old_password"], form.cleaned_data["new_password1"])
            logger.info(f"Password was updated for {self.request.username} from IP {ip}")
        except ParamValidationError:
            logger.info(f"Password updated failed for {self.request.username} from IP {ip} - invalid new password")
            form._errors.setdefault("new_password1", ErrorList(["New password is unacceptable."]))
            return super().form_invalid(form)
        except (Boto3Error, ClientError) as e:
            error_code = e.response["Error"]["Code"]
            logger.info(f"Password updated failed for {self.request.username} from IP {ip} - {e} {error_code}")
            if error_code == "NotAuthorizedException":
                form._errors.setdefault("old_password", ErrorList(["Password is incorrect."]))
                return super().form_invalid(form)
            elif error_code == "InvalidPasswordException":
                form._errors.setdefault(
                    "new_password1", ErrorList([f"New password is unacceptable: {e.response['Error']['Message']}"])
                )
                return super().form_invalid(form)
            elif error_code == "LimitExceededException":
                form._errors.setdefault(
                    "new_password1", ErrorList(["Password Change Limit Exceeded.  Please try again later."])
                )
                return super().form_invalid(form)
            else:
                logger.warning("UNEXPECTED ERROR WHILE CHANGING PASSWORD")
                logger.warning(error_code)
                form._errors.setdefault(
                    "new_password1", ErrorList(["An error occurred while trying to change your password."])
                )
                return super().form_invalid(form)

        send_courtesy_email("password_change", self.request.user)
        return super().form_valid(form)


class ChangePasswordandRegisterView(FormView, AccessMixin):
    template_name = "cogauth/change_password_and_register.html"
    form_class = COGPasswordChangeForm
    success_url = "cogauth/password_change_done.html"

    def form_valid(self, form):
        #        user = form.save()
        logger.debug(self.request.session.get("username"))
        tokens = password_challenge_dance(
            self.request.session.get("username"), form.cleaned_data["old_password"], form.cleaned_data["new_password1"]
        )
        if tokens is None:
            form._errors.setdefault("old_password", ErrorList(["Your temporary password is incorrect."]))
            return super().form_invalid(form)
        self.request.session["ID_TOKEN"] = tokens["AuthenticationResult"]["IdToken"]
        self.request.session["REFRESH_TOKEN"] = tokens["AuthenticationResult"]["RefreshToken"]
        self.request.session["ACCESS_TOKEN"] = tokens["AuthenticationResult"]["AccessToken"]
        user = authenticate(
            self.request, username=self.request.session.get("username"), password=form.cleaned_data["new_password1"]
        )
        if user is not None:
            del self.request.session["username"]
            del self.request.session["FORCEPASSWORD"]
            auth_login(self.request, user)
            cognito_check_permissions(self.request)
            send_courtesy_email("password_change", user)
            return redirect("vinny:dashboard")
        else:
            if request.session.get("FORCEPASSWORD", False):
                return redirect("cogauth:password_change")
            else:
                form._errors.setdefault("username", ErrorList(["Error Occurred. Please contact cert@cert.org"]))
                return super().form_invalid(form)

        return super().form_valid(form)

    def dispatch(self, request, *args, **kwargs):
        if not (request.session.get("FORCEPASSWORD") and request.session.get("username")):
            return self.handle_no_permission()
        return super(ChangePasswordandRegisterView, self).dispatch(request, *args, **kwargs)


class LoginHelpView(TemplateView):
    template_name = "cogauth/loginhelp.html"

    def get_context_data(self, **kwargs):
        context = super(LoginHelpView, self).get_context_data(**kwargs)

        if self.request.session.get("username"):
            # this user has already entered their name and password
            context["showlink"] = 1

        return context


class RegisterView(FormView):
    template_name = "cogauth/signup.html"
    form_class = SignUpForm
    success_url = "cogauth/account_activation_sent.html"

    def get_context_data(self, **kwargs):
        context = super(RegisterView, self).get_context_data(**kwargs)
        if hasattr(settings, "TERMS_URL"):
            context["terms_url"] = settings.TERMS_URL
        else:
            context["terms_url"] = "#"
        if self.request.session.get("REGISTER", False):
            context["form"] = self.form_class(initial={"email": self.request.session["REGISTER"]})
            context["title"] = "Confirm your VINCE Registration"
            context["subtitle"] = "Before you can login, we need a bit more information from you."
        else:
            context["title"] = "Create a VINCE Account"
        return context

    def form_valid(self, form):
        # Begin reCAPTCHA validation
        ip = vinceutils.get_ip(self.request)
        recaptcha_response = self.request.POST.get("g-recaptcha-response")
        data = {"secret": settings.GOOGLE_RECAPTCHA_SECRET_KEY, "response": recaptcha_response}
        email = form.cleaned_data["email"]
        try:
            r = requests.post(GOOGLE_VERIFY_URL, data=data)
            result = r.json()
            if not result["success"]:
                logger.warning(f"Invalid recaptcha validation Result: {result} {email} from IP {ip}")
                form._errors[forms.forms.NON_FIELD_ERRORS] = ErrorList(["Invalid reCAPTCHA.  Please try again"])
                return super().form_invalid(form)
        except Exception as e:
            logger.warning(f"Failed for recaptcha exception raised {e} from IP {ip}")
        dup = User.objects.using("vincecomm").filter(email__iexact=email)
        if dup:
            reset_url = reverse("cogauth:init_password_reset")
            form._errors.setdefault(
                "email",
                ErrorList(
                    [
                        f'Email already exists. Usernames are <b>CASE SENSITIVE</b>. Or did you forget your password? <a href="{reset_url}">Reset your password</a>.'
                    ]
                ),
            )
            logger.warning(f"Attempt to register duplicate user {email} from IP {ip}")
            return super().form_invalid(form)

        reserved = VinceCommEmail.objects.filter(email__iexact=form.cleaned_data["email"], email_list=True)
        if reserved:
            form._errors.setdefault(
                "email",
                ErrorList(
                    [
                        "Email already exists. Usernames are <b>CASE SENSITIVE</b>. This email is reserved, please use your personal email address for accounts."
                    ]
                ),
            )
            logger.warning(f"Attempt to register duplicate user {email} which is notification onlyfrom IP {ip}")
            return super().form_invalid(form)

        c = Cognito(settings.COGNITO_USER_POOL_ID, settings.COGNITO_APP_ID, user_pool_region=settings.COGNITO_REGION)
        c.add_base_attributes(
            email=form.cleaned_data["email"],
            given_name=form.cleaned_data["first_name"],
            family_name=form.cleaned_data["last_name"],
            preferred_username=form.cleaned_data["preferred_username"],
        )
        c.add_custom_attributes(Organization=form.cleaned_data["organization"], title=form.cleaned_data["title"])
        # must register user first, otherwise user will exist locally and not in cognito if
        # password doesn't meet requirements
        try:
            #          c.register(form.cleaned_data['preferred_username'], form.cleaned_data['password1'])
            c.register(form.cleaned_data["email"], form.cleaned_data["password1"])
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidPasswordException":
                form._errors.setdefault(
                    "password1", ErrorList([f"Password not accepted: {e.response['Error']['Message']}"])
                )
                return super().form_invalid(form)
            elif e.response["Error"]["Code"] == "UsernameExistsException":
                reset_url = reverse("cogauth:init_password_reset")
                form._errors.setdefault(
                    "email",
                    ErrorList(
                        [
                            f'Email already exists. Did you forget your password? <a href="{reset_url}">Reset your password</a>.'
                        ]
                    ),
                )
                return super().form_invalid(form)
            else:
                form._errors.setdefault(
                    "password1",
                    ErrorList([f"Error occurred: {e.response['Error']['Code']}: {e.response['Error']['Message']}"]),
                )
                return super().form_invalid(form)

        user = form.save()
        user.refresh_from_db()
        user.username = user.email
        user.is_active = True
        user.vinceprofile.preferred_username = form.cleaned_data["preferred_username"]
        user.vinceprofile.org = form.cleaned_data["organization"]
        user.vinceprofile.title = form.cleaned_data["title"]
        user.vinceprofile.save()
        user.save()
        logger.info(f"New user successfully registered {user.email} from IP {ip}")
        self.request.session["CONFIRM_ID"] = user.id
        return redirect("cogauth:account_activation_sent")


def dict_to_cognito(attributes, attr_map=None):
    """
    :param attributes: Dictionary of User Pool attribute names/values
    :return: list of User Pool attribute formatted dicts: {'Name': <attr_name>, 'Value': <attr_value>}
    """
    if attr_map is None:
        attr_map = {}
    for k, v in attr_map.copy().items():
        if v in attributes.keys():
            #            attributes.update({k: attributes.pop(k, None)})
            attributes[k] = attributes.pop(v)
        else:
            if k in attributes:
                attributes.pop(k)
    #    return [{'Name': key, 'Value': value} for key, value in attributes.items()]
    return attributes


class UpdateProfileView(LoginRequiredMixin, TokenMixin, GetUserMixin, FormView):
    template_name = "cogauth/update-profile.html"
    form_class = ProfileForm
    login_url = "cogauth:login"

    def get_success_url(self):
        return reverse_lazy("cogauth:profile")

    def get_initial(self):
        u = self.get_user()
        initial = u.__dict__.get("_data")
        initial["timezone"] = self.request.user.vinceprofile.timezone
        return initial

    def get_context_data(self, **kwargs):
        context = super(UpdateProfileView, self).get_context_data(**kwargs)
        context["unread_msg_count"] = _unread_msg_count(self.request.user)
        return context

    def form_valid(self, form):
        c = get_cognito(self.request)
        self.request.user.first_name = form.cleaned_data["first_name"]
        self.request.user.last_name = form.cleaned_data["last_name"]
        self.request.user.vinceprofile.preferred_username = form.cleaned_data["preferred_username"]
        self.request.user.vinceprofile.org = form.cleaned_data["org"]
        self.request.user.vinceprofile.country = form.cleaned_data["country"]
        self.request.user.vinceprofile.title = form.cleaned_data["title"]
        self.request.user.vinceprofile.timezone = form.cleaned_data["timezone"]
        self.request.user.vinceprofile.save()
        self.request.user.save()
        user_attrs = dict_to_cognito(form.cleaned_data, settings.COGNITO_ATTR_MAPPING)

        # set new timezone
        self.request.session["timezone"] = self.request.user.vinceprofile.timezone
        c.update_profile(user_attrs)
        messages.success(self.request, "You have successfully updated your profile.")
        return super(UpdateProfileView, self).form_valid(form)


class LogoutView(CALogoutView):

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        request.session.delete()
        ip = vinceutils.get_ip(request)
        logger.info(f"Performing logout of user {request.user.username} from ip {ip}")
        return super(LogoutView, self).dispatch(request, *args, **kwargs)


class GetCognitoUserMixin(object):
    client = boto3.client("apigateway", region_name=settings.COGNITO_REGION, endpoint_url=get_cognito_url())

    def get_user_object(self):
        cog_client = boto3.client("cognito-idp", endpoint_url=get_cognito_url(), region=settings.COGNITO_REGION)
        user = cog_client.get_user(AccessToken=self.request.session["ACCESS_TOKEN"])
        c = get_cognito(self.request)
        u = UserObj(
            username=user.get("UserAttributes")[0].get("username"),
            attribute_list=user.get("UserAttributes"),
            attr_map=settings.COGNITO_ATTR_MAPPING,
            cognito_obj=c,
        )
        return u

    def get_queryset(self):
        try:
            u = self.get_user_object()
        except KeyError:
            raise Http404
        my_plans = self.client.get_usage_plans(keyId=u.api_key_id)
        return my_plans.get("items", [])
