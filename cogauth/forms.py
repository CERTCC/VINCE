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
from django import forms
from django_countries.widgets import CountrySelectWidget
from django_countries.fields import CountryField
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from django.contrib.auth.models import User
from django.utils.translation import gettext, gettext_lazy as _
import logging
from re import search
import pytz 
logger = logging.getLogger(__name__)

class COGAuthenticationForm(forms.Form):
    username = forms.RegexField(
        label=_("Email"),
        max_length=200,
        regex=r'^[\w.@+-_]+$',
        required=True,
        error_messages={'invalid':_("Username is typically an email address. It may not contain certain special characters (such as spaces).  It is CASE SENSITIVE.")})

    password = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput)

    def clean_username(self):
        # lowercase the domain part of the email address
        # because django is going to do it anyway when creating
        # the user and we need django and cognito to be in sync
        email =	self.cleaned_data['username']
        parts = email.strip().split('@', 1)
        if len(parts) > 1:
            parts[1] = parts[1].lower()
        email = '@'.join(parts)
        return email
    
class COGPasswordRegisterForm(forms.Form):
    newpassword1 = forms.CharField(max_length=50, required=True, widget=forms.PasswordInput)
    newpassword2 = forms.CharField(max_length=50, required=True, widget=forms.PasswordInput)
    first_name = forms.CharField(max_length=200,required=True)
    last_name = forms.CharField(max_length=200,required=True)
    company = forms.CharField(max_length=200, label="Company/Affiliation", required=False)
    country = CountryField(default='US').formfield()
    
    def clean(self):
        cleaned_data = super().clean()
        newpassword1 = cleaned_data.get('newpassword1')
        newpassword2 = cleaned_data.get('newpassword2')

        if newpassword1 != newpassword2:
            self.add_error('newpassword2', "Password does nto match")
            raise forms.ValidationError(" New Passwords did not match")

    class Meta:
        widgets = {
            'countrycode': CountrySelectWidget()}


class COGResetMFA(forms.Form):

    reason = forms.CharField(
        widget=forms.Textarea(),
        label=_('Reason for MFA reset'))
        
        
class COGInitialPWResetForm(forms.Form):
    username = forms.CharField(max_length=200, required=True, label=_("Email"))

    def clean_username(self):
        email = self.cleaned_data['username']
        parts = email.strip().split('@', 1)
        if len(parts) > 1:
            parts[1] = parts[1].lower()
        email = '@'.join(parts)
        return email

class COGVerifyEmailForm(forms.Form):
    code = forms.CharField(
        max_length=10,
        required=True,
        widget=forms.TextInput(attrs={'autofocus': 'autofocus', 'autocomplete':'off'}))

    def clean(self):
        cleaned_data = super().clean()
        if len(cleaned_data.get('code')) < 6:
            self.add_error('code', "Minimum 6 digits are required.")
            raise forms.ValidationError(" Invalid length for user code.")
        
class COGResetPasswordForm(forms.Form):
    code = forms.CharField(
        max_length=10,
        required=True,
        widget=forms.TextInput(attrs={'autocomplete':'off'}))

    new_password1 = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput,
        label="New Password")
    
    new_password2 = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput,
        label="Please re-enter Password")

    def clean(self):
        cleaned_data = super().clean()
        newpassword1 = cleaned_data.get('new_password1')
        newpassword2 = cleaned_data.get('new_password2')

        if len(newpassword1) < 8:
            raise forms.ValidationError("Password does not meet length requirements")
        
        if newpassword1 != newpassword2:
            self.add_error('new_password2', "Passwords do not match")
            raise forms.ValidationError("Passwords did not match")
        
        
class COGPasswordChangeForm(forms.Form):
    old_password = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput,
        label="Current Password")
    
    new_password1 = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput,
        label="New Password")
    
    new_password2 = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput,
        label="Please re-enter Password")

    def clean(self):
        cleaned_data = super().clean()
        newpassword1 = cleaned_data.get('new_password1')
        newpassword2 = cleaned_data.get('new_password2')

        if newpassword1 != newpassword2:
            self.add_error('new_password2', "Passwords do not match")
            raise forms.ValidationError("Passwords did not match")
    
class TOTPForm(forms.Form):
    temp_password = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={'autocomplete':'off'}),
        label="Temporary Password",
        help_text="The current code generated in the app",
        required=True)
    
    device_name = forms.CharField(
        max_length=200,
        label="Device Name",
        required=False,
        help_text="A friendly device name to remind you of the application you used.")

    def clean(self):
        cleaned_data = super().clean()
        if len(cleaned_data.get('temp_password')) < 6:
            self.add_error('temp_password', "Minimum 6 digits are required.")
            raise forms.ValidationError(" Invalid length for user code.")
    
# phone numbers vary greatly world-wide, so best we can do is verify
# that no "weird" characters are entered.
def validate_phone_number(value):
    phone_re = "\+[^0-9+]" # set of all things except phone number characters and commas
    if search(phone_re, value) is not None:
        raise forms.ValidationError('%s contains non-telephone characters' % value)
    
class MFASMSForm(forms.Form):
    phone_number = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': '+14122687090'}),
        max_length=60,
        help_text="Phone numbers must follow these formatting rules: A phone number"
        " must start with a plus (+) sign, followed immediately by the country code. "
        "A phone number can only contain the + sign and digits. You must remove "
        "parentheses, spaces, or dashes.  (e.g. a US-based phone number must follow this"
        " format: +14325551212)",
        required=True,
        label='Telephone',
        validators=[validate_phone_number])
        
class ProfileForm(forms.Form):
    
    first_name = forms.CharField(
        max_length=200,required=True)
    
    last_name = forms.CharField(
        max_length=200,required=True)
    
    country = CountryField(default='US').formfield(required=False)
    
    email = forms.EmailField(
        required=True,
        disabled=True,
        label="Login Username/Email. This field is case sensitive.")

    preferred_username = forms.RegexField(
        label=_("Preferred Display Name"),
        max_length=254,
        help_text=_('The name displayed to other VINCE users. It may only contain 1 space and may not contain certain special characters.'),
        regex=r'^[-\w\+]+(\s[-\w\+]+)*$',
        required=True,
        error_messages={'invalid':_("Invalid username. Your display name may only contain 1 space and may not contain certain special characters.")})
    
    org = forms.CharField(
        max_length=200,
        label="Company/Affiliation",
        required=False)
    
    title = forms.CharField(
        max_length=200,
        label="Job Title",
        help_text=_('This field is visible to other VINCE users'),
        required=False)

    timezone = forms.ChoiceField(
        label="Timezone",
        choices=[(x, x) for x in pytz.common_timezones])

    def __init__(self, *args, **kwargs):
        super(ProfileForm, self).__init__(*args,**kwargs)
    
    class Meta:
        widgets = {
            'countrycode': CountrySelectWidget()}
        
class VerificationForm(forms.Form):
    code = forms.CharField(max_length=10, required=True, widget=forms.TextInput(attrs={'autofocus': 'autofocus', 'autocomplete':'off'}))
    
class SignUpForm(UserCreationForm):
    organization = forms.CharField(
        max_length=200,
        label="Company/Affiliation",
        required=False)
    email = forms.CharField(
        max_length=254,
        widget=forms.TextInput(attrs={'autocomplete':'username'}),
        required=True,
        help_text=_('This will be your personal login username. <b>This field is CASE SENSITIVE.</b><br/><b>PLEASE NOTE:</b> Each VINCE user account is intended to be tied to a specific individual. If you would like to use an alias (for example, <i>psirt@example.com</i>) to receive group notifications, please create your account here first, and once your individual account has been approved, you will have the opportunity to create a group, join an existing group, and otherwise manage the email addresses associated with your organization.'), 
        label="Email address")

    title = forms.CharField(
        max_length=200,
        required=False,
        label="Job Title")
    
    preferred_username = forms.RegexField(
        label=_("Preferred Display Name"),
        max_length=254,
        help_text=_('The name visible to other VINCE users. It may only contain 1 space and may not contain certain special characters. (You can modify this later)'),
        regex=r'^[-\w\+]+(\s[-\w\+]+)*$',
        required=True,
        error_messages={'invalid':_("Invalid username. Your display name may only contain 1 space and may not contain certain special characters.")})

    password1 = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput(attrs={'autocomplete':"new-password"}),
        label="New Password",
        help_text=_('Password Requirements:<ul>\
        <li>Minimum length is 8 characters</li>\
        <li>Maximum length is 50 characters</li>\
        <li>Requires at least 1 number</li>\
        <li>Requires at least 1 special character ("+" and "=" don\'t count)</li>\
        <li>Requires uppercase letters</li>\
        <li>Requires lowercase letters</li>\
        </ul>'))

    password2 = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput(attrs={'autocomplete':"new-password"}),
        label="Password confirmation",
        help_text=_('Enter the same password as before, for verification')
    )
    
    agree_to_terms = forms.BooleanField(
        required=True,
        label="I agree to the terms of service")
    
    class Meta:
        model = User
        fields = ("email", "password1", "password2", "preferred_username", "first_name", "last_name", "organization", "title", "agree_to_terms")
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', '')
        super(SignUpForm, self).__init__(*args,**kwargs)

    def clean_email(self):
        # lowercase the domain part of the email address
        # because django is going to do it anyway when creating
        # the user and we need django and cognito to be in sync
        email = self.cleaned_data['email']
        parts = email.strip().split('@', 1)
        if len(parts) > 1:
            parts[1] = parts[1].lower()
        email = '@'.join(parts)
        return email
        
    def save(self, commit=True):
        user = super(SignUpForm, self).save(commit=False)
        user.save()
        return user

