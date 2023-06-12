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
from django.utils import timezone
from django.forms.widgets import SelectDateWidget
from .models import *
from django.template.defaultfilters import filesizeformat
from django.core.exceptions import ValidationError
from datetime import date
from re import search
from django.conf import settings

LIMIT_CHOICES = [(1, "10"), (2, "25"), (3, "50"), (4, "100"), (5, "All")]
SORT_CHOICES = [(1, "Newest First"),(2, "Oldest first")]


COORD_STATUS_CHOICES = [(1, "I have not attempted to contact any vendors"),
                        (2, "I have been unable to find contact information for a vendor"),
                        (3, "I have contacted vendors but not sent them details"),
                        (4, "I have sent details to vendors"),
                        (5, "None of these apply")]
WHY_NOT_CHOICES = [(1, 'I have not attempted to contact any vendors'),
                   (2, 'I have been unable to find contact information for a vendor'),
                   (3, 'Other')]
YES_NO_CHOICES = [(1, "YES"), (2, "NO")]
YEAR_CHOICES = [(y,y) for y in range(date.today().year,1999,-1)]

# to restrict size of uploads
# http://chriskief.com/2013/10/19/limiting-upload-file-size-with-django-forms/
# http://stackoverflow.com/questions/2472422/django-file-upload-size-limit
class RestrictedFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        self.content_types = kwargs.pop('content_types', None)
        self.max_upload_size = kwargs.pop('max_upload_size', None)
        if not self.max_upload_size:
            self.max_upload_size = settings.MAX_UPLOAD_SIZE
        super(RestrictedFileField, self).__init__(*args, **kwargs)

    def clean(self, *args, **kwargs):
        data = super(RestrictedFileField, self).clean(*args, **kwargs)
        try:
            if data.content_type.split('/')[0] in self.content_types:
                if data.size > self.max_upload_size:
                    raise forms.ValidationError('File size must be under %s. Current file size is %s.' % (filesizeformat(self.max_upload_size), filesizeformat(data.size)))
            else:
                raise forms.ValidationError('File type (%s) is not supported.' % data.content_type)
        except AttributeError:
            pass

        return data


# to write your own validators:
# https://docs.djangoproject.com/en/1.8/ref/validators/
def validate_not_future_date(value):
    if value > date.today():
        raise ValidationError('%s is a future date' % value)

# phone numbers vary greatly world-wide, so best we can do is verify
# that no "weird" characters are entered.
def validate_phone_number(value):
    phone_re = "[^0-9()+.,\- ]" # set of all things except phone number characters and commas
    if search(phone_re, value) is not None:
        raise ValidationError('%s contains non-telephone characters' % value)


class SearchForm(forms.Form):
    wordSearch = forms.CharField(max_length=100, label='Keyword(s)', widget=forms.TextInput(), required=False)
    vendor = forms.CharField(max_length=100, label="Search by vendor", required=False)
    datestart = forms.DateField(required=False)
    dateend = forms.DateField(required=False)
    page = forms.CharField(max_length=5, required=False)
    years = forms.MultipleChoiceField(choices=YEAR_CHOICES,
                                      required=False,
                                      widget=forms.CheckboxSelectMultiple(attrs={'class' : 'ul_nobullet'}))
    
    def __init__(self, *args, **kwargs):
        super(SearchForm, self).__init__(*args, **kwargs)
        self.fields['dateend'].initial = timezone.now

    def to_list(self):
        return [y[0] for y in YEAR_CHOICES]

    def clean(self):
        cleaned_data = super(SearchForm, self).clean()
        wordSearch1 = cleaned_data.get("wordSearch")
        vendor1 = cleaned_data.get("vendor")
        
        if not wordSearch1 and not vendor1:
            self.add_error('wordSearch', 'Please fill in either word search or vendor field.')
            self.add_error('vendor', 'Please fill in either word search or vendor field.')
            raise forms.ValidationError("Please fill out fields.")

        return cleaned_data


class GovReportForm(forms.ModelForm):
    contact_name = forms.CharField(
        max_length=100,
        required=False,
        label='Name', 
        help_text='The name of the person submitting this form. You may use a pseudonym, alias, or handle in place of your real name.')
    contact_org = forms.CharField(
        max_length=100, 
        required=False, 
        label='Organization', 
        help_text='The name of the organization you are reporting on behalf of, if applicable.')
    contact_email = forms.EmailField(
        label='Email address', 
        required=False,
        max_length=100,
        help_text='Your personal email address. Consider creating a free webmail account if you do not wish to share your email address.')
    reporter_pgp = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'ASCII-armored public PGP key or URL (optional, but helps us communicate securely with you)'}),
        label='Public PGP key',
        max_length=100000000,
        required=False,
        help_text="Optionally, if you would like to use PGP encrypted email, please include either your ASCII-armored PGP key or a URL to your key. CERT/CC will use this key for future correspondence."
    )
    contact_phone = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': '+1 412-268-7090'}),
        max_length=60, 
        required=False, 
        label='Telephone', 
        validators=[validate_phone_number],
        help_text='The telephone where we may reach you if necessary')
    credit_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want to be acknowledged by name if DHS publishes a document based on this report?',
        help_text='DHS will credit you unless otherwise specified.', 
        required=True,
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}))
    affected_website = forms.URLField(
        widget=forms.TextInput(attrs={'placeholder': 'e.g., https://dhs.gov'}),
        label='Affected Website', 
        help_text='Please provide the URL to the domain affected by this vulnerability',
        required=True,
        max_length=200)
    vul_description = forms.CharField(
        max_length=10000, 
        label='Proof of Concept Description', 
        widget=forms.Textarea(), 
        help_text='Please provide a description of the vulnerability and proof of concept information here.')

    comments = forms.CharField(
        max_length=20000, 
        label='Any additional comments that will not be shared with vendors:', 
        help_text='Comments in this box will be kept private and will not be included in any publication or shared with vendors.', 
        required=False, 
        widget=forms.Textarea())

    user_file = RestrictedFileField(
        label='Upload File',
        help_text="You may specify one (1) related file to send us",
        content_types=['application', 'text', 'image', 'video'],
        required=False
    )
    
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', '')
        super(GovReportForm, self).__init__(*args,**kwargs)
    
    class Meta:
        model = GovReport
        fields = "__all__"


class VulCoordForm(forms.ModelForm):
    contact_name = forms.CharField(
        max_length=100, 
        label='Name', 
        required=False,
        help_text='The name of the person submitting this form. You may use a pseudonym, alias, or handle in place of your real name.')
    contact_org = forms.CharField(
        max_length=100, 
        required=False, 
        label='Organization', 
        help_text='The name of the organization you are reporting on behalf of, if applicable.')

    contact_email = forms.EmailField(
        label='Email address', 
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'address@example.com'}),
        help_text='Your personal email address. Consider creating a free webmail account if you do not wish to share your email address.')
    reporter_pgp = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'ASCII-armored public PGP key or URL (optional, but helps us communicate securely with you)'}),
        label='Public PGP key',
        max_length=100000000,
        required=False,
        help_text="Optionally, if you would like to use PGP encrypted email, please include either your ASCII-armored PGP key or a URL to your key."
    )
    contact_phone = forms.CharField(
        max_length=60, 
        required=False, 
        label='Telephone', 
        validators=[validate_phone_number],
        help_text='The telephone where we may reach you if necessary', 
        widget=forms.TextInput(attrs={'placeholder': '+1 412-268-7090'}))

    share_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want us to share your contact information with vendors?', 
        help_text='We will share contact information with vendors unless otherwise specified.',
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)
    credit_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want to be acknowledged by name in any published document about this vulnerability?', 
        help_text='If we publish a document based on this report, we will credit you unless otherwise specified.',
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)
    coord_status = forms.MultipleChoiceField(
        choices=COORD_STATUS_CHOICES, label="What coordination actions have you taken so far?", 
        help_text="You must select at least one", 
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class' : 'ul_nobullet'}))
    comm_attempt = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Have you contacted the vendor about this vulnerability?',
        required=True,
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}))
    why_no_attempt = forms.ChoiceField(
        choices=WHY_NOT_CHOICES, label="Why have you not contacted the vendor directly?",
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}),
        required=False)
    please_explain = forms.CharField(
        max_length=20000,
        widget=forms.Textarea(attrs={}),
        required=False)

    vendor_name = forms.CharField(
        max_length=100, 
        label="Vendor Name", 
        required=False,
        help_text="The name of the organization or company that develops the affected product.")
    multiplevendors = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label="Do you believe multiple vendors are affected?", 
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)
    other_vendors = forms.CharField(
        max_length=1000, 
        label="Please list the vendors, one vendor per line.", 
        required=False,
        widget=forms.Textarea())

    first_contact = forms.DateField(
        label="Date of First Contact Attempt", 
        input_formats=['%Y-%m-%d'],                                    
        widget=forms.DateInput(attrs={'placeholder':'YYYY-MM-DD'}),
        validators=[validate_not_future_date],
        required=False)

    vendor_communication = forms.CharField(
        max_length=20000, 
        label='Summary of previous vendor communications', 
        widget=forms.Textarea(),
        required=False,
        help_text='What communications have you received from the vendor(s) so far? (max 20,000 chars)')

    product_name = forms.CharField(
        max_length=100, 
        required=True,
        label='What is the name of the affected product or software?', 
        help_text='This field will be used in the subject and/or body of an acknowledgment email from our system to help identify this report with its tracking number. Please DO NOT include any sensitive information in this field. Give the full product name such as "FooBar Router ABC1200" or "FooSoft Office."', 
        widget=forms.TextInput())

    product_version = forms.CharField(
        max_length=100, 
        label='What version number of the product or software is affected?', 
        required=True,
        help_text='Please include the version number you tested, such as 1.2.4, if known; otherwise put "unknown." A version number, firmware version, builder number, or release date is helpful for identifying affected products.', 
        widget=forms.TextInput())

    ics_impact = forms.BooleanField(
        label='Significant ICS/OT impact?',
        required=False)
    
    vul_description = forms.CharField(
        max_length=20000, 
        label='What is the vulnerability?', 
        required=True,
        widget=forms.Textarea(attrs={'rows': 10}),
        help_text='Please describe the vulnerability in sufficient technical detail. Include a proof of concept if possible.  You may describe multiple vulnerabilities here rather than submitting multiple forms, if the vulnerabilities affect the same product. (max 20,000 chars)')
    
    vul_exploit = forms.CharField(
        max_length=20000, 
        label='How does an attacker exploit this vulnerability?',
        help_text='Explain access or other conditions necessary to attack. (max 20,000 chars)',
        widget=forms.Textarea(),
        required=True)
    
    vul_impact = forms.CharField(
        max_length=20000, 
        label='What does an attacker gain by exploiting this vulnerability? (i.e., what is the impact?)',
        help_text='Additional privileges, etc. Please be specific as possible. (max 20,000 chars)',
        widget=forms.Textarea(),
        required=True)
    vul_discovery = forms.CharField(
        max_length=20000, 
        label='How was the vulnerability discovered?',
        help_text='Please note any specific tools or techniques used. (max 20,000 chars)',
        widget=forms.Textarea(),
        required=True)
    vul_public = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label="Is this vulnerability publicly known?",
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)
    public_references = forms.CharField(
        max_length=1000, 
        label="Please provide references (max 1000 chars)", 
        widget=forms.Textarea(attrs={'placeholder': 'URL(s)'}),
        required=False)
    vul_exploited = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Is there evidence that this vulnerability is being actively exploited?', 
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)
    exploit_references = forms.CharField(
        max_length=20000, 
        label="Please provide references", 
        required=False,
        widget=forms.Textarea(attrs={'placeholder': 'URL(s)'}))
    vul_disclose = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you plan to publicly disclose this vulnerability yourself?', 
        required=True,
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}))
    disclosure_plans = forms.CharField(
        max_length=1000, 
        label="What are your public disclosure plans? (max 1000 chars)", 
        widget=forms.Textarea(attrs={'placeholder': 'Include dates and events if applicable'}),
        required=False)
    user_file = RestrictedFileField(
        label='Upload File',
        help_text="You may specify one (1) related file to send us",
        content_types=['application', 'text', 'image', 'video'],
        required=False
        )
#    user_file = forms.FileField(label="You can upload one file limited to 10 MB. Pleave leave a note in the Private comments below if you would like to make alternative arrangements to send files.", widget=forms.ClearableFileInput(attrs={'class':'button'}))

    tracking = forms.CharField(
        max_length=100, 
        label='If you have one or more existing VINCE Tracking IDs for this submission, enter them below. Separate each tracking ID with a comma:', 
        help_text='If you are following up with us regarding an existing VINCE Tracking ID, please enter it here.', 
        required=False, 
        widget=forms.TextInput(attrs={'placeholder': f'{settings.CASE_IDENTIFIER}nnnnnn, etc.'}))
    comments = forms.CharField(
        max_length=20000, 
        label='Any additional comments that will not be shared with vendors:', 
        help_text='Comments in this box will be kept private and will not be included in any publication or shared with vendors.', 
        required=False, 
        widget=forms.Textarea())

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', '')
        super(VulCoordForm, self).__init__(*args,**kwargs)
    
    
    class Meta:
        model = VulCoordRequest
        fields = "__all__"

class ReportForm(forms.Form):
    wordSearch = forms.CharField(max_length=100, label='', widget=forms.TextInput(), required=False)
    limit = forms.ChoiceField(choices=LIMIT_CHOICES)
    sort = forms.ChoiceField(widget=forms.RadioSelect, choices=SORT_CHOICES)
    datestart = forms.DateField(widget = SelectDateWidget(empty_label="nada"))
    dateend = forms.DateField()

    def __init__(self, *args, **kwargs):
        super(ReportForm, self).__init__(*args, **kwargs)
        self.fields['limit'].initial = 3
        self.fields['sort'].initial = 1
        self.fields['datestart'].initial = timezone.now
        self.fields['dateend'].initial = timezone.now
