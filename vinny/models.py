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
from django.db import models, transaction
# Create your models here.
from django.utils.translation import ugettext, gettext_lazy as _
from django.contrib.auth.models import User, Group
from django.conf import settings
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from django_countries.fields import CountryField
from django.contrib.postgres import fields
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth.hashers import make_password
import logging
#from .signals import message_sent
from .utils import cached_attribute
from django.utils.functional import cached_property
from vinny.mailer import send_newmessage_mail
from bigvince.storage_backends import PrivateMediaStorage, SharedMediaStorage
from django.utils.encoding import smart_text
from lib.vince.m2crypto_encrypt_decrypt import ED
import base64
import os
import boto3
import random
import uuid
import re
from django.db.models import Q
import traceback
import mimetypes
from django.dispatch import Signal

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

message_sent = Signal(providing_args=["message", "thread", "reply"])

def random_logo_color():
    return "#"+''.join([random.choice('0123456789ABCDEF') for j in range(6)])

def generate_uuid():
    return uuid.uuid1()

class VinceAPIToken(models.Model):
    """
    The default authorization token model
    """
    key = models.CharField(
        _("Key"),
        max_length=250,
        primary_key=True)
    
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name="auth_token",
        on_delete=models.CASCADE)

    created = models.DateTimeField(
        _("Created"),
        auto_now_add=True)

    class Meta:
        verbose_name = _("Token")
        verbose_name_plural = _("Tokens")

    def save(self, token, *args, **kwargs):
        if not token:
            return None

        self.key = make_password(token, settings.SECRET_KEY)

        return super(VinceAPIToken, self).save(*args, **kwargs)

    def generate_key(self):
        return binascii.hexlify(os.urandom(20)).decode()

    def __str__(self):
        return self.key


class VinceProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                related_name="vinceprofile",
                                on_delete=models.CASCADE)
    org = models.CharField(max_length=250, blank=True, null=True)
    preferred_username = models.CharField(max_length=250, blank=True, null=True)
    country = CountryField(blank=True, null=True, default="US")
    email_verified = models.BooleanField(default=False)
    title = models.CharField(max_length=200, blank=True, null=True)
    logocolor = models.CharField(max_length=10, default=random_logo_color)
    #if we don't know this user, the user must go into pending mode before they can login
    api_key = models.CharField(max_length=256, blank=True, null=True)
    pending = models.BooleanField(default=True)
    ignored = models.BooleanField(default=False)
    service = models.BooleanField(default=False)
    multifactor = models.BooleanField(default=False)
    timezone = models.CharField(default='UTC', max_length=100)
    settings_pickled = models.TextField(
        _('Settings Dictionary'),
        help_text=_('This is a base64-encoded representation of a '
                    'pickled Python dictionary.'
                    'Do not change this field via the admin.'),
        blank=True,
	null=True,
    )
    def _get_username(self):
        if self.preferred_username:
            return self.preferred_username
        else:
            return self.user.get_full_name()

    vince_username = property(_get_username)

    def _get_track_access(self):
        return self.user.groups.filter(name='vincetrack').exists()

    is_track = property(_get_track_access)
    
    def _get_url(self):
        ed = ED(base64.b64encode(settings.SECRET_KEY.encode()))
        euid = ed.encrypt(str(self.user.pk))
        return reverse("vinny:usercard", args=[euid])

    url = property(_get_url)
    
    def _get_logo(self):
        groups = self.user.groups.exclude(groupcontact__isnull=True)
        if len(groups) >= 1:
            logo_groups = groups.exclude(Q(groupcontact__logo='')|Q(groupcontact__logo=None))
            if len(logo_groups) >= 1:
                return logo_groups[0].groupcontact.get_logo()
        return None

    logo = property(_get_logo)

    def _get_vendor_status(self):
        groups = self.user.groups.filter(groupcontact__contact__active=True).exclude(groupcontact__contact__isnull=True)
        if len(groups) >= 1:
            vendor_groups = groups.exclude(groupcontact__contact__vendor_type__in=["Contact", "User"])
            if len(vendor_groups) >= 1:
                return True
        return False

    is_vendor = property(_get_vendor_status)

    def _get_admin_status(self):
        admin = VinceCommGroupAdmin.objects.filter(email__email=self.user.email, contact__active=True, contact__vendor_type__in=["Coordinator", "Vendor"])
        if admin:
            return True
        return False

    is_vendor_admin = property(_get_admin_status)
    
    def __str__(self):
        if self.preferred_username:
            return self.preferred_username
        else:
            return self.user.get_full_name()

    name = property(__str__)
        
    def _first_initial(self):
        if self.preferred_username:
            return self.preferred_username[0]
        elif self.user.get_full_name():
            return self.user.get_full_name()[0]
        else:
            return "?"

    initial = property(_first_initial)
        
    def _get_association(self):
        if self.real_org:
            return self.real_org
        elif self.org:
            return self.org
        else:
            return "VINCE User"

    association = property(_get_association)

    def _get_modified(self):
        # this is just for sorting purposes
        if self.user.last_login:
            return self.user.last_login
        else:
            return timezone.now()

    modified = property(_get_modified)
    
    def _set_settings(self, data):
        # data should always be a Python dictionary.
        try:
            import pickle
        except ImportError:
            import cPickle as pickle
        from base64 import encodebytes as b64encode
        self.settings_pickled = b64encode(pickle.dumps(data)).decode()
    
    def _get_settings(self):
        # return a python dictionary representing the pickled data.
        try:
            import pickle
        except ImportError:
            import cPickle as pickle

        try:
            from base64 import decodebytes as b64decode
            if self.settings_pickled:
                return pickle.loads(b64decode(self.settings_pickled.encode('utf-8')))
            else:
                return {}
        except (pickle.UnpicklingError, AttributeError) as e:
            return {}

    settings = property(_get_settings, _set_settings)

    @property
    @cached_attribute
    def real_org(self):
        groups = self.user.groups.filter(groupcontact__contact__vendor_type="Vendor").exclude(groupcontact__isnull=True)
        my_groups = []
        for ug in groups:
            my_groups.append(ug.groupcontact.contact.vendor_name)
        return ", ".join(my_groups)



"""    
def get_username(self):
    if self.vinceprofile.preferred_username:
        return self.vinceprofile.preferred_username
    else:
        return self.get_full_name()
    
User.add_to_class("__str__", get_username)
"""

class VinceCommContact(models.Model):
    VENDOR_TYPE = (
    ('Contact', 'Contact'),
    ('Vendor', 'Vendor'),
    ('User', 'User'),
    ('Coordinator', 'Coordinator'),
    )

    LOCATION_CHOICES=(
    ('Domestic', 'Domestic'),
    ('International', 'International')
    )

    vendor_id = models.IntegerField()
    vendor_name = models.CharField(max_length=100)
    vendor_type = models.CharField(max_length=50, default="Vendor", choices=VENDOR_TYPE)
    countrycode = CountryField(blank=True, null=True, default="US")
    active = models.BooleanField(default=True)
    location = models.CharField(max_length=15, choices=LOCATION_CHOICES, default="domestic")
    version = models.IntegerField(default=0)
    uuid = models.UUIDField(blank=True, null=True, editable=False)
    
    def __str__(self):
        return self.vendor_name

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('vinny:contact', args=(self.id,))

    def get_emails(self):
        email_contact = VinceCommEmail.objects.filter(contact=self, status=True).values_list('email', flat=True)
        return list(email_contact)

    def get_list_email(self):
        email_list = VinceCommEmail.objects.filter(contact=self, email_list=True, status=True, public=True).exclude(name__icontains='service').first()
        if email_list:
            return email_list.email
        else:
            return ""

    def get_phone_number(self):
        phone = VinceCommPhone.objects.filter(contact=self, public=True).first()
        if phone:
            return phone.phone
        else:
            return ""

class VinceCommPostal(models.Model):
    ADDRESS_TYPE = (
    ('Home', 'Home'),
    ('Work', 'Work'),
    ('Other', 'Other'),
    ('School', 'School'),
    )
    contact = models.ForeignKey(VinceCommContact, on_delete=models.CASCADE)
    country = CountryField(blank=True, null=True, default="US")
    primary = models.BooleanField(default=True)
    address_type = models.CharField(max_length=20, choices=ADDRESS_TYPE, default='Work')
    street = models.CharField(max_length=150)
    street2 = models.CharField(max_length=150, blank=True, null=True)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=40, blank=True, null=True)
    zip_code = models.CharField(max_length=12)
    version = models.IntegerField(default=0)
    public = models.BooleanField(default=False)

    def __str__(self):
        return "%s %s, %s %s" % (self.street, self.city, self.state, self.zip_code)


class VinceCommPhone(models.Model):
    PHONE_TYPE = (
    ('Fax', 'Fax'),
    ('Home', 'Home'),
    ('Hotline', 'Hotline'),
    ('Office', 'Office'),
    ('Mobile', 'Mobile'),
    )
    contact = models.ForeignKey(VinceCommContact, on_delete=models.CASCADE)
    country_code = models.CharField(max_length=5, default="+1")
    phone = models.CharField(max_length=50)
    phone_type = models.CharField(max_length=20, choices=PHONE_TYPE, default='Work')
    comment = models.CharField(max_length=200, blank=True, null=True)
    version = models.IntegerField(default=0)
    public = models.BooleanField(default=False)

    def __str__(self):
        return "%s %s" % (country_code, phone)

class VinceCommEmail(models.Model):
    EMAIL_FUNCTION=(
    ('TO', 'TO'),
    ('CC', 'CC'),
    ('EMAIL', 'EMAIL'),
    ('REPLYTO', 'REPLYTO')
    )
    EMAIL_TYPE = (
    ('Work', 'Work'),
    ('Other', 'Other'),
    ('Home', 'Home'),
    ('School', 'School')
    )
    contact = models.ForeignKey(VinceCommContact, on_delete=models.CASCADE)
    email = models.EmailField(max_length=254)
    email_type = models.CharField(max_length=20, choices=EMAIL_TYPE, default='Work')
    name = models.CharField(max_length=200, blank=True, null=True)
    email_function = models.CharField(max_length=10, choices=EMAIL_FUNCTION, default='TO')
    status = models.BooleanField(default=True)
    version = models.IntegerField(default=0)
    invited = models.BooleanField(default=False)
    public = models.BooleanField(default=False)
    email_list = models.BooleanField(default=True)
    
    def __str__(self):
        return self.email


class VinceCommWebsite(models.Model):
    contact = models.ForeignKey(VinceCommContact, on_delete=models.CASCADE)
    url = models.URLField()
    description = models.CharField(max_length=100, blank=True, null=True)
    version = models.IntegerField(default=0)
    public = models.BooleanField(default=False)

    def __str__(self):
        return self.url

class VinceCommPgP(models.Model):
    contact = models.ForeignKey(VinceCommContact, on_delete=models.CASCADE)
    pgp_key_id = models.CharField(max_length=200)
    pgp_fingerprint = models.CharField(max_length=200, blank=True, null=True)
    pgp_version = models.IntegerField(blank=True, null=True)
    pgp_key_data = models.TextField(blank=True, null=True)
    revoked = models.BooleanField(default=False)
    startdate = models.CharField(max_length=12, blank=True, null=True)
    enddate = models.CharField(max_length=12, blank=True, null=True)
    pgp_protocol = models.CharField(max_length=30, default="GPG1 ARMOR MIME")
    version = models.IntegerField(default=0)
    public = models.BooleanField(default=False)
    pgp_email = models.EmailField(max_length=254,
                                  help_text=_('The email address that belongs with this PGP key'),
                                  blank=True, null=True)

    def __str__(self):
        return self.pgp_fingerprint


class ContactInfoChange(models.Model):
    contact = models.ForeignKey(
        VinceCommContact,
        on_delete=models.CASCADE
    )
    model = models.CharField(
        _('Model'), max_length=100
    )
    field = models.CharField(
        _('Field'), max_length=100
    )
    old_value = models.TextField(
        _('Old Value'),
        blank=True,
        null=True
    )
    new_value = models.TextField(
        _('New Value'),
        blank=True,
        null=True
    )
    
    action = models.ForeignKey(
        "VendorAction",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_('Vendor Action'),
    )
    approved = models.BooleanField(
        default=False)
    
    def _get_ts(self):
        if self.action:
            return self.action.created
        else:
            return timezone.now()

    action_ts = property(_get_ts)
    
    def __str__(self):
        out = '%s: %s: %s ' % (self.action, self.model, self.field)
        if not self.new_value:
#            out += ugettext('removed')
            out += '%s' % self.old_value
        elif not self.old_value:
            out += _('added %s') % self.new_value
        else:
            out += _('changed from "%(old_value)s" to "%(new_value)s"') % {
                'old_value': self.old_value,
                'new_value': self.new_value
            }
        return out
    def __repr__(self):
        return self.__str__()

    
class GroupContact(models.Model):
    group = models.OneToOneField(
        Group,
        on_delete=models.CASCADE)

    contact = models.ForeignKey(
        VinceCommContact,
        on_delete=models.CASCADE,
        blank=True,
        null=True)

    default_access = models.BooleanField(
        default=True,
        help_text="If true, grant case access to users in group by default")
    
    logo = models.FileField(
        storage=SharedMediaStorage(location="vince_logos"),
        blank=True,
        null=True)

    logocolor = models.CharField(
        max_length=10,
        default=random_logo_color)

    vincetrack = models.BooleanField(
        default=False,
        help_text="Is this a vincetrack group?"
    )

    def _get_url(self):
        ed = ED(base64.b64encode(settings.SECRET_KEY.encode()))
        egid = ed.encrypt(str(self.group.pk))
        return reverse("vinny:groupcard", args=[egid])

    url = property(_get_url)
    
    def get_logo(self):
        if self.logo:
            return self.logo.url
        else:
            return None

    def get_logo_name(self):
        if self.logo:
            return self.logo.name
        else:
            return None

    def get_public_emails(self):
        return VinceCommEmail.objects.filter(contact=self.contact, public=True)

    def get_public_keys(self):
        return VinceCommPgP.objects.filter(contact=self.contact, public=True, revoked=False)

    def get_public_postal(self):
        return VinceCommPostal.objects.filter(contact=self.contact, public=True)

    def get_public_phone(self):
        return VinceCommPhone.objects.filter(contact=self.contact, public=True)

    def get_public_site(self):
        return VinceCommWebsite.objects.filter(contact=self.contact, public=True)

    def get_vince_users(self):
        return User.objects.filter(groups=self.group, is_active=True).exclude(vinceprofile__service=True)


class CoordinatorSettings(models.Model):
    group = models.OneToOneField(
        Group,
        on_delete=models.CASCADE)

    team_signature = models.TextField(
        blank=True,
        null=True,
        help_text=_('Email signature for automatic case messages sent by VINCE to case participants'),
    )

    team_email = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text=_('Email address to use for outgoing email. If not set, uses DEFAULT_REPLY_EMAIL in settings'),
    )

    disclosure_link = models.URLField(
        blank=True,
        null=True,
        help_text=_("Link to disclosure guidance that will be presented to case members at first view of case")
    )
    
    
class VinceCommGroupAdmin(models.Model):
    contact = models.ForeignKey(VinceCommContact,
                                on_delete=models.CASCADE)

    email = models.ForeignKey(VinceCommEmail,
                              on_delete=models.CASCADE)

    comm_action = models.BooleanField(
        default = False,
        help_text = "If true, group admin was created by another group admin"
    )

    def __str__(self):
        return "%s" % self.email.email



def get_uuid_filename(self, filename):

    name = str(self.uuid)

    return name
    
class VinceAttachment(models.Model):
    file = models.FileField(
        _('File'),
        storage=SharedMediaStorage(),
        upload_to=get_uuid_filename,
        max_length=1000,
    )

    filename = models.CharField(
        _('Filename'),
        max_length=1000,
    )

    mime_type = models.CharField(
        _('MIME Type'),
        max_length=255,
    )

    size = models.IntegerField(
        _('Size'),
        help_text=_('Size of this file in bytes'),
    )

    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True)

    uploaded_time = models.DateTimeField(
        default=timezone.now)

    def __str__(self):
        return '%s' % self.filename

    def _get_access_url(self):
        url = self.file.storage.url(self.file.name, parameters={'ResponseContentDisposition': f'attachment; filename="{self.filename}"'}, expire=10)
        return url
    
    access_url = property(_get_access_url)

    class Meta:
        ordering = ('filename',)
        verbose_name = _('Vince Attachment')
        verbose_name_plural = _('Vince Attachments')


class VinceTrackAttachment(models.Model):
    file = models.ForeignKey(
        VinceAttachment,
	on_delete=models.CASCADE)

    case = models.ForeignKey(
	"Case",
        blank=True,
        null=True,
        on_delete=models.SET_NULL)

    vulnote = models.BooleanField(
        default = False)

    shared = models.BooleanField(
        default = False)
    
        
class VinceCommInvitedUsers(models.Model):
    email = models.CharField(
        max_length=200)
    
    case = models.ForeignKey(
        "Case",
        on_delete=models.CASCADE)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        help_text=_('The user that invited this user.'),
        on_delete=models.SET_NULL)

    coordinator = models.BooleanField(
        default = False)

    # the id of the CaseParticipant in VINCE 
    vince_id = models.IntegerField(
        default=0)
    
    def __str__(self):
        return "%s" % self.email


def update_filename(instance, filename):
    if instance.vrf_id:
        new_filename = "vrf%s_%s" % (instance.vrf_id, filename)
    else:
        new_filename= "novrf_%s" % filename

    return new_filename
    

class VTCaseRequest(models.Model):
    """                                                                                       
    A Case Request is a request for VINCE vulnerability coordination that
    has either been manually created by a coordinator or has come from
    the Vulnerability Reporting Form (VRF).
                                                                                              
    A Case Request will eventually (but not always) become a Vulnerability
    Case if selected by the Vuln Coordination Team.                                     
    """
    PENDING_STATUS = 0
    OPEN_STATUS = 1
    REOPENED_STATUS = 2
    RESOLVED_STATUS = 3
    CLOSED_STATUS = 4
    DUPLICATE_STATUS = 5

    STATUS_CHOICES = (
        (PENDING_STATUS, _('Pending')),
        (OPEN_STATUS, _('Open')),
        (REOPENED_STATUS, _('Reopened')),
        (RESOLVED_STATUS, _('Resolved')),
        (CLOSED_STATUS, _('Closed')),
        (DUPLICATE_STATUS, _('Duplicate')),
    )

    WHY_NOT_CHOICES = [('1', 'I have not attempted to contact any vendors'),
                       ('2', 'I have been unable to find contact information for a vendor'),
                       ('3', 'Other')]
    
    vrf_id = models.CharField(max_length=20)
    contact_name = models.CharField(max_length=100, blank=True, null=True)
    contact_org = models.CharField(max_length=100, blank=True, null=True)
    contact_email = models.EmailField(max_length=254, blank=True, null=True)
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    share_release = models.BooleanField(default=True)
    credit_release = models.BooleanField(default=True)
    comm_attempt = models.BooleanField(blank=True, null=True)
    why_no_attempt = models.CharField(max_length=100, blank=True, null=True, choices=WHY_NOT_CHOICES)
    please_explain = models.TextField(blank=True, null=True)
    vendor_name = models.CharField(max_length=100, blank=True, null=True)
    multiplevendors = models.BooleanField(default=False)
    other_vendors = models.TextField(blank=True, null=True)
    first_contact = models.DateTimeField(blank=True, null=True)
    vendor_communication = models.TextField(blank=True, null=True)
    product_name = models.CharField(max_length=500)
    product_version = models.CharField(max_length=100, blank=True, null=True)
    ics_impact = models.BooleanField(default=False)
    vul_description = models.TextField(blank=True, null=True)
    vul_exploit = models.TextField(blank=True, null=True)
    vul_impact = models.TextField(blank=True, null=True)
    vul_discovery = models.TextField(blank=True, null=True)
    vul_public = models.BooleanField(default=False)
    public_references = models.CharField(max_length=1000, blank=True, null=True)
    vul_exploited = models.BooleanField(default=False)
    exploit_references = models.CharField(max_length=1000, blank=True, null=True)
    vul_disclose = models.BooleanField(default=False)
    disclosure_plans = models.CharField(max_length=1000, blank=True, null=True)
    user_file = models.FileField(blank=True, null=True,
                                 storage=PrivateMediaStorage(),
                                 upload_to=update_filename)
    date_submitted = models.DateTimeField(default=timezone.now)
    tracking = models.CharField(max_length=100,blank=True, null=True)
    status = models.IntegerField(
        _('Status'),
        choices=STATUS_CHOICES,
	default=PENDING_STATUS,
    )

    comments = models.TextField(blank=True, null=True)

    search_vector = SearchVectorField(null=True)

    new_vuid = models.CharField(
        max_length=20,
        blank=True,
        null=True)
    
    coordinator = models.ForeignKey(
        Group,
        blank=True,
        null=True,
        help_text=_('The group assigned to this report.'),
        on_delete=models.SET_NULL)
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        help_text=_('The user that submitted the report.'),
        on_delete=models.SET_NULL)

    class Meta:
        indexes = [ GinIndex(
            fields = ['search_vector'],
            name = 'vc_caserequest_gin',
            )
	]

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('vinny:cr', args=(self.id,))

    def _get_modified(self):
        return self.date_submitted

    modified = property(_get_modified)
    
    def __str__(self):
        return self.vrf_id

    def get_title(self):
        if self.new_vuid:
            return f"{settings.CASE_IDENTIFIER}{self.new_vuid}: {self.product_name}"
        return f"{settings.REPORT_IDENTIFIER}{self.vrf_id}: {self.product_name}"

    def _get_status(self):
        """
        Displays the ticket status, with an "On Hold" message if needed.
        """
        return u'%s' % (self.get_status_display())

    get_status = property(_get_status)

    def _get_status_html(self):
        if self.status == self.OPEN_STATUS:
            return f"<span class=\"label badge-tag-success\">{self.get_status_display()}</span>"
        elif self.status == self.PENDING_STATUS:
            return f"<span class=\"label badge-tag-primary\">{self.get_status_display()}</span>"
        elif self.status == self.CLOSED_STATUS:
            return f"<span class=\"label badge-tag-info\">{self.get_status_display()}</span>"
        else:
            return f"<span class=\"label badge-tag-primary\">{self.get_status_display()}</span>"

    get_status_html = property(_get_status_html)
    
class CRFollowUp(models.Model):
    cr = models.ForeignKey(
        VTCaseRequest,
        on_delete = models.CASCADE,
        verbose_name=_('Case Request'),
    )

    date = models.DateTimeField(
        _('Date'),
        default=timezone.now
    )
    
    last_edit = models.DateTimeField(
        _('Last Modified Date'),
        blank=True,
        null=True)

    title = models.CharField(
        _('Title'),
        max_length=200,
        blank=True,
        null=True,
    )
    
    comment = models.TextField(
        _('Comment'),
        blank=True,
        null=True,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_('User'),
    )

    new_status = models.IntegerField(
        _('New Status'),
        choices=VTCaseRequest.STATUS_CHOICES,
        blank=True,
        null=True,
        help_text=_('If the status was changed, what was it changed to?'),
    )

    def __str__(self):
        return '%s' % self.title

class ReportAttachment(models.Model):
        
    action = models.ForeignKey(
        CRFollowUp,
        on_delete=models.CASCADE,
        verbose_name=_('Vendor Action'),
        blank=True,
        null=True
    )

    file = models.ForeignKey(
        VinceAttachment,
        on_delete=models.CASCADE,
        blank=True,
        null=True)
    
    attachment = models.FileField(
        storage=PrivateMediaStorage(),
        blank=True,
        null=True)

    vince_id = models.IntegerField(
        default = 0
    )
    

class Case(models.Model):
    ACTIVE_STATUS = 1
    INACTIVE_STATUS = 2

    STATUS_CHOICES = (
        (ACTIVE_STATUS, _('Active')),
        (INACTIVE_STATUS, _('Inactive')),
    )
    vuid = models.CharField(
        max_length=20
    )
    created = models.DateTimeField(
        auto_now_add=True
    )
    modified = models.DateTimeField(
        auto_now=True
    )
    status = models.IntegerField(
        _('Status'),
        choices=STATUS_CHOICES,
        default=ACTIVE_STATUS,
    )
    summary = models.CharField(
        max_length=1000,
        help_text=_('A summary of the case.'),
    )
    title = models.CharField(
        max_length=500,
        help_text=_('A title for this case. Optional.')
    )
        
    due_date = models.DateTimeField(
        blank=True, null=True
    )

    publicdate = models.DateTimeField(
        blank=True, null=True
    )

    publicurl =	models.CharField(
	max_length=500,	blank=True, null=True,
        help_text=_('The URL for the public notice of a vulnerability.')
    )
    
    vince_id = models.IntegerField(
        default=0
    )
    
    cr = models.OneToOneField(
        VTCaseRequest,
        blank=True, null=True,
        on_delete=models.SET_NULL
    )

    team_owner = models.ForeignKey(
	Group,
        blank=True, null=True,
        help_text=_('The coordinator group that is leading this case'),
	on_delete=models.SET_NULL)
    
    note = models.OneToOneField(
        "VCVUReport",
        on_delete=models.SET_NULL,
        blank=True, null=True)

    uid = models.CharField(
        max_length=50,
        default=generate_uuid)

    search_vector = SearchVectorField(null=True)

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('vinny:case', args=(self.id,))
    
    class Meta:
        indexes = [ GinIndex(
            fields = ['search_vector'],
            name = 'vc_case_gin',
            )
        ]

    def __str__(self):
        return self.vuid
        
    def get_title(self):
        return "%s%s: %s" % (settings.CASE_IDENTIFIER, self.vuid, self.title)

    def get_vuid(self):
        return f"{settings.CASE_IDENTIFIER}%s" % self.vuid

    vu_vuid = property(get_vuid)
    
    def _get_status(self):
        """
        Displays the ticket status, with an "On Hold" message if needed.
        """
        held_msg=""
        return u'%s%s' % (self.get_status_display(), held_msg)

    get_status = property(_get_status)

    def _get_case_for_url(self):
        """ A URL-friendly ticket ID, used in links. """
        return u"VU%s" % (self.vuid)

    case_for_url = property(_get_case_for_url)

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('vinny:case', args=(self.id,))
    
    def _is_published(self):
        try:
            if self.note.datefirstpublished:
                return True
        except:
            pass
        return False

    published = property(_is_published)

    def _get_status_html(self):
        return_str = ""
        if self.status == self.ACTIVE_STATUS:
            return_str = f"<span class=\"label success\">{self.get_status_display()}</span>"
        else:
            return_str = f"<span class=\"label info\">{self.get_status_display()}</span>" 
        if self.published:
            # published assumed public
            return_str = return_str +  f"  <span class=\"label badge-tag-success\">Public</span>"
        elif self.publicdate:
            return_str = return_str +  f"  <span class=\"label badge-tag-success\">Public</span>"
        return return_str

    get_status_html = property(_get_status_html)

class VinceCommCaseAttachment(models.Model):
    action = models.ForeignKey(
        "VendorAction",
        on_delete=models.CASCADE,
        verbose_name=_('Vendor Action'),
        blank=True,
        null=True
    )

    file = models.ForeignKey(
        VinceAttachment,
        on_delete=models.CASCADE,
	blank=True,
        null=True)
    
    attachment = models.FileField(
        storage=PrivateMediaStorage(),
        blank=True,
        null=True)

    vince_id = models.IntegerField(
        default = 0
    )

class CaseVulnerabilityManager(models.Manager):

    def get_queryset(self):
        return super(CaseVulnerabilityManager, self).get_queryset().filter(deleted=False)
    
class CaseVulnerability(models.Model):
    cve = models.CharField(
	_('CVE'),
	max_length=50,
        blank=True,
        null=True)

    description = models.TextField(
        _('Description'))
    
    case = models.ForeignKey(
        Case,
	on_delete=models.CASCADE)

    date_added = models.DateTimeField(
        default=timezone.now)

    vince_id = models.IntegerField(
        blank=True, null=True,
        help_text=_('The vince pk'),
    )

    deleted = models.BooleanField(
        default = False,
        help_text=_('Only True if vulnerability is removed after publication')
    )

    case_increment = models.IntegerField(
        default = 0)
    
    ask_vendor_status = models.BooleanField(
        default=False)

    objects = CaseVulnerabilityManager()
    
    def __str__(self):
        return "%s" % self.description

    def _get_vul(self):
        """ A user-friendly Vul ID, which is the cve if cve exists,
        otherwise it's a combination of vul ID and case. """
        if (self.cve):
            return u"CVE-%s" % self.cve
        else:
            return u"%s" % self.cert_id

    vul = property(_get_vul)

    def _get_vul_for_url(self):
        """ A URL-friendly vul ID, used in links. """
        return u"%s-%s" % (self.case.case_for_url, self.vince_id)

    vul_for_url = property(_get_vul_for_url)

    def	_get_cert_id(self):
        return u"%s%s.%d" % (settings.CASE_IDENTIFIER, self.case.vuid, self.case_increment)

    cert_id = property(_get_cert_id)

    def as_dict(self):
        exploits = CaseVulExploit.objects.filter(vul=self).count()
        link = reverse("vinny:vuldetail", args=(self.id,))
        editstatus = reverse('vinny:status', args=(self.case.id,))
        return {
            'id': self.id,
            'cert_id': self.cert_id,
            'ask_vendor_status': self.ask_vendor_status,
            'description': self.description,
            'cve': self.vul,
            'exploits': exploits,
            'vuldetaillink': link,
            'editstatus': editstatus,
            'date_added': self.date_added.strftime('%Y-%m-%d'),
	}


class CaseVulCVSS(models.Model):

    vul = models.ForeignKey(
        CaseVulnerability,
        on_delete=models.CASCADE)

    last_modified = models.DateTimeField(
	_('Last Modified Date'),
        default=timezone.now)

    vector = models.CharField(
        _('CVSS Vector String'),
        max_length=100,
	blank=True,
	null=True)

    score = models.DecimalField(
        _('CVSS Base Score'),
        max_digits=3,
        decimal_places=1,
        blank=True,
        null=True)

    severity = models.CharField(
	_('CVSS Severity'),
        max_length=20,
        blank=True,
        null=True)

    def __str__(self):
        return self.vector
    
    
class CaseVulExploit(models.Model):

    EXPLOIT_CHOICES = (('code', 'code'),
                       ('report', 'report'),
                       ('other', 'other')
                       )

    vul = models.ForeignKey(
        CaseVulnerability,
        on_delete=models.CASCADE)

    date_added = models.DateTimeField(
        default=timezone.now)

    reference_date = models.DateTimeField(
        blank=True,
        null=True)

    link = models.URLField()

    reference_type = models.CharField(
        max_length=30,
        choices=EXPLOIT_CHOICES,
        default='code')

    notes = models.TextField(blank=True,
                             null=True)

    vince_id = models.IntegerField(
        blank=True, null=True,
        help_text=_('The vince exploit pk'),
    )

    def __str__(self):
        return "%s" % self.link
    
class CaseMember(models.Model):
    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE)

    group = models.ForeignKey(
        Group,
        blank=True, null=True,
        on_delete=models.CASCADE)

    participant = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True, null=True,
        help_text=_('A participant in the case'),
        related_name='participant',
        on_delete = models.CASCADE)

    added = models.DateTimeField(
        default=timezone.now)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        help_text=_('The user that added the vendor.'),
        on_delete=models.SET_NULL)

    seen = models.BooleanField(
        default=False)

    coordinator = models.BooleanField(
        default = False)

    reporter_group = models.BooleanField(
        default = False)
    
    # the id of the CaseParticipant in VINCE
    vince_id = models.IntegerField(
        default=0)

    def __str__(self):
        if self.participant:
            return f"{self.participant} for case {self.case.vu_vuid}"
        elif self.group:
            try:
                return f"{self.group.groupcontact.contact.vendor_name} for case {self.case.vu_vuid}"
            except:
                return f"{self.group.name} for case {self.case.vu_vuid}"
        else:
            return f"Case Member for {self.case.vu_vuid}"    
    
    def share_status(self):
        status = CaseStatement.objects.filter(member=self).first()
        if status:
            return status.share
        else:
            return False
    
    def get_general_status(self):
        status = CaseMemberStatus.objects.filter(member=self)
        stat = 3
        for x in status:
            if x.status == 1:
                stat = 1
                break
            if x.status == 2:
                stat = 2
        return stat
            
    def get_statement(self):
        stmt = CaseStatement.objects.filter(member=self, statement__isnull=False)
        if stmt:
            return stmt
        else:
            return CaseMemberStatus.objects.filter(member=self, statement__isnull=False)
    
    class Meta:
        unique_together = (('group', 'case', 'participant'),)


class CaseMemberStatusManager(models.Manager):

    def get_queryset(self):
        return super(CaseMemberStatusManager, self).get_queryset().exclude(vulnerability__deleted=True)
        
class CaseMemberStatus(models.Model):
    AFFECTED = 1
    UNAFFECTED = 2
    UNKNOWN = 3

    STATUS_CHOICES = (
        (UNAFFECTED, _('Not Affected')),
	(AFFECTED, _('Affected')),
        (UNKNOWN, _('Unknown')),
    )
    member = models.ForeignKey(
        CaseMember,
        on_delete=models.CASCADE)

    vulnerability = models.ForeignKey(
        CaseVulnerability,
        on_delete=models.CASCADE)

    status = models.IntegerField(
	_('Status'),
        choices=STATUS_CHOICES,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        help_text=_('The user that committed status.'),
        on_delete=models.SET_NULL)

    references = models.TextField(
        blank=True,
        null=True)

    statement = models.TextField(
        blank=True,
        null=True)

    date_added = models.DateTimeField(
        default=timezone.now)

    date_modified = models.DateTimeField(
        auto_now=True
    )

    approved = models.BooleanField(
        default=False
    )

    objects = CaseMemberStatusManager()
    
    class Meta:
        unique_together = (('member', 'vulnerability'),)

class CaseStatement(models.Model):
    ### This is a general statement on a case vs a statement on a vul ###

    case = models.ForeignKey(
        Case,
        help_text=('The case this post belongs to'),
        on_delete=models.CASCADE,
    )

    member = models.ForeignKey(
        CaseMember,
        on_delete=models.CASCADE)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
	help_text=_('The user that provided statement.'),
        on_delete=models.SET_NULL)

    references = models.TextField(
        blank=True,
        null=True)

    statement = models.TextField(
        blank=True,
        null=True)

    addendum = models.TextField(
        blank=True,
        null=True)

    share = models.BooleanField(
        default=False)
    
    date_added = models.DateTimeField(
        default=timezone.now)

    date_modified = models.DateTimeField(
        auto_now=True
    )

    approved = models.BooleanField(
        default=False)

    def __str__(self):
        return self.statement
    
    class Meta:
        unique_together = (('case', 'member'),)

        
""" Adapted from Misago
https://github.com/rafalp/Misago
"""
class PostManager(models.Manager):
    def search(self, case=None, query=None, author_list=[]):
        qs = self.get_queryset()
        if case is not None:
            qs = qs.filter(case=case)
        if author_list is not None:
            qs = qs.filter(author__in=author_list)
        if query is not None:
            qs = qs.filter(current_revision__content__search=query)
        return qs


class Post(models.Model):
    current_revision = models.OneToOneField(
        'PostRevision',
        blank=True,
        null=True,
        on_delete=models.CASCADE,
        related_name='current_set',
        help_text=_('The revision displayed for this post.  If you need to rollback, change value of this field.'))

    case = models.ForeignKey(
        Case,
        help_text=('The case this post belongs to'),
        on_delete=models.CASCADE,
    )

    created = models.DateTimeField(
        auto_now_add=True
    )

    modified = models.DateTimeField(
        auto_now=True
    )

    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True, null=True,
	help_text=_('The writer of this post.'),
        on_delete=models.SET_NULL)

    group = models.ForeignKey(
        Group,
        blank=True, null=True,
        help_text=_('The group of the user'),
        on_delete=models.SET_NULL
    )

    vince_id = models.IntegerField(
        blank=True, null=True,
        help_text=_('The vince pk'),
    )

    pinned = models.BooleanField(
        default=False,
        help_text=_('A pinned post is pinned to the top of the page.'),
    )

    deleted = models.BooleanField(
        default=False
    )
    
    objects = PostManager()

    def add_revision(self, new_revision, save=True):
        """
        Sets the properties of a revision and ensures its the current
        revision.
        """
        assert self.id or save, (
            'Article.add_revision: Sorry, you cannot add a'
            'revision to an article that has not been saved '
            'without using save=True')
        if not self.id:
            self.save()
        revisions = self.postrevision_set.all()
        try:
            new_revision.revision_number = revisions.latest().revision_number + 1
        except PostRevision.DoesNotExist:
            new_revision.revision_number = 0
        new_revision.post = self
        new_revision.previous_revision = self.current_revision
        if save:
            new_revision.clean()
            new_revision.save()
        self.current_revision = new_revision
        if save:
            self.save()
            
    def __str__(self):
        if self.current_revision:
            return str(self.current_revision.revision_number)
        obj_name = _('Post without content (%d)') % (self.id)
        return str(obj_name)

    def get_org_name(self):
        if self.group:
            try:
                if self.group.groupcontact:
                    vendor_name = self.group.groupcontact.contact.vendor_name
                    # is this user still a member of that vendor?
                    if self.author:
                        if self.author.groups.filter(id=self.group.id).exists():
                            return vendor_name
                    return f"{vendor_name} (Inactive User)"
            except:
                return "VINCE User"
        elif self.author:
            # how is this author a part of this case?
            cm = CaseMember.objects.filter(group__in=self.author.groups.all(), case=self.case).first()
            if cm:
                if cm.group.name == self.case.vuid:
                    if cm.coordinator:
                        return "Coordinator"
                    else:
                        return "Reporter"
                if cm.group.groupcontact:
                    return cm.group.groupcontact.contact.vendor_name
            else:
                return "(Removed from case)"

        return "Removed"

    def get_org_logo(self):
        print(self.author)
        if self.group:
            return self.group.groupcontact.get_logo()
        elif self.author:
            # how is this author a part of this case?
            print(self.author.groups.all())
            cm = CaseMember.objects.filter(group__in=self.author.groups.all(), case=self.case).first()
            if cm:
                return cm.group.groupcontact.get_logo()
            else:
                print("got random")
                return self.author.vinceprofile.get_logo()
        else:
            return None
    
    def get_post_count(self):
        numposts = Post.objects.filter(author=self.author).count()
        if numposts == 1:
            return "First post"
        else:
            return "%d posts" % numposts

    def _get_vc(self):
        return True

    vc = property(_get_vc)

    def _get_user(self):
        return self.author

    user = property(_get_user)

    @property
    @cached_attribute
    def replies(self):
        return self.children.order_by("created")

    @property
    @cached_attribute
    def num_replies(self):
        return self.children.count()

class ThreadedPost(Post):
    parent = models.ForeignKey(
        Post,
        null=True, blank=True,
        on_delete=models.CASCADE,
        default=None,
        related_name="children",
        verbose_name=_('Parent'))

    newest_activity = models.DateTimeField(null=True)

    objects = PostManager()

    class Meta(object):
        verbose_name = _('Threaded post')
        verbose_name_plural = _('Threaded posts')
    
class BaseRevisionMixin(models.Model):

    """This is an abstract model used as a mixin: Do not override any of the
    core model methods but respect the inheritor's freedom to do so itself."""

    revision_number = models.IntegerField(
        editable=False,
        verbose_name=_('revision number'))

    user_message = models.TextField(
        blank=True,
    )

    automatic_log = models.TextField(
        blank=True,
        editable=False,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_('user'),
        blank=True, null=True,
        on_delete=models.SET_NULL)

    modified = models.DateTimeField(
        auto_now=True)

    created = models.DateTimeField(
        auto_now_add=True)

    previous_revision = models.ForeignKey(
        'self',
        blank=True, null=True,
        on_delete=models.SET_NULL
    )

    deleted = models.BooleanField(
        verbose_name=_('deleted'),
        default=False,
    )

    locked = models.BooleanField(
        verbose_name=_('locked'),
        default=False,
    )

    def inherit_predecessor(self, predecessor):
        """
        This is a naive way of inheriting, assuming that ``predecessor`` is in
        fact the predecessor and there hasn't been any intermediate changes!
        :param: predecessor is an instance of whatever object for which
        object.current_revision implements BaseRevisionMixin.
        """
        predecessor = predecessor.current_revision
        self.previous_revision = predecessor
        self.deleted = predecessor.deleted
        self.locked = predecessor.locked
        self.revision_number = predecessor.revision_number + 1


    def set_from_request(self, request):
        if request.user.is_authenticated:
            self.user = request.user

    class Meta:
        abstract = True


class PostRevision(BaseRevisionMixin,  models.Model):
    """This is where main revision data is stored. To make it easier to
    copy, NEVER create m2m relationships."""

    post = models.ForeignKey(
        Post,
        on_delete=models.CASCADE,
        verbose_name=_('Post'))

    # This is where the content goes, with whatever markup language is used
    content = models.TextField(
        blank=True,
        verbose_name=_('vulnote contents'))

    search_vector = SearchVectorField(null=True)
    
    def __str__(self):
        if self.revision_number:
            return "(%d)" % self.revision_number
        else:
            return "OG Post"

    def clean(self):
        # Enforce DOS line endings \r\n. It is the standard for web browsers,
        # but when revisions are created programatically, they might
        # have UNIX line endings \n instead.
        logger.debug(self.content)
        self.content = self.content.replace('\r', '').replace('\n', '\r\n')

    def inherit_predecessor(self, post):
        """
        Inherit certain properties from predecessor because it's very
        convenient. Remember to always call this method before
        setting properties :)"""

        predecessor = post.current_revision
        self.post = predecessor.post
        self.content = predecessor.content
#        self.title = predecessor.title
        self.deleted = predecessor.deleted
        self.locked = predecessor.locked

    class Meta:
        get_latest_by = 'revision_number'
        ordering = ('created',)
        unique_together = ('post', 'revision_number')
        indexes = [ GinIndex(
            fields = ['search_vector'],
            name = 'post_gin',
            )
        ]


# Adapted from Pinax-messages Project
class Thread(models.Model):

    subject = models.CharField(
        max_length=150)

    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="UserThread")

    case = models.ForeignKey(
        Case,
        blank=True, null=True,
        on_delete=models.CASCADE)

    to_group = models.CharField(
        max_length=250,
        blank = True,
        null = True
    )

    from_group = models.CharField(
        max_length=150,
        blank = True,
        null = True
    )

    groupchat = models.BooleanField(
        default=False)

    @classmethod
    def none(cls):
        return cls.objects.none()

    @classmethod
    def all(cls, user):
        return cls.objects.filter(userthread__user=user)

    @classmethod
    def inbox(cls, user):
        return cls.objects.filter(userthread__user=user, userthread__deleted=False).distinct()

    @classmethod
    def deleted(cls, user):
        return cls.objects.filter(userthread__user=user, userthread__deleted=True).distinct()

    @classmethod
    def read(cls, user):
        return cls.objects.filter(userthread__user=user, userthread__deleted=False, userthread__unread=False).distinct()

    @classmethod
    def unread(cls, user):
        return cls.objects.filter(userthread__user=user, userthread__deleted=False, userthread__unread=True).distinct()

    def __str__(self):
        return "{}: {}".format(
            self.subject,
            ", ".join([str(user) for user in self.users.all()])
        )

    def get_absolute_url(self):
        return reverse("vinny:thread_detail", args=[self.pk])

    @property
    @cached_attribute
    def first_message(self):
        return self.messages.all()[0]

    @property
    @cached_attribute
    def latest_message(self):
        return self.messages.order_by("-created").first()

    @property
    @cached_attribute
    def number_attachments(self):
        return MessageAttachment.objects.filter(message__in=self.messages.all()).count()

    @property
    @cached_attribute
    def num_messages(self):
        return len(self.messages.all())
    
    @classmethod
    def ordered(cls, objs):
        """
        Returns the iterable ordered the correct way, this is a class method
        because we don"t know what the type of the iterable will be.
        """
        objs = list(objs)
        try:
            objs.sort(key=lambda o: o.latest_message.created, reverse=True)
        except:
            pass
        return objs

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('vinny:thread_detail', args=(self.id,))


class UserThread(models.Model):

    thread = models.ForeignKey(
        Thread,
        on_delete=models.CASCADE)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE)

    unread = models.BooleanField()

    deleted = models.BooleanField()

class MessageManager(models.Manager):
    def search(self, case=None, query=None, author_list=None):
        qs = self.get_queryset()
        if case is not None:
            qs = qs.filter(thread__case=case)
        if author_list is not None:
            qs = qs.filter(sender__in=author_list)
        if query is not None:
            qs = qs.filter(content__search=query)
            
        return qs
    
class Message(models.Model):

    thread = models.ForeignKey(
        Thread,
        related_name="messages",
        on_delete=models.CASCADE)

    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="sent_messages",
        on_delete=models.CASCADE)

    created = models.DateTimeField(
        default=timezone.now)

    content = models.TextField(blank=True, null=True)

    objects = MessageManager()
    
    @classmethod
    def new_reply(cls, thread, user, content):
        """
        Create a new reply for an existing Thread.
        Mark thread as unread for all other participants, and
        mark thread as read by replier.
        """
        msg = cls.objects.create(thread=thread, sender=user, content=content)
        thread.userthread_set.exclude(user=user).update(deleted=False, unread=True)
        thread.userthread_set.filter(user=user).update(deleted=False, unread=False)
        message_sent.send(sender=cls, message=msg, thread=thread, reply=True)
        #for recip in thread.userthread_set.exclude(user=user):
        #    send_newmessage_mail(msg, recip.user)
        return msg

    @classmethod
    def new_message(cls, from_user, to_users, case, subject, content, signal=True):
        """
        Create a new Message and Thread.
        Mark thread as unread for all recipients, and
        mark thread as read and deleted from inbox by creator.
        """
        if case:
            vc = Case.objects.filter(id=case).first()
        else:
            vc = None
        thread = Thread.objects.create(subject=subject, case=vc)
        track_users=[]
        direct_msg = False

        #get coordinators on case
        if vc:
            vt_groups = CaseMember.objects.filter(case=case, coordinator=True).exclude(group__groupcontact__vincetrack=False).exclude(group__groupcontact__isnull=True).values_list('group', flat=True)
            logger.debug(vt_groups)
            vt_users = User.objects.using('vincecomm').filter(groups__in=vt_groups)
            logger.debug(vt_users)
            to_group = ", ".join(list(CaseMember.objects.filter(case=case, coordinator=True).exclude(group__groupcontact__vincetrack=False).exclude(group__groupcontact__isnull=True).values_list('group__groupcontact__contact__vendor_name', flat=True)))
            
        else:
            #otherwise just send to admin group (settings.py)
            #lookup group:
            to_g = Group.objects.using('vincecomm').filter(groupcontact__contact__vendor_name=settings.COGNITO_ADMIN_GROUP).first()
            if to_g:
                vt_users = User.objects.using('vincecomm').filter(groups__id=to_g.id, is_staff=True)
            else:
                logger.warning(f"ERROR: No group for {settings.COGNITO_ADMIN_GROUP}")
            to_group = settings.COGNITO_ADMIN_GROUP
            
        if to_users:
            for user in to_users:
                puser = User.objects.using('vincecomm').filter(id=user).first()
                if puser.groups.filter(name='vincetrack').exists():
                    track_users.append(puser)
                thread.userthread_set.create(user=puser, deleted=False, unread=True)
            #IF TO_USERS means this is from Coordinators
            direct_msg = True
        else:
            thread.to_group = to_group
            logger.debug(f"sending to {to_group}")
            thread.save()
            for user in vt_users:
                thread.userthread_set.create(user=user, deleted=False, unread=True)

        if direct_msg:
            #need to give access to all vt_users in the from_user group
            if not vc:
                team = from_user.groups.filter(groupcontact__vincetrack=True)
                vt_users = User.objects.using('vincecomm').filter(groups__in=team)
            #else if case - this goes to the coordinators on the case
            for user in vt_users:
                thread.userthread_set.create(user=user, deleted=True, unread=False)
        else:
            thread.userthread_set.create(user=from_user, deleted=True, unread=False)
        
        msg = cls.objects.create(thread=thread, sender=from_user, content=content)
        if signal:
            message_sent.send(sender=cls, message=msg, thread=thread, reply=False)

        if signal and direct_msg and track_users:
            for user in track_users:
                # the normal signal skips sending mail to track users,
                # but we need to notify them if it's a direct message from
                # one track member to another
                send_newmessage_mail(msg, user, notrack=False)
        #if to_users:
        #    for user in emails:
        #        send_newmessage_mail(msg, user)
        
        return msg

    def _get_user(self):
        return self.sender

    user = property(_get_user)

    def _get_vc(self):
        return True

    vc = property(_get_vc)
    
    class Meta:
        ordering = ("created",)

    def get_absolute_url(self):
        return self.thread.get_absolute_url()

class MessageAttachment(models.Model):

    file = models.ForeignKey(
        VinceAttachment,
        on_delete=models.CASCADE,
	blank=True,
        null=True)
    
    attachment = models.FileField(
        storage=PrivateMediaStorage(),
        blank=True,
        null=True)
    
    message = models.ForeignKey(
        Message,
        on_delete=models.CASCADE)

    @classmethod
    def attach_file(cls, message, file):
        """
        Upload the file to S3 and "attach" it to the message
        """

        if file.size:
            filename = smart_text(file.name)
            logger.debug(filename)
            try:
                mime_type = file.content_type
            except:
                mime_type = mimetypes.guess_type(filename, strict=False)[0]
                if not(mime_type):
                    mime_type = 'application/octet-stream'

            att = VinceAttachment(
                file=file,
                filename=os.path.basename(filename),
                mime_type=mime_type,
                size=file.size,
            )
            att.save()

        na = cls.objects.create(message=message, file=att)
        print(na.file.file.name)
        s3 = boto3.client('s3', region_name=settings.AWS_REGION)
        # check tag will be acceptable?
        nopass = re.findall(r'[^-+= \.:/@A-Za-z0-9_]', filename)
        if nopass:
            #this tag contains unacceptable chars, so do not add tag
            rd = s3.put_object_tagging(Bucket=settings.PRIVATE_BUCKET_NAME,
                                       Key='vince_attachments/'+ na.file.file.name,
                                       Tagging={'TagSet':[{'Key': 'Message', 'Value':str(message.id)}]})
        else:
            rd = s3.put_object_tagging(Bucket=settings.PRIVATE_BUCKET_NAME,
                                       Key='vince_attachments/'+ na.file.file.name,
                                       Tagging={'TagSet':[{'Key': 'Message', 'Value':str(message.id)},
                                                          {'Key':'Filename', 'Value':filename}]})

        
class VendorAction(models.Model):

    created = models.DateTimeField(
        _('Date'),
        default=timezone.now
    )

    title = models.CharField(
        _('Title'),
        max_length=200,
        blank=True,
        null=True,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        verbose_name=_('User'),
    )

    member = models.ForeignKey(
        CaseMember,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)
    
    case = models.ForeignKey(
	Case,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)

    post = models.ForeignKey(
        Post,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)


    def _get_date(self):
        # this is just so we can rename 'created' for sorting purposes
        return self.created

    date = property(_get_date)
    
    def __str__(self):
        if self.case and self.member:
            return f'{self.case.vuid}: {self.created} {self.title}'
        return '%s' % self.title

    def _get_vc(self):
        return True

    vc = property(_get_vc)


class VendorStatusChange(models.Model):

    action = models.ForeignKey(
        VendorAction,
        on_delete=models.CASCADE,
        verbose_name=_('Vendor Action'),
    )
    
    field = models.CharField(
        _('Field'),
        max_length=100,
    )

    old_value = models.TextField(
        _('Old Value'),
        blank=True,
        null=True,
    )

    new_value = models.TextField(
        _('New Value'),
        blank=True,
        null=True,
    )

    vul = models.ForeignKey(
        CaseVulnerability,
        on_delete=models.CASCADE,
        blank=True,
        null=True)

    def __str__(self):
        out = '%s ' % self.field
        if not self.new_value:
            out += 'removed'
        elif not self.old_value:
            out += ('set to %s') % self.new_value
        else:
            out += ('changed from "%(old_value)s" to "%(new_value)s"') % {
		'old_value': self.old_value,
                'new_value': self.new_value
            }
        return out

    class Meta:
        verbose_name = _('Vendor Status change')
        verbose_name_plural = _('Vendor status changes')


class VCVUReport(models.Model):
    vuid = models.CharField(max_length=50)
    idnumber = models.CharField(max_length=20)
    name = models.CharField(max_length=500)
    overview = models.TextField(blank=True, null=True)
    datecreated = models.DateTimeField(default = timezone.now)
    publicdate = models.DateTimeField(null=True, blank=True)
    datefirstpublished = models.DateTimeField(null=True, blank=True)
    dateupdated = models.DateTimeField(blank=True, null=True)
    keywords_str = models.TextField(blank=True, null=True)
    vulnote = models.ForeignKey(
        'VCVulnerabilityNote',
        blank=True, null=True,
        help_text=('This is used for VINCE published Vul Notes'),
        on_delete=models.CASCADE)

class VCVulnerabilityNote(models.Model):
    content = models.TextField(
        verbose_name=_('vulnote contents'))

    title = models.CharField(
        max_length=512,
        verbose_name=_('vul note title'))

    references = models.TextField(
        blank=True,
        null=True,
        verbose_name=_('references'))

    dateupdated = models.DateTimeField(
        default=timezone.now)

    datefirstpublished = models.DateTimeField(
        blank=True, null=True)

    revision_number = models.IntegerField(
        default=1,
        verbose_name=_('revision number'))

    vuid = models.CharField(max_length=20)

    publicdate = models.DateTimeField(
	null=True,
        blank=True)

    published = models.BooleanField(
        default=False)

    def get_title(self):
        return "%s: %s" % (self.vu_vuid, self.title)

    vutitle = property(get_title)

    def get_vuid(self):
        return f"{settings.CASE_IDENTIFIER}{self.vuid}"

    vu_vuid = property(get_vuid)

    def _get_idnumber(self):
        return self.vuid

    idnumber = property(_get_idnumber)

    def __str__(self):
        return self.vuid

class VCNoteVulnerability(models.Model):

    cve = models.CharField(
        _('CVE'),
        max_length=50,
        blank=True,
        null=True)

    description = models.TextField(
        _('Description'))

    note = models.ForeignKey(
        VCVulnerabilityNote,
        related_name="notevuls",
        on_delete=models.CASCADE)

    uid = models.CharField(
        max_length=100)

    case_increment = models.IntegerField(
	default = 0)

    date_added = models.DateTimeField(
        default=timezone.now)

    dateupdated= models.DateTimeField(
        auto_now=True
    )

    def __str__(self):
        return "%s" % self.vul

    def _get_vul(self):
        """ A user-friendly Vul ID, which is the cve if cve exists,
        otherwise it's a combination of vul ID and case. """
        if (self.cve):
            return u"CVE-%s" % self.cve 
        else:
            return u"%s" % self.cert_id
    vul = property(_get_vul)

    def _get_cert_id(self):
        return u"%s%s.%d" % (settings.CASE_IDENTIFIER, self.note.vuid, self.case_increment)

    cert_id = property(_get_cert_id)

class VCVendor(models.Model):

    note = models.ForeignKey(
        VCVulnerabilityNote,
        related_name="vendors",
        on_delete=models.CASCADE)

    contact_date = models.DateTimeField(
        help_text=_('The date that this vendor was first contacted about this vulnerability.'),
        blank=True,
        null=True
    )

    vendor = models.CharField(
        max_length=200,
        help_text=_('The name of the vendor that may be affected.')
    )

    uuid = models.UUIDField(
        blank=True,
        null=True,
        help_text=_('The uuid of the contact.')
    )

    references = models.TextField(
        help_text=_('Vendor references for this case'),
        blank=True,
        null=True)

    statement = models.TextField(
        help_text=_('A general vendor statement for all vuls in the case'),
        blank=True,
        null=True)

    statement_date = models.DateTimeField(
	blank=True,
        null=True
    )
    
    addendum = models.TextField(
        blank=True,
	null=True)
    
    dateupdated = models.DateTimeField(
        default=timezone.now
    )

    def get_status(self):
        status = VCVendorVulStatus.objects.filter(vendor=self).order_by('status').first()
        if status:
            return status.get_status_display()
        else:
            return "Unknown"

class VCVendorVulStatus(models.Model):
    AFFECTED_STATUS = 1
    UNAFFECTED_STATUS = 2
    UNKNOWN_STATUS = 3

    STATUS_CHOICES = (
        (AFFECTED_STATUS, "Affected"),
        (UNAFFECTED_STATUS, "Not Affected"),
        (UNKNOWN_STATUS, "Unknown")
    )

    vendor = models.ForeignKey(
        VCVendor,
        related_name="vendorvulstatus",
        on_delete=models.CASCADE)

    vul = models.ForeignKey(
        VCNoteVulnerability,
        related_name="notevulnerability",
        on_delete=models.CASCADE)

    status = models.IntegerField(
        choices=STATUS_CHOICES,
        default = UNKNOWN_STATUS,
        help_text=_('The vendor status. Unknown until vendor says otherwise.')
    )

    date_added = models.DateTimeField(
        default=timezone.now)

    dateupdated = models.DateTimeField(
        auto_now=True
    )

    references = models.TextField(
        blank=True,
        null=True)

    statement = models.TextField(
        blank=True,
        null=True)
    
class CaseTracking(models.Model):
    case = models.ForeignKey(
        Case,
	on_delete=models.CASCADE)

    group = models.ForeignKey(
	Group,
        on_delete=models.CASCADE)

    tracking = models.CharField(
        blank=True, null=True,
        max_length=100)
    
    added_by = models.ForeignKey(
	settings.AUTH_USER_MODEL,
        blank=True, null=True,
        on_delete=models.SET_NULL)

    dateupdated = models.DateTimeField(
        auto_now=True
    )

    class Meta:
        unique_together = (('group', 'case'),)
    
    def __str__(self):
        return self.tracking

class CaseViewed(models.Model):
    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE)
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True, null=True,
	on_delete=models.CASCADE)

    date_viewed = models.DateTimeField(
        default=timezone.now)


class CaseCoordinator(models.Model):
    case = models.ForeignKey(
        Case,
	on_delete=models.CASCADE)

    assigned = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE)

    def __str__(self):
        return f"%s is assigned to %s" % (self.assigned.get_username(), self.case.vu_vuid)
    

class CaseMemberUserAccess(models.Model):
    casemember = models.ForeignKey(
        CaseMember,
        on_delete=models.CASCADE)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE)

    admin = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='admin',
        help_text="User that made change",
        on_delete=models.SET_NULL,
        blank=True, null=True)

    date_modified = models.DateTimeField(
        default=timezone.now)


class VCDailyNotification(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE)

    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE)

    posts = models.IntegerField(
        default = 1)

    tracking = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )
    
    def __str__(self):
        if self.tracking:
            if self.posts > 1:
                return f"{self.posts} new posts in case {self.tracking} [{self.case.vu_vuid}]."
            else:
                return f"{self.posts} new posts in case {self.tracking} [{self.case.vu_vuid}]."
        if self.posts > 1:
            return f"{self.posts} new posts in case {self.case.vu_vuid}."
        else:
            return f"{self.posts} new post in case {self.case.vu_vuid}."
    

class VINCEEmailNotification(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
	on_delete=models.CASCADE)

    case = models.ForeignKey(
	Case,
        blank=True,
        null=True,
        on_delete=models.SET_NULL)

    summary = models.BooleanField(
        default=False)

    date_sent = models.DateTimeField(
        default=timezone.now)


    
