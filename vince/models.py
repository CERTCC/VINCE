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
import logging
from django.db import models
from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from django.contrib.postgres.fields import ArrayField
from django_countries.fields import CountryField
from django.contrib.postgres import fields
from django.conf import settings
from bigvince.storage_backends import PrivateMediaStorage, SharedMediaStorage
from django.db.models import Q
from datetime import timedelta, date, datetime
from django.urls import reverse
import json
import uuid
import re
import traceback
#Django 3 and up
from django.db.models import JSONField
import io
from lib.vince import utils as vinceutils

logger = logging.getLogger(__name__)

logger.setLevel(logging.DEBUG)

GENERAL_TICKET_QUEUE = 1
CASE_REQUEST_QUEUE = 2
CASE_TASK_QUEUE = 3
OTHER_QUEUE = 4
QUEUE_TYPE = (
    (GENERAL_TICKET_QUEUE, _('General Ticket')),
    (CASE_REQUEST_QUEUE, _('Case Request Queue')),
    (CASE_TASK_QUEUE, _('Case Task Queue')),
    (OTHER_QUEUE, _('Other Queue'))
)



class GroupSettings(models.Model):
    group = models.OneToOneField(
        Group,
        on_delete=models.CASCADE)

    publish = models.BooleanField(
        default=True)

    organization = models.CharField(
        help_text=_('The name of the cognito group'),
        max_length=50,
        blank=True,
        null=True)

    vulnote_template = models.TextField(
        blank=True,
        null=True)

    team_email = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text=_('Email address to use for outgoing email. If not set, uses DEFAULT_REPLY_EMAIL in settings'),
    )

    team_signature = models.TextField(
        blank=True,
        null=True,
        help_text=_('Email signature for automatic case messages sent by VINCE to case participants'),
    )

    disclosure_link = models.URLField(
        blank=True,
        null=True,
        help_text=_("Link to disclosure guidance that will be presented to case members at first view of case")
    )

    cna_email = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text=_('Email address used for CVE assignment'),
    )
    
    contact = models.ForeignKey(
        "Contact",
        blank=True,
        null=True,
        on_delete=models.SET_NULL)

    contacts_read = models.BooleanField(
        help_text=_('Does this group have permissions to read VINCE contacts'),
        default=True)

    contacts_write = models.BooleanField(
        help_text=_('Does this group have permissions to add/edit VINCE contacts'),
        default=True)

    def _get_triage(self):
        #get cr wueue
        queue = TicketQueue.objects.filter(queue_type=2, team=self.group).first()
        return queue

    triage = property(_get_triage)


class OldJSONField(JSONField):
    """ This was due to legacy support in Django 2.2. from_db_value
    should be explicitily sepcified when extending JSONField """

    def db_type(self, connection):
        return 'json'

    def from_db_value(self, value, expression, connection):
        return value

# Create your models here.
GROUP_TYPE = (
    ('srmail', 'SRMail List'),
    ('vendorlist', 'Vendor Contact List')
    )

STATUS_TYPE = (
    ('Active', 'Active'),
    ('Inactive', 'Inactive'),
    ('Unknown', 'Unknown')
)

MEMBER_TYPE = (
    ('Organization', 'Organization'),
    ('Person', 'Person'),
    ('Group', 'Group'))

#### CONTACTS MODELS ####

class ContactManager(models.Manager):
    def search(self, query=None):
        qs = self.get_queryset()
        if query is not None:
            qs = qs.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[query])
        return qs

class Contact(models.Model):
    #Kept Contact Type for backwards compatibility
    
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
    vendor_id = models.CharField(max_length=10, blank=True, null=True)
    vendor_name = models.CharField(max_length=100)
    vendor_type = models.CharField(max_length=50, default="Vendor", choices=VENDOR_TYPE)
    srmail_peer = models.CharField(max_length=100, blank=True, null=True)
    srmail_salutation = models.CharField(max_length=100, blank=True, null=True)
    srmail_id = models.IntegerField(blank=True, null=True)
    lotus_id = models.IntegerField(blank=True, null=True)
    countrycode = CountryField(blank=True, null=True, default="US")
    active = models.BooleanField(default=True)
    date_added = models.DateTimeField(default=timezone.now)
    user_added = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    location = models.CharField(max_length=15, choices=LOCATION_CHOICES, default="domestic")
    comment = models.TextField(blank=True, null=True)
    search_vector = SearchVectorField(null=True)
    modified = models.DateTimeField(
        auto_now=True
    )
    version = models.IntegerField(default=0)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    objects = ContactManager()

    def __str__(self):
        return self.vendor_name

    def get_absolute_url(self):
        return reverse('vince:contact', args=(self.id,))

    def get_emails(self):
        email_contact = EmailContact.objects.filter(contact=self, status=True).values_list('email', flat=True)
        return list(email_contact)

    def get_official_emails(self):
        email_contact = EmailContact.objects.filter(contact=self, email_function__in=["TO", "CC"], status=True).values_list('email', flat=True)
        return list(email_contact)

    def get_list_email(self):
        email_list = EmailContact.objects.filter(contact=self, email_list=True, status=True).exclude(name__icontains='service').first()
        if email_list:
            return email_list.email
        else:
            return ""

    def get_phone_number(self):
        phone = PhoneContact.objects.filter(contact=self).first()
        if phone:
            return phone.phone
        else:
            return ""
    
    def _get_tag_html(self):
        tags = self.contacttag_set.all()
        html = ""
        search_url = reverse("vince:searchcontacts")
        for tag in tags:
            html = html + f"<span class=\"label tkttag primary\"><a href=\"{search_url}?tag={tag}\"><i class=\"fas fa-tag\"></i> {tag}</a></span>  "
        return html

    get_tag_html = property(_get_tag_html)
    
    name = property(__str__)

    class Meta:
        indexes = [GinIndex(
            fields=['search_vector'],
            name= 'cmgr_gin',
            )
        ]

class GroupAdmin(models.Model):
    contact = models.ForeignKey(Contact,
                                on_delete=models.CASCADE)

    email = models.ForeignKey("EmailContact",
                              on_delete=models.CASCADE)

    def __str__(self):
        return "%s" % self.email


class ContactTag(models.Model):
    """
    This is the way to classify contacts
    """

    contact = models.ForeignKey(
        Contact,
        on_delete=models.CASCADE,
        verbose_name=_('Contact'),
    )

    created = models.DateTimeField(
        auto_now_add=True
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        help_text=_('User that tagged this contact.'),
        verbose_name=_('User'),
    )

    tag = models.CharField(
        max_length=50,
        help_text=_('The tag')
    )

    def __str__(self):
        return self.tag


class PostalAddress(models.Model):
    ADDRESS_TYPE = (
    ('Home', 'Home'),
    ('Work', 'Work'),
    ('Other', 'Other'),
    ('School', 'School'),
    )
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    country = CountryField(blank=True, null=True, default="US")
    primary = models.BooleanField(default=True)
    address_type = models.CharField(max_length=20, choices=ADDRESS_TYPE, default='Work')
    street = models.CharField(max_length=150)
    street2 = models.CharField(max_length=150, blank=True, null=True)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=40)
    zip_code = models.CharField(max_length=12)
    comment = models.CharField(max_length=200, blank=True, null=True)
    date_added = models.DateTimeField(default=timezone.now)
    user_added = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    version = models.IntegerField(default=0)
    def __str__(self):
        return "%s %s, %s %s" % (self.street, self.city, self.state, self.zip_code)

class PhoneContact(models.Model):
    PHONE_TYPE = (
    ('Fax', 'Fax'),
    ('Home', 'Home'),
    ('Hotline', 'Hotline'),
    ('Office', 'Office'),
    ('Mobile', 'Mobile'),
    )
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    country_code = models.CharField(max_length=5, default="+1")
    phone = models.CharField(max_length=50)
    phone_type = models.CharField(max_length=20, choices=PHONE_TYPE, default='Office')
    comment = models.CharField(max_length=200, blank=True, null=True)
    date_added = models.DateTimeField(default=timezone.now)
    user_added = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    version = models.IntegerField(default=0)

    def __str__(self):
        return "%s %s" % (country_code, phone)

class EmailContact(models.Model):
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
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    email = models.EmailField(max_length=254)
    email_type = models.CharField(max_length=20, choices=EMAIL_TYPE, default='Work')
    name = models.CharField(max_length=200, blank=True, null=True)
    user_added = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    email_function = models.CharField(max_length=10, choices=EMAIL_FUNCTION, default='TO')
    status = models.BooleanField(default=True)
    version = models.IntegerField(default=0)
    email_list = models.BooleanField(default=False)

    def __str__(self):
        return self.email

class Website(models.Model):
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    url = models.URLField()
    description = models.CharField(max_length=100, blank=True, null=True)
    date_added = models.DateTimeField(default=timezone.now)
    user_added = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    version = models.IntegerField(default=0)

    def __str__(self):
        return self.url

class ContactPgP(models.Model):
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    created_ts = models.DateTimeField(default=timezone.now)
    pgp_key_id = models.CharField(max_length=200)
    pgp_fingerprint = models.CharField(max_length=200, blank=True, null=True)
    pgp_version = models.IntegerField(blank=True, null=True)
    pgp_key_data = models.TextField(blank=True, null=True)
    revoked = models.BooleanField(default=False)
    startdate = models.CharField(max_length=12, blank=True, null=True)
    enddate = models.CharField(max_length=12, blank=True, null=True)
    pgp_protocol = models.CharField(max_length=30, default="GPG1 ARMOR MIME")
    version = models.IntegerField(default=0)
    pgp_email = models.EmailField(max_length=254,
                                  help_text=_('The email that belongs with this PGP Key.'),
                                  blank=True,
                                  null=True)
                                              
    def __str__(self):
        return self.pgp_key_id


class ContactGroup(models.Model):
    name = models.CharField(max_length=100)
    vuid = models.CharField(max_length=50, blank=True, null=True)
    description = models.CharField(max_length=250)
    srmail_peer_name = models.CharField(max_length=50)
    group_type = models.CharField(max_length=20, choices=GROUP_TYPE, default="srmail")
    status = models.CharField(max_length=20, choices=STATUS_TYPE, default="Active")
    comment = models.TextField(blank=True, null=True)
    date_added = models.DateTimeField(default=timezone.now)
    user_added = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, blank=True, null=True)
    version = models.IntegerField(default=0)
    modified = models.DateTimeField(
        auto_now=True
    )

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('vince:group', args=(self.id,))

class GroupDuplicate(models.Model):
    group = models.ForeignKey(ContactGroup, on_delete=models.CASCADE)

    def __str__(self):
        return self.group.name

class GroupMember(models.Model):
    group = models.ForeignKey(ContactGroup, on_delete=models.CASCADE)
    contact = models.ForeignKey(Contact, blank=True, null=True, on_delete=models.CASCADE)
    group_member = models.ForeignKey(GroupDuplicate, on_delete=models.CASCADE, blank=True, null=True)
    member_type = models.CharField(max_length=30, choices=MEMBER_TYPE, default="Organization")
    date_added = models.DateTimeField(default=timezone.now)
    user_added = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        return self.group.name

#1 - create
#2 - remove(change status)
#3 - modify
#4 - add to group
#5 - remove from group
#6 - tags

class Activity(models.Model):
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    text = models.CharField(max_length=1500, blank=True, null=True)
    action = models.IntegerField()
    action_ts = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return "%s %s on contact: %s" % (self.user.email, self.text, self.contact.vendor_name)

# 1 - create
# 2 - add to
# 3 - remove from
# 4 - change status
# 5 - change description/name

class GroupActivity(models.Model):
    group = models.ForeignKey(ContactGroup, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    text = models.CharField(max_length=1500, blank=True, null=True)
    action = models.IntegerField()
    action_ts = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return "%s %s on Group: %s" % (self.user.email, self.text, self.group.name)

class ContactAssociation(models.Model):
    contact = models.ForeignKey(Contact,
                                on_delete=models.CASCADE)

    user = models.EmailField(
        _('User Email'),
        help_text=_('The email of the user to verify.'),
        max_length=254)

    ticket = models.ForeignKey(
	"Ticket",
        on_delete=models.SET_NULL,
        verbose_name=_('Ticket'),
	blank=True,
        null=True
    )

    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        help_text=_('The user that initiated the request'),
        blank=True,
        null=True)

    authorized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name=_('Authorizer'),
        help_text=_('The user that authorized this request'),
        blank=True,
        null=True)
    
    email = models.CharField(
        _('Contact Email Address(es) for Verification.'),
        help_text=_('The company email address to send to. Multiple emails should be separated by a comma'),
        max_length=1000)

    email_body = models.TextField(
        help_text=_('The body of the email that will be sent to the above address for contact verification '),
        blank=True,
        null=True)

    restart = models.BooleanField(
        default=False)
    
    complete = models.BooleanField(
        default=False)

    approval_requested = models.BooleanField(
        default=False)

    def __str__(self):
        return f"{self.user} for {self.contact.vendor_name}"

        
#### TICKETING #####

class TicketQueue(models.Model):
    """
    A queue is a collection of tickets into what would generally be business
    areas or departments.
    For example, a company may have a queue for each Product they provide, or
    a queue for each of Accounts, Pre-Sales, and Support.
    """

    title = models.CharField(_('Title'),
                             max_length=100)

    slug = models.SlugField(
        _('Slug'),
        max_length=50,
        unique=True,
        help_text=_('This slug is used when building ticket ID\'s. Once set, '
                    'try not to change it or e-mailing may get messy.'),
    )

    new_ticket_cc = models.CharField(
        _('New Ticket CC Address'),
        blank=True,
        null=True,
        max_length=200,
        help_text=_('If an e-mail address is entered here, then it will '
                    'receive notification of all new tickets created for this queue. '
                    'Enter a comma between multiple e-mail addresses.'),
    )

    updated_ticket_cc = models.CharField(
        _('Updated Ticket CC Address'),
        blank=True,
        null=True,
        max_length=200,
        help_text=_('If an e-mail address is entered here, then it will '
                    'receive notification of all activity (new tickets, closed '
                    'tickets, updates, reassignments, etc) for this queue. Separate '
                    'multiple addresses with a comma.'),
    )

    default_owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='default_owner',
        blank=True,
        null=True,
        verbose_name=_('Default owner'),
    )

    queue_type = models.IntegerField(
        _('Queue Type'),
        choices = QUEUE_TYPE,
        default = GENERAL_TICKET_QUEUE)

    from_email = models.CharField(
        _('S3 Bucket Name for Email'),
        max_length=250,
        blank=True,
        null=True)


    #If this queue is owned by a team, set it here
    team = models.ForeignKey(
        Group,
        blank=True,
        null=True,
        help_text=_('Team Owner'),
        on_delete=models.SET_NULL
    )
    
    # Possibly adding this to associate a form with a queue
    #content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)

    #object_id = models.PositiveIntegerField()

    #content_object = GenericForeignKey('content_type', 'object_id')

    def __str__(self):
        return "%s" % self.title


    def _from_address(self):
        """
        Short property to provide a sender address in SMTP format,
        eg 'Name <email>'. We do this so we can put a simple error message
        in the sender name field, so hopefully the admin can see and fix it.
        """
        return u'VINCE-%s <%s>' % (self.title, settings.DEFAULT_FROM_EMAIL)
    from_address = property(_from_address)


class QueuePermissions(models.Model):

    queue = models.ForeignKey(
	TicketQueue,
        on_delete=models.CASCADE,
        verbose_name=_('Queue'),
    )

    group = models.ForeignKey(
        Group,
        help_text=_('Group permissions'),
        on_delete=models.CASCADE
    )

    group_read = models.BooleanField(
        default=True,
        verbose_name=_('group read access'))

    group_write = models.BooleanField(
	default=True,
        verbose_name=_('group write access'))

    publish = models.BooleanField(
        default=True,
        verbose_name=('queue publish access'))

    class Meta:
        unique_together = (('queue', 'group'),)


class TicketManager(models.Manager):
    def search(self, query=None):
        qs = self.get_queryset()
        if query is not None:
            qs = qs.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[query])
        return qs


class Ticket(models.Model):
    """
    To allow a ticket to be entered as quickly as possible, only the
    bare minimum fields are required. These basically allow us to
    sort and manage the ticket. The user can always go back and
    enter more information later.

    A good example of this is when a customer is on the phone, and
    you want to give them a ticket ID as quickly as possible. You can
    enter some basic info, save the ticket, give the customer the ID
    and get off the phone, then add in further detail at a later time
    (once the customer is not on the line).

    Note that assigned_to is optional - unassigned tickets are displayed on
    the dashboard to prompt users to take ownership of them.
    """


    OPEN_STATUS = 1
    REOPENED_STATUS = 2
    RESOLVED_STATUS = 3
    CLOSED_STATUS = 4
    DUPLICATE_STATUS = 5
    IN_PROGRESS_STATUS = 6
    #Maximum related activity to display
    MAX_ACTIVITY = 20
    
    STATUS_CHOICES = (
        (OPEN_STATUS, _('Open')),
        (REOPENED_STATUS, _('Reopened')),
        (RESOLVED_STATUS, _('Resolved')),
        (CLOSED_STATUS, _('Closed')),
        (DUPLICATE_STATUS, _('Duplicate')),
        (IN_PROGRESS_STATUS, _('In progress')),
    )

    PRIORITY_CHOICES = (
        (1, _('1. Critical')),
        (2, _('2. High')),
        (3, _('3. Normal')),
        (4, _('4. Low')),
        (5, _('5. Very Low')),
    )

    CLOSE_CHOICES = (
        (1, 'Opened Case'),
        (2, 'Task Complete'),
        (3, 'Spam'),
        (4, 'Decline'),
        (5, 'Decline, already fixed'),
        (6, 'Decline, vendor not contacted'),
        (7, 'Decline, vendor cooperating'),
        (8, 'Decline, live website vul'),
        (9, 'Forward'),
    )

    title = models.CharField(
        _('Title'),
        max_length=200,
    )

    queue = models.ForeignKey(
        TicketQueue,
        on_delete=models.CASCADE,
        verbose_name=_('Queue'),
    )

    case = models.ForeignKey(
        'VulnerabilityCase',
        on_delete=models.SET_NULL,
        verbose_name=_('Case'),
        blank=True,
        null=True,
        help_text=_('The case this ticket is associated to'),
    )

    created = models.DateTimeField(
        _('Created'),
        blank=True,
        help_text=_('Date this ticket was first created'),
    )

    modified = models.DateTimeField(
        _('Modified'),
        blank=True,
        help_text=_('Date this ticket was most recently changed.'),
    )

    submitter_email = models.CharField(
        _('Submitter E-Mail'),
        max_length=300,
        blank=True,
        null=True,
        help_text=_('The submitter will receive an email for all public '
                    'follow-ups left for this task.'),
    )

    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='assigned_to',
        blank=True,
        null=True,
        verbose_name=_('Assigned to'),
    )

    status = models.IntegerField(
        _('Status'),
        choices=STATUS_CHOICES,
        default=OPEN_STATUS,
    )

    on_hold = models.BooleanField(
        _('On Hold'),
        blank=True,
        default=False,
        help_text=_('If a ticket is on hold, it will not automatically be escalated.'),
    )

    description = models.TextField(
        _('Description'),
        blank=True,
        null=True,
        help_text=_('The content of the customers query.'),
    )

    resolution = models.TextField(
        _('Resolution'),
        blank=True,
        null=True,
        help_text=_('The resolution provided to the customer by our staff.'),
    )

    priority = models.IntegerField(
        _('Priority'),
        choices=PRIORITY_CHOICES,
        default=3,
        blank=3,
        help_text=_('1 = Highest Priority, 5 = Low Priority'),
    )

    due_date = models.DateTimeField(
        _('Due on'),
        blank=True,
        null=True,
    )

    close_reason = models.IntegerField(
        default=2,
        choices=CLOSE_CHOICES
    )

    search_vector = SearchVectorField(null=True)

    objects = TicketManager()

    class Meta:
        indexes = [ GinIndex(
            fields = ['search_vector'],
            name = 'ticket_gin',
            )
        ]
    def _get_assigned_to(self):
        """ Custom property to allow us to easily print 'Unassigned' if a
        ticket has no owner, or the users name if it's assigned. If the user
        has a full name configured, we use that, otherwise their username. """
        if not self.assigned_to:
            return _('Unassigned')
        else:
            return self.assigned_to.usersettings.vince_username
#            if self.assigned_to.usersettings.g():
#                return self.assigned_to.get_full_name()
#            else:
#                return self.assigned_to.get_username()
    get_assigned_to = property(_get_assigned_to)

    def _get_ticket(self):
        """ A user-friendly ticket ID, which is a combination of ticket ID
        and queue slug. This is generally used in e-mail subjects. """

        return u"[%s]" % self.ticket_for_url
    ticket = property(_get_ticket)

    def _get_ticket_for_url(self):
        """ A URL-friendly ticket ID, used in links. """
        return u"%s-%s" % (self.queue.slug, self.id)
    ticket_for_url = property(_get_ticket_for_url)

    def _get_priority_css_class(self):
        """
        Return the boostrap class corresponding to the priority.
        """
        if self.priority == 2:
            return "warning"
        elif self.priority == 1:
            return "danger"
        elif self.priority == 5:
            return "success"
        else:
            return ""


    get_priority_css_class = property(_get_priority_css_class)


    def _get_status(self):
        """
        Displays the ticket status, with an "On Hold" message if needed.
        """
        held_msg = ''
        if self.on_hold:
            held_msg = _(' - On Hold')
        dep_msg = ''
        if not self.can_be_resolved:
            dep_msg = _(' - Open dependencies')
        return u'%s%s%s' % (self.get_status_display(), held_msg, dep_msg)
    get_status = property(_get_status)

    def get_absolute_url(self):
        return reverse('vince:ticket', args=(self.id,))

    def __str__(self):
        return '%s %s' % (self.id, self.title)

    def save(self, *args, **kwargs):
        if not self.pk or kwargs.get('force_insert', False):
            # This is a new ticket as no ID yet exists.
            self.created = timezone.now()
            self.modified = self.created
        else:
            self.modified = timezone.now()

        if not self.priority:
            self.priority = 3

        super(Ticket, self).save(*args, **kwargs)

    def _can_be_resolved(self):
        """
        Returns a boolean.
        True = any dependencies are resolved
        False = There are non-resolved dependencies
        """
        OPEN_STATUSES = (Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS)
        return TicketDependency.objects.filter(ticket=self).filter(
            depends_on__status__in=OPEN_STATUSES).count() == 0

    can_be_resolved = property(_can_be_resolved)

    def get_actions(self):
        #zero or negative max_activity is unlimited
        if self.MAX_ACTIVITY > 0:
            self.followup_set.order_by('-date')[:self.MAX_ACTIVITY]
        return self.followup_set.order_by('-date')


    def _get_status_html(self):
        if self.status == self.OPEN_STATUS:
            return f"<span class=\"label success\">{self.get_status_display()}</span>"
        elif self.status == self.REOPENED_STATUS:
            return f"<span class=\"label warning\">{self.get_status_display()}</span>"
        elif self.status == self.CLOSED_STATUS:
            return f"<span class=\"label info\">{self.get_status_display()}</span>"
        else:
            return f"<span class=\"label primary\">{self.get_status_display()}</span>"

    get_status_html = property(_get_status_html)

    def _get_close_status_html(self):
        return f"<span class=\"label badge-tag-info\">{ self.get_close_reason_display()}</span>"

    get_close_status_html = property(_get_close_status_html)

    def _get_tag_html(self):
        tags = self.tickettag_set.all()
        html = ""
        search_url = reverse("vince:ticketsearch")
        for tag in tags:
            html = html + f"<span class=\"label tkttag primary\"><a href=\"{search_url}?tag={tag}\"><i class=\"fas fa-tag\"></i> {tag}</a></span>  "
        return html

    get_tag_html = property(_get_tag_html)

    def _get_review(self):
        test = VulNoteReview.objects.filter(ticket=self).order_by('-date_complete').first()
        print(test)
        return VulNoteReview.objects.filter(ticket=self).order_by('-date_complete').first()
    
    review = property(_get_review)
    
    def as_dict(self):
        if self.case:
            case = self.case.vu_vuid,
        else:
            case = None
        assignment = str(self.get_assigned_to)

        time_since = timezone.now() - self.created
        days_since = time_since.days
        time_since = timezone.now() - self.modified
        stale_since = time_since.days
        url = str(self.get_absolute_url())
        return {
	    'id': self.id,
            'title': self.title,
            'url': url,
	    'ticket': self.ticket,
	    'description': self.description,
            'created':self.created.strftime('%Y-%m-%d'),
            'date': self.modified.strftime('%Y-%m-%d'),
            'status': self.get_status,
            'queue': self.queue.title,
            'resolution': self.resolution,
            'assigned_to': assignment,
            'case': case,
            'open_for': days_since,
            'stale_for': stale_since 
        }


class TicketContact(models.Model):
    contact = models.ForeignKey(
        Contact,
        on_delete=models.CASCADE,
        help_text=_('The contact associated with this ticket.')
    )

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        verbose_name=_('Ticket'),
    )

    def __str__(self):
        return '%s' % self.contact.vendor_name



class TicketThread(models.Model):
    ticket = models.IntegerField(
        _('VinceTrack Ticket ID'))
    thread = models.IntegerField(
        _("VinceComm Thread ID")
    )

class FollowupMessage(models.Model):
    followup = models.ForeignKey(
        "FollowUp",
        on_delete=models.CASCADE,
        blank=True, null=True,
        verbose_name=_('Follow-up'),
    )
    msg = models.IntegerField(
        _('VinceComm Msg ID'))


class Action(models.Model):


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
        max_length=300,
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
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        verbose_name=_('User'),
    )

    email_id = models.CharField(
	max_length=150,
        blank=True,
        null=True,
        help_text=_('If email-originated, email ID here')
    )

    email_bucket = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text=_('If email-originated, bucket name here')
    )
    
    new_status = models.IntegerField(
        _('New Status'),
        choices=Ticket.STATUS_CHOICES,
        blank=True,
        null=True,
        help_text=_('If the status was changed, what was it changed to?'),
    )

    artifact = models.ForeignKey(
        'Artifact',
        blank=True,
        null=True,
        on_delete = models.SET_NULL,
        help_text=_('If an artifact was added, reference to artifact.'),
    )

    def __str__(self):
        return '%s' % self.title

    def _get_related_ticket(self):
        ticket = FollowUp.objects.filter(action_ptr=self).first()
        if ticket:
            return ticket.ticket
        else:
            return None
    get_related_ticket = property(_get_related_ticket)

    def _get_related_case(self):
        case = CaseAction.objects.filter(action_ptr=self).first()
        if case:
            return case.case
        else:
            return None
    get_related_case = property(_get_related_case)

    def _get_created(self):
        # this is just so we can rename 'created' for sorting purposes
        return self.date

    created = property(_get_created)

    def _is_email(self):
        if self.title.startswith('New Email') or self.title.startswith('New email'):
            return True
        return False

    is_email = property(_is_email)

class FollowUp(Action):
    """
    A FollowUp is a comment and/or change to a ticket. We keep a simple
    title, the comment entered by the user, and the new status of a ticket
    to enable easy flagging of details on the view-ticket page.

    The title is automatically generated at save-time, based on what action
    the user took.

    Tickets that aren't public are never shown to or e-mailed to the submitter,
    although all staff can see them.
    """

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        verbose_name=_('Ticket'),
    )

    class Meta:
        ordering = ('date',)
        verbose_name = _('Follow-up')
        verbose_name_plural = _('Follow-ups')


    def save(self, *args, **kwargs):
        logger.debug(f"Follow up saved args: {args}, kwargs: {kwargs}")
        db = kwargs.get('using', 'default')
        t = self.ticket
        t.modified = timezone.now()
        t.save(using=db)
        super(FollowUp, self).save(*args, **kwargs)

    def _get_html_logo(self):
        if "commented" in self.title:
            return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"far fa-comment\"></i></span></div>"
        elif "Submitted" in self.title:
            return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"fas fa-plus-square\"></i></span></div>"
        elif "message" in self.title:
            return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"far fa-envelope\"></i></span></div>"
        else:
            return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"fas fa-cogs\"></i></span></div>"

    html_logo = property(_get_html_logo)


class TicketChange(models.Model):
    """
    For each FollowUp, any changes to the parent ticket (eg Title, Priority,
    etc) are tracked here for display purposes.
    """

    followup = models.ForeignKey(
        FollowUp,
        on_delete=models.CASCADE,
        verbose_name=_('Follow-up'),
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

    def __str__(self):
        out = '%s ' % self.field
        if not self.new_value:
            out += _('removed')
        elif not self.old_value:
            out += _('set to %s') % self.new_value
        else:
            out += _('changed from "%(old_value)s" to "%(new_value)s"') % {
                'old_value': self.old_value,
                'new_value': self.new_value
            }
        return out

    class Meta:
        verbose_name = _('Ticket change')
        verbose_name_plural = _('Ticket changes')


def attachment_path(instance, filename):
    """
    Provide a file path that will help prevent files being overwritten, by
    putting attachments in a folder off attachments for ticket/followup_id/.
    """
    import os
    os.umask(0)
    if instance.action.get_related_ticket:
        path = 'vince/attachments/%s/%s' % (instance.action.get_related_ticket.ticket_for_url, instance.action.id)
    else:
        path = 'vince/attachments/%s/%s' % (instance.action.get_related_case.case_for_url, instance.action.id)

    att_path = os.path.join(settings.MEDIA_ROOT, path)
    if settings.DEFAULT_FILE_STORAGE == "django.core.files.storage.FileSystemStorage":
        if not os.path.exists(att_path):
            os.makedirs(att_path, 0o777)
    return os.path.join(path, filename)


def get_uuid_filename(self, filename):

    name = str(self.uuid)

    return name

class Attachment(models.Model):
    """
    Represents a file attached to a follow-up. This could come from an e-mail
    attachment, or it could be uploaded via the web interface.
    """

    file = models.FileField(
        _('File'),
        storage=PrivateMediaStorage(),
        upload_to=get_uuid_filename,
        max_length=1000,
    )

    action = models.ForeignKey(
        Action,
        on_delete=models.CASCADE,
        verbose_name=_('Action'),
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

    public = models.BooleanField(
        default=False)

    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True)

    def __str__(self):
        return '%s' % self.filename

    def _get_access_url(self):
        filename = vinceutils.safe_filename(self.filename,str(self.uuid),self.mime_type)
        url = self.file.storage.url(self.file.name, parameters={'ResponseContentDisposition': f'attachment; filename="{filename}"'})
        return url

    access_url = property(_get_access_url)

    class Meta:
        ordering = ('filename',)
        verbose_name = _('Attachment')
        verbose_name_plural = _('Attachments')

class CaseAttachment(models.Model):
    case = models.ForeignKey(
        "VulnerabilityCase",
        on_delete=models.CASCADE,
        verbose_name=_('Case'),
    )
    attachment = models.ForeignKey(
        Attachment,
        on_delete=models.CASCADE)
    attached = models.DateTimeField(
        default=timezone.now)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
	blank=True,
	null=True,
	on_delete=models.SET_NULL)

class NotificationAttachment(models.Model):
    notification = models.ForeignKey(
        'VendorNotificationContent',
        on_delete=models.CASCADE,
        verbose_name=_('Notification'),
    )
    attachment = models.ForeignKey(
        Attachment,
        on_delete=models.CASCADE)
    attached = models.DateTimeField(
        default=timezone.now)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
	blank=True,
	null=True,
	on_delete=models.SET_NULL)



class TicketCC(models.Model):
    """
    Often, there are people who wish to follow a ticket who aren't the
    person who originally submitted it. This model provides a way for those
    people to follow a ticket.
    In this circumstance, a 'person' could be either an e-mail address or
    an existing system user.
    """

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        verbose_name=_('Ticket'),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        help_text=_('User who wishes to receive updates for this ticket.'),
        verbose_name=_('User'),
    )

    email = models.EmailField(
        _('E-Mail Address'),
        blank=True,
        null=True,
        help_text=_('For non-user followers, enter their e-mail address'),
    )

    can_view = models.BooleanField(
        _('Can View Ticket?'),
        blank=True,
        default=False,
        help_text=_('Can this CC login to view the ticket details?'),
    )

    can_update = models.BooleanField(
        _('Can Update Ticket?'),
        blank=True,
        default=False,
        help_text=_('Can this CC login and update the ticket?'),
    )

    def _email_address(self):
        if self.user and self.user.email is not None:
            return self.user.email
        else:
            return self.email
    email_address = property(_email_address)

    def _display(self):
        if self.user:
            return self.user
        else:
            return self.email

    display = property(_display)

    def __str__(self):
        return '%s for %s' % (self.display, self.ticket.title)


class TicketTag(models.Model):
    """
    This is the way to classify tickets.
    """

    ticket = models.ForeignKey(
        Ticket,
	on_delete=models.CASCADE,
        verbose_name=_('Ticket'),
    )

    created = models.DateTimeField(
        auto_now_add=True
    )
    
    user = models.ForeignKey(
	settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
	null=True,
	help_text=_('User that tags this ticket.'),
        verbose_name=_('User'),
    )

    tag = models.CharField(
        max_length=50,
        help_text=_('The tag')
    )

    def __str__(self):
        return self.tag

    
class TicketDependency(models.Model):
    """
    The ticket identified by `ticket` cannot be resolved until the ticket in `depends_on` has been resolved.

    To help enforce this, a helper function `can_be_resolved` on each Ticket instance checks that
    these have all been resolved.
    """
    class Meta:
        unique_together = (('ticket', 'depends_on'),)
        verbose_name = _('Ticket dependency')
        verbose_name_plural = _('Ticket dependencies')

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        verbose_name=_('Ticket'),
        related_name='ticketdependency',
    )

    depends_on = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        verbose_name=_('Depends On Ticket'),
        related_name='depends_on',
    )

    def __str__(self):
        return '%s / %s' % (self.ticket, self.depends_on)


class CaseDependency(models.Model):
    """
    The case identified by `case` cannot be resolved until the ticket in `depends_on` has been resolved.

    To help enforce this, a helper function `can_be_resolved` on each Ticket instance checks that
    these have all been resolved.
    """
    class Meta:
        unique_together = (('case', 'depends_on'),)
        verbose_name = _('Case dependency')
        verbose_name_plural = _('Case dependencies')

    case = models.ForeignKey(
        'VulnerabilityCase',
        on_delete=models.CASCADE,
        verbose_name=_('Case'),
        related_name='casedependency',
    )
    depends_on = models.ForeignKey(
	Ticket,
        on_delete=models.CASCADE,
	verbose_name=_('Depends On Ticket'),
        related_name='case_depends_on',
    )

    def __str__(self):
        return '%s / %s' % (self.case, self.depends_on)


class VulNote(models.Model):
    current_revision = models.OneToOneField(
        'VulNoteRevision',
        blank=True, null=True,
        on_delete=models.CASCADE,
        related_name='current_set',
        help_text=_('The revision being displayed for this vul note. If you need to rollback, change value of this field.')
    )

    case = models.OneToOneField(
        'VulnerabilityCase',
        help_text=_('The case this vul note belongs with.'),
        on_delete=models.CASCADE
    )

    created = models.DateTimeField(
        auto_now_add=True
    )

    modified = models.DateTimeField(
        auto_now=True
    )

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True, null=True,
        help_text=_('The owner of this vul note, typically the creator.'),
	on_delete=models.SET_NULL)

    group = models.ForeignKey(
        Group,
        blank=True, null=True,
        help_text=_('Group permissions'),
        on_delete=models.SET_NULL
    )

    group_read = models.BooleanField(
        default=True,
        verbose_name=_('group read access'))

    group_write = models.BooleanField(
        default=True,
        verbose_name=_('group write access'))

    other_read = models.BooleanField(
        default=True,
        verbose_name=_('other read access'))

    approved = models.BooleanField(
        default=False,
        help_text=('Vul note must be approved before publishing'))

    ticket_to_approve = models.ForeignKey(
        Ticket,
        blank=True, null=True,
        on_delete = models.SET_NULL)

    date_published = models.DateTimeField(
        blank=True, null=True)

    date_last_published = models.DateTimeField(
        blank=True, null=True)

    date_shared = models.DateTimeField(
        blank=True, null=True)

    revision_shared = models.IntegerField(
        default = 999)

    revision_published = models.IntegerField(
        default = 999)

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
        revisions = self.vulnoterevision_set.all()
        try:
            new_revision.revision_number = revisions.latest().revision_number + 1
        except VulNoteRevision.DoesNotExist:
            new_revision.revision_number = 0
        new_revision.vulnote = self
        new_revision.previous_revision = self.current_revision
        if save:
            new_revision.clean()
            new_revision.save()
        self.current_revision = new_revision
        if save:
            self.save()


    def __str__(self):
        if self.current_revision:
            return self.current_revision.title
        obj_name = _('Vul Note without content (%(id)d)') % {'id': self.id}
        return str(obj_name)


        
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


class VulNoteRevision(BaseRevisionMixin,  models.Model):

    """This is where main revision data is stored. To make it easier to
    copy, do NEVER create m2m relationships."""

    vulnote = models.ForeignKey(
        'VulNote',
        on_delete=models.CASCADE,
        verbose_name=_('vulnote'))

    # This is where the content goes, with whatever markup language is used
    content = models.TextField(
        blank=True,
        verbose_name=_('vulnote contents'))

    # This title is automatically set from either the article's title or
    # the last used revision...
    title = models.CharField(
        max_length=512,
        verbose_name=_('vul note title'),
        null=False,
        blank=False,
        help_text=_(
            'Each revision contains a title field that must be filled out, even if the title has not changed'))
    references = models.TextField(
        blank=True,
        verbose_name=_('references'))

    date_published = models.DateTimeField(
        blank=True, null=True)

    date_shared = models.DateTimeField(
        blank=True, null=True)

    search_vector = SearchVectorField(null=True)
    
    def __str__(self):
        if self.revision_number:
            return "%s (%d)" % (self.title, self.revision_number)
        else:
            return "%s" % self.title

    def clean(self):
        # Enforce DOS line endings \r\n. It is the standard for web browsers,
        # but when revisions are created programatically, they might
        # have UNIX line endings \n instead.
        self.content = self.content.replace('\r', '').replace('\n', '\r\n')

    def inherit_predecessor(self, vulnote):
        """
        Inherit certain properties from predecessor because it's very
        convenient. Remember to always call this method before
        setting properties :)"""
        predecessor = vulnote.current_revision
        self.vulnote = predecessor.vulnote
        self.content = predecessor.content
        self.title = predecessor.title
        self.references = predecessor.references
        self.deleted = predecessor.deleted
        self.locked = predecessor.locked

    def _get_reviews(self):
        return VulNoteReview.objects.filter(vulnote=self, complete=True)

    reviews = property(_get_reviews)
        
    class Meta:
        indexes = [GinIndex(
            fields=['search_vector'],
            name= 'vulnote_gin',
            )
        ]
        get_latest_by = 'revision_number'
        ordering = ('created',)
        unique_together = ('vulnote', 'revision_number')



class VulNoteReview(models.Model):
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
	on_delete=models.SET_NULL,
        blank=True,
        null=True)

    vulnote = models.ForeignKey(
        VulNoteRevision,
        on_delete=models.CASCADE,
        help_text=_('The revision of the vulnote being reviewed.')
    )

    review =  models.TextField(
        )
    
    feedback = models.TextField(
        _('Feedback'),
        blank=True, null=True,
        help_text=_('Feedback/Comments to the Author')
    )
    
    ticket = models.ForeignKey(
        Ticket,
        blank=True, null=True,
        on_delete=models.SET_NULL)
    
    marks = OldJSONField(
        blank=True,
        null=True)

    date_complete = models.DateTimeField(
        blank=True, null=True)
    
    complete = models.BooleanField(
        default=False)

    approve = models.BooleanField(
        default=False)

    def _marks_json(self):
        return json.loads(self.marks)

    marksj = property(_marks_json)

    def __str__(self):
        if self.reviewer:
            return f"{self.vulnote.vulnote.case.vu_vuid} review by {self.reviewer.usersettings.preferred_username}"
        else:
            return f"{self.vulnote.vulnote.case.vu_vuid} review unassigned."
    

class EmailTemplate(models.Model):
    """
    Since these are more likely to be changed than other templates, we store
    them in the database.
    This means that an admin can change email templates without having to have
    access to the filesystem.
    """

    template_name = models.CharField(
        _('Template Name'),
        max_length=100,
    )

    subject = models.CharField(
        _('Subject'),
        max_length=100,
        help_text=_('If related to a ticket action, This will be prefixed '
                    '"[ticket.ticket] ticket.title"'
                    '. We recommend something simple such as '
                    '"(Updated") or "(Closed)"'
                    ' - the same context is available as in plain_text, below.'),
    )

    heading = models.CharField(
        _('Heading'),
        max_length=100,
        help_text=_('In HTML e-mails, this will be the heading at the top of '
                    'the email - the same context is available as in plain_text, '
                    'below.'),
    )

    plain_text = models.TextField(
        _('Plain Text'),
        help_text=_('If related to a ticket, the context available to you'
                    ' includes {{ ticket }}, '
                    '{{ queue }}, and depending on the time of the call: '
                    '{{ resolution }} or {{ comment }}.'),
    )

    html = models.TextField(
        _('HTML'),
        help_text=_('The same context is available here as in plain_text, above.'),
    )

    locale = models.CharField(
        _('Locale'),
        max_length=10,
        blank=True,
        null=True,
        help_text=_('Locale of this template.'),
    )

    body_only = models.BooleanField(
        default=False)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)

    modified = models.DateTimeField(
        auto_now=True
    )

    def __str__(self):
        return '%s' % self.template_name


    def as_dict(self):
        if self.user:
            user = self.user.usersettings.preferred_username
        else:
            user = "system"
        return {
	    'id': self.id,
	    'name': self.template_name,
            'user': user,
            'subject': self.subject,
            'modified': self.modified.strftime('%Y-%m-%d'),
            'locale': self.locale,
            'auto': not(self.body_only)}
    
    class Meta:
        ordering = ('template_name', 'locale')
        verbose_name = _('e-mail template')
        verbose_name_plural = _('e-mail templates')


def update_filename(instance, filename):
    if instance.vrf_id:
        new_filename = "vrf%s_%s" % (instance.vrf_id, filename)
    else:
        new_filename= "novrf_%s" % filename

    return new_filename


class CaseRequest(Ticket):
    """
    A Case Request is a request for VINCE vulnerability coordination that
    has either been manually created by a coordinator or has come from
    the Vulnerability Reporting Form (VRF).

    A Case Request will eventually (but not always) become a Vulnerability
    Case if selected by the Vuln Coordination Team.
    """
    SUB_CHOICES = (
        ('email', 'email'),
        ('web', 'web'),
        ('manual', 'manual'),
        )
    VRF_FORM = 1
    GOV_FORM = 3

    REQUEST_TYPES = (
        (VRF_FORM, 'VRF'),
        (GOV_FORM, 'GOV'),
    )

    vrf_id = models.CharField(max_length=20)
    request_type = models.IntegerField(
        _('Request Type'),
        choices=REQUEST_TYPES,
        default=VRF_FORM,
    )
    contact_name = models.CharField(max_length=100, blank=True, null=True)
    contact_org = models.CharField(max_length=100, blank=True, null=True)
    contact_email = models.EmailField(max_length=254, blank=True, null=True)
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    share_release = models.BooleanField(default=True)
    credit_release = models.BooleanField(default=True)
    comm_attempt = models.BooleanField(blank=True, null=True)
    why_no_attempt = models.CharField(max_length=100, blank=True, null=True)
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
    user_file = models.FileField(blank=True, null=True, storage=PrivateMediaStorage(), upload_to=update_filename)
    tracking = models.CharField(max_length=100,blank=True, null=True)
    comments = models.TextField(blank=True, null=True)
    date_submitted = models.DateTimeField(default=timezone.now)
    submission_type = models.CharField(max_length=15, choices=SUB_CHOICES, default="web")
    vc_id = models.IntegerField(default = 0)


    def get_vrf_subject(self):
        if self.vrf_id:
            return "%s%s" % (settings.REPORT_IDENTIFIER, self.vrf_id)
        elif self.tracking:
            return "%s" % self.tracking
        else:
            return "New Vulnerability Report"

    vrf_subject = property(get_vrf_subject)

class VulnerabilityCaseManager(models.Manager):
    def search(self, query=None):
        qs = self.get_queryset()
        if query is not None:
            qs = qs.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[query])
        return qs

class VulnerabilityCase(models.Model):
    """
    A Vulnerability Case is a case that has been selected by a
    VINCE Coordination team for vulnerability coordination
    """
    INACTIVE_STATUS = 2
    ACTIVE_STATUS = 1

    STATUS_CHOICES = (
        (ACTIVE_STATUS, _('Active')),
        (INACTIVE_STATUS, _('Inactive')),
    )
    vuid = models.CharField(max_length=20)
    created = models.DateTimeField(default=timezone.now)

    modified = models.DateTimeField(
        _('Modified'),
        blank=True,
        null=True,
        help_text=_('Date this case was most recently changed.'),
    )

    on_hold = models.BooleanField(
        _('On Hold'),
        blank=True,
        default=False,
        help_text=_('If a case is on hold, it will not automatically be escalated.'),
    )
    status = models.IntegerField(
	_('Status'),
        choices=STATUS_CHOICES,
        default=ACTIVE_STATUS,
    )

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        help_text=_('The User that has selected the case for coordination'),
        on_delete=models.SET_NULL,
        blank=True,
        null=True
    )

    team_owner = models.ForeignKey(
        Group,
        help_text=_('The team that owns this case'),
        on_delete=models.SET_NULL,
        blank=True,
        null=True
    )
    
    case_request = models.ForeignKey(
        Ticket,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        help_text=_('The CaseRequest that this is Case is derived from'))

    product_name = models.CharField(
        max_length=500,
        help_text=_('The vulnerable product name/affected website.')
    )

    product_version = models.CharField(
        max_length=100,
        help_text=_('The product version that is vulnerable (if available).'),
        blank=True,
        null=True
    )

    summary = models.CharField(
        max_length=1000,
        help_text=_('A summary of the vulnerable.  This may be taken from the description in the CaseRequest.')
    )

    title = models.CharField(
        max_length=500,
        help_text=_('A title for this case.'))

    due_date = models.DateTimeField(
        help_text=_('Estimated Public Date'),
        blank=True, null=True
    )

    publicdate = models.DateTimeField(
        blank=True, null=True
    )


    publicurl = models.CharField(
        _('Public URL'),
        max_length=500, blank=True, null=True,
        help_text=_('The URL for the public notice of a vulnerability.'),
    )


    template = models.ForeignKey(
        'CaseTemplate',
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        help_text=_('Changing the template will result in the addition of new tasks to this case. Existing tasks will not be modified.'),
    )

    vul_incrementer = models.IntegerField(
        default = 0
    )

    lotus_notes = models.BooleanField(
        default = False,
        help_text=_('Do not create this case in VinceComm.')
    )

    changes_to_publish = models.BooleanField(
        default = False,
        help_text=_('Switch to True if changes to case require publishing')
    )

    search_vector = SearchVectorField(null=True)

    objects = VulnerabilityCaseManager()

    class Meta:
        indexes = [ GinIndex(
            fields = ['search_vector'],
            name = 'case_gin',
            )
        ]

    def get_title(self):
        return f"{settings.CASE_IDENTIFIER}{self.vuid}: {self.title}"

    vutitle = property(get_title)

    def get_vuid(self):
        return f"{settings.CASE_IDENTIFIER}{self.vuid}"

    vu_vuid = property(get_vuid)

    def __str__(self):
        return self.vuid

    def get_absolute_url(self):
        return reverse('vince:case', args=(self.id,))

    def _get_case_for_url(self):
        """ A URL-friendly ticket ID, used in links. """
        return u"VU%s" % (self.vuid)

    case_for_url = property(_get_case_for_url)

    def _get_status(self):
        """
        Displays the ticket status, with an "On Hold" message if needed.
        """
        held_msg = ''
#	if self.on_hold:
#            held_msg = _(' - On Hold')
#        dep_msg = ''
        return u'%s%s' % (self.get_status_display(), held_msg)
    get_status = property(_get_status)

    def _can_be_resolved(self):
        """
        Returns a boolean.
        True = any dependencies are resolved
        False = There are non-resolved dependencies
        """
        OPEN_STATUSES = (Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS)
        return CaseDependency.objects.filter(case=self).filter(
            depends_on__status__in=OPEN_STATUSES).count() == 0
    can_be_resolved = property(_can_be_resolved)

    def _get_assigned_to(self):
        """ Custom property to allow us to easily print 'Unassigned' if a
        case has no owner, or the users name if it's assigned. If the user
        has a full name configured, we use that, otherwise their username. """
        assignments = list(CaseAssignment.objects.filter(case=self).values_list('assigned__usersettings__preferred_username', flat=True))
        if assignments:
            return ",".join(assignments)
        else:
            return _('Unassigned')

    get_assigned_to = property(_get_assigned_to)

    def _get_status_html(self):
        changed = ""
        if self.changes_to_publish:
            changed = "<span class=\"badge warning\" title=\"Unpublished Changes\">U</span>"
        if self.status == self.ACTIVE_STATUS:
            if self.published:
                return f"<span class=\"label success\">{self.get_status_display()}</span>   <span class=\"label badge-tag-success\">Published{changed}</span>"
            return f"<span class=\"label success\">{self.get_status_display()}</span>"

        else:
            if self.published:
                return f"<span class=\"label info\">{self.get_status_display()}</span>  <span class=\"label badge-tag-success\">Published</span>"
            else:
                return f"<span class=\"label info\">{self.get_status_display()}</span>"

    get_status_html = property(_get_status_html)

    def _get_tag_html(self):
        tags = self.casetag_set.all()
        html = ""
        search_url = reverse("vince:casesearch")
        for tag in tags:
            html = html + f"<span class=\"label tkttag primary\"><a href=\"{search_url}?tag={tag}\"><i class=\"fas fa-tag\"></i> {tag}</a></span>  "
        return html

    get_tag_html = property(_get_tag_html)

    def _get_owner_html(self):
        if self.team_owner:
            return f"<span class=\"label info\">{self.team_owner.name}</span>"
        else:
            return ""

    get_owner_html = property(_get_owner_html)

    def _is_published(self):
        try:
            if self.vulnote.date_published:
                return True
        except:
            pass
        return False

    published = property(_is_published)

    def is_active(self):
        today = date.today()
        if ((today.year - self.created.year) > 0):
            return False
        return True

    def get_cves(self):
        cves = []
        for vul in self.vulnerability_set.all():
            if not(vul.deleted):
                if vul.cve:
                    cves.append(f"CVE-{vul.cve}")
        return cves

    def as_dict(self):

        url = str(self.get_absolute_url())

        #number of posts
        activity = CaseAction.objects.filter(case=self, post__isnull=False).count()

        #vendors
        vendors = VulnerableVendor.casevendors(self);
        vendors_notified = vendors.filter(contact_date__isnull=False).count()
        vendors_seen = vendors.filter(seen=True).count()

        try:
            vulnote = self.vulnote
            if vulnote:
                if vulnote.date_published:
                    vulnote = "Published " + vulnote.date_published.strftime('%Y-%m-%d')
                elif vulnote.date_shared:
                    vulnote = "Shared " + vulnote.date_shared.strftime('%Y-%m-%d')
                else:
                    vulnote = "Draft " + vulnote.modified.strftime('%Y-%m-%d')
        except:
            vulnote = "Not started"

        if self.due_date:
            due_date = self.due_date.strftime('%Y-%m-%d')
            if self.due_date < timezone.now():
                color = "error"
            else:
                color = "goodtext"
        else:
            due_date = None
            color = "warningtext"

        if self.publicdate:
            publicdate = self.publicdate.strftime('%Y-%m-%d')
            if self.publicdate < timezone.now():
                color = "warningtext"
        else:
            publicdate = None

        assignment = str(self.get_assigned_to)

        if self.modified:
            modified = self.modified.strftime('%Y-%m-%d')
        else:
            modified = self.created.strftime('%Y-%m-%d')
            
        return {
            'id': self.id,
            'vu': self.vu_vuid,
            'title': self.title,
            'url': url,
            'description': self.summary,
            'created':self.created.strftime('%Y-%m-%d'),
            'date': modified,
            'due_date':due_date,
            "date_color": color,
            'publicdate': publicdate,
            'vuls': Vulnerability.casevuls(self).count(),
            'posts': activity,
            'assigned_to': assignment,
            'vendors': vendors.count(),
            'vendors_notified': vendors_notified,
            'vendors_seen': vendors_seen,
            'vulnote':vulnote
	}

    
class CasePermissions(models.Model):

    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE,
        verbose_name=_('Case')
    )

    group = models.ForeignKey(
        Group,
	help_text=_('Group permissions'),
        on_delete=models.CASCADE
    )

    group_read = models.BooleanField(
        default=True,
        verbose_name=_('group read access'))

    group_write = models.BooleanField(
        default=True,
	verbose_name=_('group write access'))

    publish = models.BooleanField(
        default=True,
        verbose_name=_('publish permissions'))

    class Meta:
        unique_together = (('case', 'group'),)


class CaseTag(models.Model):
    """
    This is the way to classify cases
    """

    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE,
        verbose_name=_('Case'),
    )

    created = models.DateTimeField(
        auto_now_add=True
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        help_text=_('User that tagged this case.'),
        verbose_name=_('User'),
    )

    tag = models.CharField(
        max_length=50,
        help_text=_('The tag')
    )

    def __str__(self):
        return self.tag
        
class CaseAction(Action):
    """
    A CaseAction is a comment and/or change to a case.

    The title will be automatically generated at save-time based on
    what action the user took.

    """

    ACTION_TYPE = (
        (0, "Generic"),
        (1, "VinceTrack"),
        (2, "Post"),
        (3, "Message"),
        (4, "Status Change"),
        (5, "VinceComm Artifact"),
        (6, "Threads"),
        (7, "Vendor Viewed"),
        (8, "Task Activity"),
        (9, "Publish Vul Note"),
        (10, "Status Change Notify"),
        (11, "Edit Post"),
        (12, "Post Removed"),
    )

    #Actions that can be assigned or re-assigned
    ASSIGN_ACTIONS = [0,1,9]

    #Actions that can trigger an email
    EMAILABLE_ACTIONS = [0, 4, 7, 8, 9, 11, 12]

    #Actions map to email_preference_types in user preferences
    #User preferences is a pickled object in User.usersettings
    USER_ACTION_MAP = { 1: 'email_case_changes',
                        2: 'email_new_posts',
                        3: 'email_new_messages',
                        4: 'email_new_status',
                        8: 'email_tasks'}
    
    action_type = models.IntegerField(
        default=0
    )

    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE,
        verbose_name=_('Case')
    )

    vendor = models.ForeignKey(
        'VulnerableVendor',
        blank=True,
        null=True,
        help_text=_('What vendor was involved in the change?'),
        on_delete=models.CASCADE
    )

    notification = models.ForeignKey(
        'VendorNotificationContent',
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        help_text=_('What notification was sent?'),
    )

    post = models.IntegerField(
        _('VinceComm Post ID'),
        blank=True,
        null=True)

    vulnote = models.ForeignKey(
        "VulNoteRevision",
        blank=True,
        null=True,
        on_delete=models.CASCADE)

    @classmethod
    def publishactions(cls, case):
        return cls.objects.filter(
            case = case,
            action_type=9
	).order_by('-date')

    def lookup(search):
        """ Lookup a action type by a number or by a name """
        if type(search) == int:
            return next((x[1] for x in CaseAction.ACTION_TYPE if x[0] == search), None)
        else:
            return next((x[0] for x in CaseAction.ACTION_TYPE if x[1] == search), None)

#    message = models.IntegerField(
#        _('VinceComm Message ID'),
#        blank=True,
#        null=True)

    class Meta:
        ordering = ('date',)
        verbose_name = _('Case Action')
        verbose_name_plural = _('Case Actions')

    def save(self, *args, **kwargs):
        c = self.case
        c.modified = timezone.now()
        c.save()

        #send the emails
        super(CaseAction, self).save(*args, **kwargs)


class CaseMessageAction(CaseAction):
    message = models.IntegerField(
        _('VinceComm Message ID'))

    thread = models.IntegerField(
        _('VinceComm Thread ID'))

    replied = models.BooleanField(
        _('Is this a reply?'),
        default=False)


class VendorNotificationContent(models.Model):
    version = models.IntegerField(
        default=0)

    post = models.IntegerField(
        default=0,
        help_text=_('The order of the posts.')
    )
    content = models.TextField(
        help_text=_('This will be a pinned post in the vendor case view.')
    )
    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE
    )
    created = models.DateTimeField(
        auto_now_add=True
    )
    modified = models.DateTimeField(
        auto_now=True
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        help_text=_('The user that wrote the notification'))

    published = models.BooleanField(
        default=False)

    published_date = models.DateTimeField(
        blank=True,
        null=True,
        help_text=_('Datetime when the post was published')
    )


class VendorNotificationEmail(models.Model):

    subject = models.CharField(
        max_length=200,
        help_text=_('The subject of the email.'),
        )

    email_body = models.TextField(
	help_text=_('The body of the email that will be sent to vendors to notify them to login to VINCE. '),
        blank=True,
        default=settings.STANDARD_VENDOR_EMAIL,
        null=True)
    
    search_vector = SearchVectorField(null=True)
    
    class Meta:
        indexes = [ GinIndex(
            fields = ['search_vector'],
            name = 'email_gin',
        )
        ]
        



class VendorNotification(models.Model):
    vendor = models.ForeignKey(
        'VulnerableVendor',
        on_delete=models.CASCADE,
        help_text=_('The vendor notified')
    )
    emails = models.CharField(
        max_length=1000,
        help_text=_('A comma separated list of the emails that was sent this message'),
        blank=True,
        null=True
    )
    notification = models.ForeignKey(
        VendorNotificationEmail,
        on_delete=models.CASCADE,
        help_text=('The content of the message')
    )
    notify_date = models.DateTimeField(
        default=timezone.now,
        help_text=_("Date the notification was sent")
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        help_text=_('The user that notified'))


class VulnerableVendor(models.Model):
    """
    A vendor that may or may not be vulnerable to a Case.
    """

    SUB_CHOICES = (
        ('email', 'email'),
        ('kb', 'kb'),
	('manual', 'manual'),
        ('vince', 'vince'),
    )

    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE,
        help_text=_('The Case that describes this vulnerability.')
    )
    vendor = models.CharField(
        max_length=200,
        help_text=_('The name of the vendor that may be affected.')
    )
    added_to_case = models.DateTimeField(
        blank=True,
        null=True,
        help_text=_('The date that this vendor was added to the case.')
    )
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        help_text=_('The user that added this vendor to the case')
    )
    contact_date = models.DateTimeField(
        blank=True,
        null=True,
        help_text=_('The date that this vendor was first contacted about this vulnerability.')
    )
    contact = models.ForeignKey(
        Contact,
        on_delete=models.CASCADE,
        help_text=_('The formal contact information if we have it')
    )

    seen = models.BooleanField(default=False,
                               help_text=_("Has the user logged in to view vuln?"))

    references = models.TextField(
        help_text=_('Vendor references for this case'),
        blank=True,
        null=True)

    statement = models.TextField(
        help_text=_('A general vendor statement for all vuls in the case'),
        blank=True,
        null=True)

    addendum = models.TextField(
        help_text=_('Text added by coordination team about this vendor.'),
        blank=True,
        null=True)

    date_modified = models.DateTimeField(
        auto_now=True
    )

    statement_date = models.DateTimeField(
        blank=True,
        null=True)

    vendor_contact = models.ForeignKey(
        'VendorContactData',
        blank=True, null=True,
        on_delete=models.SET_NULL,
        help_text=('More information about the person that provided the statement'),
    )

    submission_type = models.CharField(max_length=15,
                                       choices=SUB_CHOICES,
                                       default="vince")

    approved = models.BooleanField(
        default=False,
        help_text=_('If all status/statements have been approved.'),
    )

    user_approved = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        help_text=_('The user that approved this request.'),
        on_delete=models.SET_NULL,
        related_name='user_approved',
        blank=True,
        null=True)

    time_approved = models.DateTimeField(
        blank=True, null=True,
        help_text=_('The time the statement was approved.'),
    )

    deleted = models.BooleanField(
        default = False,
        help_text=_('This field is only true if a vendor was removed after the vulnote was published')
    )

    share = models.BooleanField(
        default = False,
        help_text=_("Does the vendor give permission to share status/statement pre-publication"),
    )

    approve_ticket = models.OneToOneField(
        Ticket,
        on_delete=models.SET_NULL,
        help_text=_('The ticket to approve this vendor'),
        related_name='approve_vendor',
        blank=True,
        null=True
    )

    lotus_id = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text='Old Lotus notes style vendor record ID')


    tagged = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        help_text=_('Ticket dependency if vendor is tagged'),
        related_name='tagged',
        blank=True,
        null=True
    )
    
    from_group = models.ForeignKey(
        'ContactGroup',
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        help_text='If this vendor was added from a group, add it here')
    
    @classmethod
    def casevendors(cls, case):
        return cls.objects.filter(
            case = case,
            deleted=False,
        )

    def __str__(self):
        return "%s in %s" % (self.vendor, self.case.vutitle)

    def get_status(self):
        status = VendorStatus.objects.filter(vendor=self).order_by('status').first()
        if status:
            return status.get_status_display()
        else:
            return "Unknown"

    def save(self, *args, **kwargs):
        if not self.id:
            self.added_to_case = timezone.now()

        super(VulnerableVendor, self).save(*args, **kwargs)
    class Meta:
        unique_together = ('case', 'contact',)

    def as_dict(self):
        if self.contact_date:
            rm_confirm = True
            remove_link = reverse("vince:rmvendorconfirm", args=[self.id])
        else:
            rm_confirm = False
            remove_link = reverse("vince:rmvendor", args=[self.id])

        other_statement = VendorStatus.objects.filter(vendor=self).exclude(statement__isnull=True)

        if self.statement or self.references or other_statement:
            statement_link = reverse("vince:vendorstatusmodal", args=[self.id])
        else:
            statement_link = None

        if self.user_approved:
            approved = True
        else:
            approved = False

        if self.contact_date:
            contact_date =  self.contact_date.strftime('%Y-%m-%d')
        else:
            contact_date = None

        if self.statement_date:
            statement_date = self.statement_date.strftime('%Y-%m-%d')
        else:
            statement_date = None

        edit_date_url = reverse("vince:confirmvendordate", args=[self.id])
        vendor_notify_url = reverse("vince:notification", args=[self.id])

        tags = self.contact.contacttag_set.all().values_list('tag', flat=True)

        tagged = False
        if self.tagged:
            if self.tagged.status in [Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS]:
                tagged = True
        
        return {
	    'id': self.id,
            'contact_link': self.contact.get_absolute_url(),
            'contact_id': self.contact.id,
	    'vendor': self.contact.vendor_name,
	    'status': self.get_status(),
            'contact_date': contact_date,
            'seen': self.seen,
            'user_approved': approved,
            'approved': self.approved,
            'remove_link': remove_link,
            'statement': statement_link,
            'statement_date': statement_date,
            'rm_confirm': rm_confirm,
            'edit_date_url': edit_date_url,
            'vendor_notification': vendor_notify_url,
            'alert_tags': list(tags),
            'tagged': tagged,
        }

class VendorContactData(models.Model):
    org_name = models.CharField(max_length=250)
    email = models.EmailField(max_length=254)
    phone = models.CharField(max_length=50, blank=True, null=True)
    other_emails = models.CharField(max_length=1000, blank=True, null=True)
    person = models.CharField(max_length=250)
    title = models.CharField(max_length=250, blank=True, null=True)

class VendorStatusManager(models.Manager):

    def get_queryset(self):
        return super(VendorStatusManager, self).get_queryset().filter(vul__deleted=False)


class VendorStatus(models.Model):
    AFFECTED_STATUS = 1
    UNAFFECTED_STATUS = 2
    UNKNOWN_STATUS = 3

    STATUS_CHOICES = (
        (AFFECTED_STATUS, "Affected"),
        (UNAFFECTED_STATUS, "Not Affected"),
        (UNKNOWN_STATUS, "Unknown")
        )

    vendor = models.ForeignKey(
        VulnerableVendor,
        on_delete=models.CASCADE)

    vul = models.ForeignKey(
        "Vulnerability",
        on_delete=models.CASCADE)

    status = models.IntegerField(
        choices=STATUS_CHOICES,
        default = UNKNOWN_STATUS,
        help_text=_('The vendor status. Unknown until vendor says otherwise.')
    )

    user = models.CharField(
        max_length=200,
        help_text=_('The user that responded to the status request.')
        )

    date_added = models.DateTimeField(
        default=timezone.now)

    date_modified = models.DateTimeField(
        auto_now=True
    )

    references = models.TextField(
        blank=True,
        null=True)

    statement = models.TextField(
        blank=True,
        null=True)

    approved = models.BooleanField(
        default=False)

    user_approved = models.ForeignKey(
	settings.AUTH_USER_MODEL,
        help_text=_('The user that approved this request.'),
	on_delete=models.SET_NULL,
        related_name='user_approve',
        blank=True,
        null=True)

    time_approved = models.DateTimeField(
        blank=True, null=True,
        help_text=_('The time the statement was approved.'),
    )

    objects = VendorStatusManager()

    def __str__(self):
        return "Vendor " + self.vendor.contact.vendor_name + " status: " + str(self.status) + " for " + str(self.vul)

    class Meta:
        unique_together = (('vendor', 'vul'),)
        verbose_name_plural = _('Vendor Statuses')

class CaseAssignment(models.Model):
    """
    A vulnerability case may have more than one person assigned to it.
    This model handles that relationship
    """
    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE)

    assigned = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE)

    def __str__(self):
        return "%s is assigned to %s" % (self.assigned.get_username(), self.case.vu_vuid)

class CaseParticipant(models.Model):
    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE,
        help_text=_('The Case that describes this vulnerability.')
    )
    user_name = models.CharField(
        max_length=100,
        help_text=_('The name of the user.')
    )

    group = models.BooleanField(
        default=False,
        help_text=_('Is this a vendor/group?')
    )

    contact = models.ForeignKey(
        "Contact",
        help_text=_('If this is a vendor/group, then link them here'), 
        blank=True,
        null=True,
        on_delete=models.SET_NULL)

    added_to_case = models.DateTimeField(
        blank=True, null=True,
        help_text=_('The date that this user was added to the case.')
    )
    status = models.CharField(
        max_length=50,
        help_text=_('Participant status.'),
        blank=True, null=True)

    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        help_text=_('The user that added this vendor to the case')
    )

    coordinator=models.BooleanField(
        help_text=_('Is this user a vulnerability coordinator?'),
        default=False)

    def __str__(self):
        return self.user_name


    def as_dict(self):
        if self.added_to_case:
            notified = self.added_to_case.strftime('%Y-%m-%d')
        else:
            notified = None

        link = None
        if self.group:
            if self.contact:
                link = reverse("vince:contact", args=[self.contact.id])
            else:
                contact = Contact.objects.filter(vendor_name=self.user_name).first()
                if contact:
                    link = reverse("vince:contact", args=[contact.id])
        else:
            user = User.objects.using('vincecomm').filter(email__iexact=self.user_name).first()
            if user:
                link = reverse('vince:vcuser', args=[user.id])
                
        remove_link = reverse("vince:rmpartnoconfirm", args=[self.id])
        rm_confirm = False
        if self.status:
            if 'Notified' in self.status:
                remove_link = reverse("vince:rmparticipant", args=[self.id])
                rm_confirm = True

                
        if self.coordinator:
            coordinator = "Coordinator"
        else:
            coordinator = "Reporter"

        if self.contact:
            name = self.contact.vendor_name
            contact_link = self.contact.get_absolute_url()
        else:
            name = self.user_name
            contact_link = None

        seen = False
        if self.status:
            if any(x in self.status for x in ["Seen", "Lead"]):
                seen = True
            
        return {
            'id': self.id,
            'name': name,
            'link': link,
            'status': self.status,
            'seen': seen,
            'notified': notified,
            'remove_link': remove_link,
            'role': coordinator,
            'changetype': reverse("vince:partype", args=[self.id]),
            'rm_confirm': rm_confirm
        }

class Artifact(models.Model):
    """
    This is an observable or outcome as result of completing a task.
    Artifacts can be used to generate vul notes or reports.
    """
    type = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        help_text=_('The type of data, a product name, an exploit, CVSS, etc.')
    )
    title = models.CharField(
        max_length=200,
        help_text=_('A title for this value that could be used in a report or vul note.')
    )
    value = models.CharField(
        max_length=500,
        help_text=_('The artifact that you want to document.'),
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        help_text=_('The user that added this artifact.')
    )
    date_added = models.DateTimeField(
        default=timezone.now)

    date_modified = models.DateTimeField(
        auto_now=True)

    description = models.TextField(
        blank=True,
        null=True,
        help_text=_('A description of this artifact.')
    )
    added_to_note = models.BooleanField(
        default = False,
        help_text=_('If artifact has been added to vulnote'))

    added_to_post = models.BooleanField(
        default = False,
        help_text=_('If artifact has been added to vendor notification'))

    file_hash = models.CharField(
        max_length=100,
        help_text=_('The hash of the file'),
        blank=True,
        null=True)
    
    def as_dict(self):
        if self.get_related_ticket():
            tkt = self.get_related_ticket()
            ticket = tkt.get_absolute_url()
            ticket_url = tkt.ticket_for_url
            delete_url = reverse('vince:rmartifact', args=[tkt.id, self.id])
            share_url = reverse('vince:maketktpublic', args=[self.id])
        else:
            ticket = None
            ticket_url = None
            delete_url = reverse('vince:rmcase_artifact', args=[self.id])
            share_url = reverse('vince:makepublic', args=[self.id])

        if self.get_related_attachment():
            #url = self.get_related_attachment().file.url
            url = reverse('vince:attachment', args=[self.get_related_attachment().uuid])
            public = self.get_related_attachment().public
        else:
            url = None
            public = False

        return {
            'id': self.id,
            'related_ticket': ticket,
            'ticket_url': ticket_url,
            'type': self.type,
            'url': url,
            'title': self.title,
            'value': self.value,
            'public': public,
            'user': self.user.usersettings.vince_username if self.user else None,
            'date_added': self.date_added.strftime('%Y-%m-%d'),
            'date_modified': self.date_modified,
            'description': self.description,
            'added_to_note': self.added_to_note,
            'added_to_post': self.added_to_post,
            'tags': self.get_related_tags(),
            'delete_url': delete_url,
            'share_url': share_url
            }

    def get_related_case(self):
        case = CaseArtifact.objects.filter(artifact_ptr=self).first()
        if case:
            return case.case
        else:
            return None

    def get_related_ticket(self):
        ticket = TicketArtifact.objects.filter(artifact_ptr=self).first()
        if ticket:
            return ticket.ticket
        else:
            return None

    def get_related_tags(self):
        tags = ArtifactTag.objects.filter(artifact=self).values_list('tag', flat=True)
        return list(tags)


    def get_related_attachment(self):
        att = ArtifactAttachment.objects.filter(artifact=self).first()
        if att:
            return att.attachment
        else:
            return None

    def __str__(self):
        return "%s: %s" % (self.title, self.value)

class ArtifactAttachment(models.Model):
    artifact = models.ForeignKey(
        Artifact,
        on_delete=models.CASCADE,
        verbose_name=_('Artifact'),
    )
    attachment = models.ForeignKey(
        Attachment,
        on_delete=models.CASCADE)


class ArtifactTag(models.Model):
    """
    This is a tag for an artifact - something
    that can easily be searched on later.
    """
    artifact = models.ForeignKey(
        Artifact,
        on_delete=models.CASCADE)
    tag = models.CharField(
        max_length=50,
        help_text=_('A short word or phrase to identify this artifact.'))
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL)
    date_added = models.DateTimeField(
        default=timezone.now)

    def __str__(self):
        return self.tag

class TicketArtifact(Artifact):
    """
    This ties an artifact to ticket (and to a case).
    A ticket can have zero to many artifacts.
    """
    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE)

    show_ticket_info = property(True)

class CaseArtifact(Artifact):
    """
    This ties an artifact to a case.
    A case can have zero to many artifacts. Artifacts
    might belong to a case through a ticket.
    """
    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE)


class CaseTemplate(models.Model):
    title = models.CharField(
        max_length=100)
    queue = models.ForeignKey(
        TicketQueue,
        on_delete=models.CASCADE,
        verbose_name=_('Queue'),
    )
    description = models.CharField(
        max_length=200
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        help_text=_('The user that created this template.'),
        blank=True,
        null=True)

    date_modified = models.DateTimeField(
        auto_now=True
    )

    vendor_email = models.TextField(
	_('Vendor Notification Email Content'),
        help_text=_('The context available to you includes {{ vu }}, '
	            '{{ title }}, and {{ owner }}.'),
        default = settings.STANDARD_VENDOR_EMAIL
    )

    participant_email = models.TextField(
        _('Participant Notification Email Content'),
        help_text=_('The context available to you includes {{ vu }}, '
                    '{{ title }}, and {{ owner }}.'),
        default = settings.STANDARD_PARTICIPANT_EMAIL
    )

    def __str__(self):
        return self.title

    def as_dict(self):
        tasks = CaseTask.objects.filter(template=self)
        if self.user:
            user = self.user.usersettings.preferred_username
        else:
            user = None
        return {
            'id': self.id,
            'title': self.title,
            'user': user,
            'description': self.description,
            'date': self.date_modified.strftime('%Y-%m-%d'),
            'tasks': len(tasks),
            'queue': self.queue.title}



class CaseTask(models.Model):
    template = models.ForeignKey(
        CaseTemplate,
        on_delete=models.CASCADE
    )

    task_title = models.CharField(
        _('Title'),
        max_length=200,
    )
    task_description = models.TextField(
        _('Description'),
        blank=True,
        null=True,
    )
    task_priority = models.IntegerField(
        _('Priority'),
        choices=Ticket.PRIORITY_CHOICES,
	default=3,
        help_text=_('1 = Highest Priority, 5 = Low Priority')
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
    )

    time_to_complete = models.DurationField(
        _('Time to complete'),
        default = timedelta(days=5)
    )

    dependency = models.BooleanField(
        default = False,
        help_text=_("Ticket will be created as a dependency of the case."))

    def as_dict(self):
        if self.assigned_to:
            user = self.assigned_to.usersettings.preferred_username
        else:
            user = None
        return {
            'id': self.id,
            'title': self.task_title,
            'user': user,
            'priority': self.task_priority,
            'description': self.task_description,
            'time': str(self.time_to_complete),
            'dependency': self.dependency
        }

class VulnerabilityManager(models.Manager):
    def search(self, query=None):
        qs = self.get_queryset()
        if query is not None:
            if re.match('cve-', query, re.I):
                query = query[4:]
            qs = qs.extra(where=["search_vector @@ (to_tsquery('english', %s))=true"],params=[query])
            #or_lookup = (Q(cve__icontains=query) |
            #             Q(description__icontains=query)|
            #             Q(vulcwe__cwe__icontains=query)
            #)
            #qs = qs.filter(or_lookup).distinct()
        return qs

class Vulnerability(models.Model):
    cve = models.CharField(
        _('CVE'),
        max_length=50,
        blank=True,
        null=True)

    description = models.TextField(
        _('Description'))

    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL)

    date_added = models.DateTimeField(
        default=timezone.now)

    modified = models.DateTimeField(
        auto_now=True
    )

    ask_vendor_status = models.BooleanField(
        default=False)

    deleted = models.BooleanField(
        default=False,
        help_text=_('Only present if a vulnerability is deleted after a case has been published.'))

    added_to_note = models.BooleanField(
        default=False)

    added_to_post = models.BooleanField(
        default	= False,
	help_text=_('If artifact has been added to vendor notification'))

    case_increment = models.IntegerField(
        default = 0)

    objects = VulnerabilityManager()

    search_vector = SearchVectorField(null=True)

    class Meta:
        indexes = [GinIndex(
            fields=['search_vector'],
            name= 'vulnerability_gin',
        )
        ]

    @classmethod
    def casevuls(cls, case):
        return cls.objects.filter(
            case = case,
            deleted=False,
        )

        def __str__(self):
            return self.vul


    def __str__(self):
        return "%s" % self.vul

    def _get_vul(self):
        """ A user-friendly Vul ID, which is the cve if cve exists,
        otherwise it's a combination of vul ID and case. """
        if (self.cve):
            return u"CVE-%s" % self.cve
        else:
            return u"%s" % (self.cert_id)
    vul = property(_get_vul)

    def as_dict(self):
        cwes = []
        for cwe in self.vulcwe_set.all():
            cwes.append(cwe.cwe)
        remove_link = reverse('vince:rmvul', args=[self.case.id, self.id])
        cveallocation = CVEAllocation.objects.filter(vul=self).first()
        if cveallocation:
            if cveallocation.cwe:
                cwes.clear()
                for x in json.loads(cveallocation.cwe):
                    cwe = x.split(" ", 1)
                    cwes.append(cwe[0])
        exploits = VulExploit.objects.filter(vul=self).count()
        edit_link = reverse("vince:editvul", args=[self.id])
        if cveallocation:
            if cveallocation.cveaffectedproduct_set.count():
                #only provide download link if all info is provided
                cveallocation = cveallocation.id
            else:
                cveallocation = None
        tags = list(self.vulnerabilitytag_set.values_list('tag', flat=True))
        return {
            'id': self.id,
            'cert_id': self.cert_id,
	    'ask_vendor_status': self.ask_vendor_status,
            'description': self.description,
            'cve': self.cve,
            'cveallocation':cveallocation,
            'exploits': exploits,
            'cwe': cwes,
            'date_added': self.date_added.strftime('%Y-%m-%d'),
            'remove_link': remove_link,
            'edit_link': edit_link,
            'tags': tags,
        }

    def _get_tag_html(self):
        tags = self.vulnerabilitytag_set.all()
        html = ""
        search_url = reverse("vince:search")
        for tag in tags:
            html = html + f"<span class=\"label tkttag primary\"><a href=\"{search_url}?q={tag}&facet=Vuls\"><i class=\"fas fa-tag\"></i> {tag}</a></span>  "
        return html

    get_tag_html = property(_get_tag_html)
    
    def _get_uid(self):
        """ A user-friendly Vul ID, which is the cve if cve exists,
        otherwise it's a combination of vul ID and case. """
        if (self.cve):
            return u"CVE-%s" % self.cve
        else:
            return u"%s" % (self.cert_id)
    uid = property(_get_uid)

    def _get_vul_for_url(self):
        """ A URL-friendly vul ID, used in links. """
        return u"%s" % (self.vul)
    vul_for_url = property(_get_vul_for_url)

    def get_absolute_url(self):
        return reverse('vince:vul', args=(self.id,))    
    
    def _get_cert_id(self):
        return u"%s.%d" % (self.case.vu_vuid, self.case_increment)

    cert_id = property(_get_cert_id)


class VulnerabilityTag(models.Model):
    """
    This is the way to classify vulnerabilities.
    """

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        verbose_name=_('Vulnerability'),
    )

    created = models.DateTimeField(
        auto_now_add=True
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        help_text=_('User that created this tag.'),
        verbose_name=_('User'),
    )

    tag = models.CharField(
        max_length=50,
        help_text=_('The tag')
    )

    def __str__(self):
        return self.tag

    
class VulCVSS(models.Model):
    vul = models.OneToOneField(
        Vulnerability,
        on_delete=models.CASCADE)

    AV = models.CharField(
        _('Attack Vector'),
        max_length=2)

    AC = models.CharField(
        _('Attack Complexity'),
        max_length=2)

    PR = models.CharField(
        _('Privileges Required'),
        max_length=2)

    UI = models.CharField(
        _('User Interaction'),
        max_length=2)

    S = models.CharField(
        _('Scope'),
        max_length=2)

    C = models.CharField(
        _('Confidentiality'),
        max_length=2)

    I = models.CharField(
        _('Integrity'),
        max_length=2)

    A = models.CharField(
        _('Availability'),
        max_length=2)

    #Temporal metrics - X if not defined

    E = models.CharField(
        _('Exploit Code Maturity'),
        default='X',
        max_length=2)

    RL = models.CharField(
        _('Remediation Level'),
        default='X',
        max_length=2)

    RC = models.CharField(
        _('Report Confidence'),
        default='X',
        max_length=2)
    
    scored_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        verbose_name=_('User'),
    )

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

    
    
class VulSSVC(models.Model):
    
    EXPLOIT_STATE_CHOICES = ((0, 'Undecided'),
                             (1, 'POC'),
                             (2, 'Active'))


    EXPLOIT_VALUE_CHOICES = ((0, 'Undecided'),
                             (1, 'diffuse'),
                             (2, 'concentrated'))

    EXPLOIT_TECHIMPACT_CHOICES = ((0, 'Undecided'),
                                  (1, 'Partial'),
                                  (2, 'Total'))
    
    
    vul = models.OneToOneField(
        Vulnerability,
        on_delete=models.CASCADE)
    
    state = models.IntegerField(
        choices=EXPLOIT_STATE_CHOICES,
        default=0)

    automatable = models.BooleanField(
        default=False)

    value_density = models.IntegerField(
        choices=EXPLOIT_VALUE_CHOICES,
        default = 0)

    technical_impact = models.IntegerField(
        choices=EXPLOIT_TECHIMPACT_CHOICES,
        default = 0)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
	null=True,
        verbose_name=_('User'),
    )

    last_edit = models.DateTimeField(
        _('Last Modified Date'),
        default=timezone.now)
    
    decision = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    
    json_file = OldJSONField(
	_('SSVC JSON File'),
        blank=True,
        null=True) 
    
    def _get_utility(self):
        if self.automatable:
            if self.value_density==1:
                return "laborious"
            elif self.value_density==2:
                return "efficient"
        else:
            if self.value_density==1:
                return "efficient"
            elif self.value_density==2:
                return "super effective"
        return "undefined"

    utility = property(_get_utility)
    
    def __str__(self):
        state_dict = dict(EXPLOIT_STATE_CHOICES)
        return f"SSVCv2/E:{state_dict[self.state][0]}:"
    
class VulCWE(models.Model):
    cwe = models.CharField(
        _('CWE'),
        max_length=20,
    )

    vul = models.ForeignKey(
        Vulnerability,
        on_delete = models.CASCADE)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL)

    date_added = models.DateTimeField(
        default=timezone.now)

    def __str__(self):
        return "CWE-%d" % self.cwe


class VulExploit(models.Model):

    EXPLOIT_CHOICES = (('code', 'code'),
                       ('report', 'report'),
                       ('other', 'other')
                       )

    vul = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL)

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

    share = models.BooleanField(
        default=False)

    publish = models.BooleanField(
        default=False)

    def __str__(self):
        return "%s" % self.link
    
    
class VinceSQS(models.Model):

    VRF_FORM = 1
    VENDOR_STMT = 2
    GOV_REPORT = 3

    FORM_CHOICES = (
        (VRF_FORM, 'VRF'),
        (VENDOR_STMT, 'Vendor Statement'),
        (GOV_REPORT, 'Gov Report'),
    )

    date_polled = models.DateTimeField(
        default=timezone.now)

    title = models.CharField(
        max_length=200)

    date_submitted = models.DateTimeField(
        default=timezone.now)

    vrf_id = models.CharField(
        max_length=20)

    read = models.BooleanField(
        default = False)

    receipt_handle = models.CharField(
        max_length=500,
        blank=True,
        null=True)

    deleted_from_queue = models.BooleanField(
        default = False)

    report_type = models.IntegerField(
	_('Report Type'),
        choices=FORM_CHOICES,
        default=VRF_FORM,
    )
    #Name of file if submitter attached file
    attached_file = models.CharField(
        max_length=250,
        blank=True,
        null=True
    )

class CVEAllocation(models.Model):
    CVE_DISCOVERY_CHOICES = (
        (1, _('INTERNAL')),
        (2, _('EXTERNAL')),
        (3, _('USER')),
        (4, _('UNKNOWN')),
    )

    title = models.CharField(
        _('Title'),
        blank=True,
        null=True,
        max_length=200)

    assigner = models.EmailField(
        max_length=254,
        default='cert@cert.org')

    cve_name = models.CharField(
        _('CVE ID'),
        max_length=200)

    cve_changes_to_publish = models.BooleanField(
        default = True,
        help_text=_('Switch to True if changes affected already published cve')
    )
    
    references = OldJSONField(
        _('References'),
        blank=True,
        null=True)

    source = models.IntegerField(
        blank=True,
        null=True,
        choices=CVE_DISCOVERY_CHOICES)

    description = models.TextField(
        _('Description'))

    work_around = OldJSONField(
        _('Workaround'),
        blank=True,
        null=True)
    resolution = models.CharField(
        _('Resolution'),
        max_length=500,
        blank=True,
        null=True)
    credit = models.CharField(
        _('Credit'),
        max_length=500,
        blank=True,
        null=True)
    cwe = OldJSONField(
        _('CWE'),
        blank=True,
        null=True)
    vul = models.OneToOneField(
        Vulnerability,
        blank=True,
        null=True,
        on_delete=models.SET_NULL)
    date_added = models.DateTimeField(
        default=timezone.now,
        blank=True,
        null=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
	blank=True,
        null=True,
        on_delete=models.SET_NULL)

    modified = models.DateTimeField(
        auto_now=True
    )

    date_public = models.DateTimeField(
        _('Date Public'),
        blank=True, null=True)

    search_vector = SearchVectorField(null=True)

    class Meta:
        indexes = [GinIndex(
            fields=['search_vector'],
            name= 'cve_gin',
        )
        ]
    def __str__(self):
        return self.cve_name

    def complete(self):
        if self.references and self.cwe:
            refs = json.loads(self.references)
            cwes = json.loads(self.cwe)
        else:
            return False
        if self.cve_name and self.date_public and len(refs) and len(cwes):
            return True
        else:
            return False

class CVEAffectedProduct(models.Model):
    cve = models.ForeignKey(
        CVEAllocation,
        on_delete=models.CASCADE)

    name = models.CharField(
        _('Affected Product Name'),
        max_length=200)

    version_name = models.CharField(
        _('Version Range End'),
        blank=True,
        null=True,
        max_length=100)

    version_affected = models.CharField(
        _('Version Range Type'),
        blank=True,
        null=True,
        max_length=25)
    
    version_value = models.CharField(
        _('Affected Version or Start'),
        max_length=100)

    organization = models.CharField(
        _('Affected Organization'),
        max_length=100,
        blank=True,
        null=True)

class VendorProduct(models.Model):
    """
    Store Vendor Product information. 
    """
    
    name = models.CharField(
    _('Product Name'),
    max_length=200)

    organization = models.ForeignKey(
        Contact,
        on_delete=models.CASCADE,
        blank=False,
        null=False)
    
    sector = ArrayField( models.CharField( max_length = 50 ), blank = True, null = True )
    
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    class Meta:
        unique_together = (('name', 'organization'),)

    def save(self, *args, **kwargs):
        if VendorProduct.objects.filter(organization=self.organization,
                                        name__iexact=self.name):
            logger.debug(f"Ignoring duplicate VendorProduct {self.name}")
            return
        return super(VendorProduct, self).save(*args, **kwargs)
        
    
class ProductVersion(models.Model):
    """
    Stores Product Version information. Links to cve and vendorproduct tables.
    """

    cve = models.ForeignKey(
        CVEAllocation,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)

    product = models.ForeignKey(
        VendorProduct,
        on_delete=models.CASCADE,
        blank=False,
        null=False)

    version_name = models.CharField(
        _('Version'),
        blank=True,
        null=True,
        max_length=100)

    version_affected = models.CharField(
        _('Version Affected'),
        blank=True,
        null=True,
        max_length=25)

    version_value = models.CharField(
        _('Version Value'),
        blank=True,
        null=True,
        max_length=100)

    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)

    cve_affected_product = models.ForeignKey(
        CVEAffectedProduct,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)
    
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

class CVEReservation(models.Model):

    cve_info = models.OneToOneField(
        CVEAllocation,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)

    cve_id = models.CharField(
        max_length=50)

    time_reserved = models.DateTimeField(
        default=timezone.now)

    account = models.ForeignKey(
        "CVEServicesAccount",
        on_delete = models.SET_NULL,
        blank=True,
        null=True)

    user_reserved = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete = models.SET_NULL)

    def __str__(self):
        return self.cve_id

    def as_dict(self):
        if self.cve_info:
            vul = reverse("vince:vul", args=[self.cve_info.vul.id])
            case = self.cve_info.vul.case.vu_vuid
        else:
            vul = None
            case =None
        if self.user_reserved:
            user = self.user_reserved.usersettings.preferred_username
        else:
            user = "Unknown"
        return {
            'cve_id': self.cve_id,
            'state': 'RESERVED',
            'vul': vul,
            'case': case,
            'user': user,
            'cve_link': reverse("vince:detailedcve", args=[self.account.id, self.cve_id]),
            'reserved':self.time_reserved.strftime('%Y-%m-%d'),
        }

class AdminPGPEmail(models.Model):
    pgp_key_data = models.TextField()

    pgp_key_id = models.CharField(
        max_length=200)

    email = models.CharField(
        _('Email(s)'),
        help_text=_('Multiple emails should be separated by a comma and space'),
        max_length=254)

    name = models.CharField(
        max_length=200, blank=True, null=True)

    user_added = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True, null=True)

    active = models.BooleanField(
        default = True)

    def __str__(self):
        return self.pgp_key_id


class UserSettings(models.Model):
    """
    A bunch of user-specific settings that we want to be able to define, such
    as notification preferences and other things that should probably be
    configurable.
    We should always refer to user.usersettings.settings['setting_name'].
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="usersettings")

    settings_pickled = models.TextField(
        _('Settings Dictionary'),
        help_text=_('This is a base64-encoded representation of a pickled Python dictionary. '
                    'Do not change this field via the admin.'),
        blank=True,
        null=True,
    )

    org = models.CharField(
        max_length=250,
        blank=True,
        null=True)

    preferred_username = models.CharField(
	max_length=250,
	blank=True,
	null=True)

    triage = models.BooleanField(
        default=False)


    case_template = models.ForeignKey(
        CaseTemplate,
        help_text=_('The default template to use when creating cases'),
        blank=True,
        null=True,
        on_delete=models.SET_NULL
    )

    #these permissions are initially inherited from the group,
    #but supersedes group permissions
    contacts_read = models.BooleanField(
        help_text=_('Does this user have permissions to read VINCE contacts'),
        default=True)

    contacts_write = models.BooleanField(
        help_text=_('Does this user have permissions to add/edit VINCE contacts'),
        default=True)
    
    def _set_settings(self, data):
        # data should always be a Python dictionary.
        if not isinstance(data,dict):
            logger.warn("Non dictionary item sent to pickle %s" % str(data))
            data = {}        
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
        class RestrictedUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                """ If find_class gets called then return error """
                raise pickle.UnpicklingError("global '%s.%s' is forbidden" %
                                             (module, name))
        try:
            from base64 import decodebytes as b64decode
            if self.settings_pickled:
                s = b64decode(self.settings_pickled.encode('utf-8'))
                #replacement for pickle.loads()
                return RestrictedUnpickler(io.BytesIO(s)).load()
            else:
                return {}
        except (pickle.UnpicklingError, AttributeError) as e:
            logger.warn("Error when trying to unpickle data %s " %(str(e)))
            return {}
        except Exception as e:
            logger.warn("Generic error when trying to unpickle data %s " %(str(e)))
            return {}

    settings = property(_get_settings, _set_settings)

    def _get_vince_username(self):
        if self.preferred_username:
            return self.preferred_username
        else:
            return self.user.get_full_name()

    vince_username = property(_get_vince_username)

    def __str__(self):
        return 'Preferences for %s' % self.user

    class Meta:
        verbose_name = _('User Setting')
        verbose_name_plural = _('User Settings')


class UserRole(models.Model):

    role = models.CharField(
        max_length=200)

    
    group = models.ForeignKey(
        Group,
        blank=True, null=True,
        help_text=_('Not required, but if left blank, will be a global role.'),
        on_delete=models.CASCADE)
    
    def __str__(self):
        return self.role


class UserAssignmentWeight(models.Model):
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="assignment")

    role = models.ForeignKey(
        UserRole,
        on_delete=models.CASCADE)
    
    weight = models.IntegerField(
        )

    current_weight = models.IntegerField(
        default = 0)

    effective_weight = models.IntegerField(
        )

    def save(self, *args, **kwargs):

        #  set effective weight to weight if new object
        if self.pk is None:
            self.effective_weight = self.weight

        return super(UserAssignmentWeight, self).save(*args, **kwargs)    

    def _get_probability(self):
        #get all weights of this role
        weight_sum = UserAssignmentWeight.objects.filter(role=self.role).aggregate(models.Sum('weight'))
        return self.weight/weight_sum['weight__sum'] * 100

    probability = property(_get_probability)
    
    class Meta:
        unique_together = (('user', 'role'),)
    
class VinceFile(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)

    case = models.ForeignKey(
        VulnerabilityCase,
	on_delete=models.SET_NULL,
        verbose_name=_('Case'),
        blank=True,
        null=True
    )

    #if false, probably added to a post
    vulnote = models.BooleanField(
        default = False)

    filename = models.CharField(
        max_length=500,
        default="filename"
    )

    post = models.ForeignKey(
	'VendorNotificationContent',
        blank=True,
        null=True,
        on_delete = models.CASCADE,
        help_text=_('Post file was added to.'),
    )
    
    to_remove = models.BooleanField(
        default=False)
    
    comm_id = models.IntegerField(
	_('VinceComm VinceTrackAttachment ID'),
        default=0)


class CognitoUserAction(Action):

    email = models.EmailField(
        max_length=254,
        help_text=_('The email address of the cognito user')
    )

class VinceSMIMECertificate(models.Model):
    email = models.EmailField(
        max_length=254,
        help_text=_('The email that belongs to the certificate')
    )

    certificate = models.FileField(
        _('Certificate'),
        storage=PrivateMediaStorage(location="certs"),
    )

    def __str__(self):
        return "%s" % self.email

    
class VinceEmail(models.Model):

    REGULAR = 1
    PGP = 2
    SMIME = 3

    EMAIL_TYPE = (
    (REGULAR, 'Regular'),
    (PGP, 'PgP'),
    (SMIME, 'S/MIME'),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        help_text=('The user that is sending the email.'),
        blank=True,
        null=True)

    notification = models.ForeignKey(
        VendorNotificationEmail,
        on_delete=models.CASCADE,
        help_text=('The subject/content of the message')
    )

    to = models.CharField(
        max_length=1000,
        help_text=('The email address(es).  Multiple emails should be separated by a comma.')
    )

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.SET_NULL,
        verbose_name=_('Ticket'),
        blank=True,
        null=True
    )

    pgp_key_id = models.CharField(
        max_length=500,
        blank=True,
        null=True)
    
    email_type = models.IntegerField(choices=EMAIL_TYPE, default=REGULAR)

    certificate = models.ForeignKey(
        VinceSMIMECertificate,
        on_delete = models.SET_NULL,
        blank=True,
        null=True
    )

    created = models.DateTimeField(default=timezone.now)

    
class MFAResetTicket(models.Model):

    user_id = models.IntegerField(
        help_text=_('The vincecomm user that requested the reset'),
    )

    ticket = models.ForeignKey(
        Ticket,
        on_delete = models.CASCADE,
        help_text=_('The ticket used for mfa tracking')
    )

    created = models.DateTimeField(
        default=timezone.now)
    

class CalendarEvent(models.Model):

    TRIAGE = 1
    OOF = 2

    EVENT_CHOICES = (
        (TRIAGE, _('Triage')),
        (OOF, _('Out of Office'))
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="assigned",
        on_delete=models.CASCADE
    )

    user_added = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="user_added",
        blank=True,
        null=True)

    created = models.DateTimeField(
        default=timezone.now)

    date = models.DateTimeField()

    end_date = models.DateTimeField(
        blank=True,
        null=True)
    
    title = models.CharField(
        _('Event Title'),
        max_length=200)

    event_id = models.IntegerField(
        choices=EVENT_CHOICES,
        default=TRIAGE
    )

    def as_dict(self):
        if self.event_id == 1:
            class_name = "triage_event"
        else:
            class_name = "oof_event"

        if self.end_date:
            end = self.end_date.strftime('%Y-%m-%d')
        else:
            end = self.date.strftime('%Y-%m-%d')
        return {
            'id': self.id,
	    'title': self.title,
            'start': self.date.strftime('%Y-%m-%d'),
            'end': end,
            'allDay': True,
            'className': class_name
        }



#action types - this corresponds with action type in CaseAction
# 1 - case change
# 2 - new post
# 3 - message ticket/reply
# 4 - vendor status update
# 8 - new case tasks (emails, bounces, tasks)
# 5 - reopened cases tasks
   
class VTDailyNotification(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE)

    action = models.ForeignKey(
        CaseAction,
        blank=True,
        null=True,
        on_delete=models.CASCADE)

    followup = models.ForeignKey(
        FollowUp,
        blank=True,
        null=True,
        on_delete=models.CASCADE)
    
    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE,
    )
    
    action_type = models.IntegerField()

    
class VinceReminder(models.Model):

    RECURRENCE_CHOICES = (
        (0, 'None'),
        (1, 'Daily'),
        (7, 'Weekly'),
        (14, 'Biweekly'),
        (28, 'Monthly'),
    )
    
    alert_date = models.DateTimeField()


    title = models.CharField(
        max_length=1000)
    
    case = models.ForeignKey(
        VulnerabilityCase,
        on_delete=models.CASCADE,
        blank=True,
        null=True
    )

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        blank=True,
        null=True)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
	on_delete=models.CASCADE)


    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name=_('created_by'),
        on_delete=models.SET_NULL,
        blank=True,
        null=True)

    created = models.DateTimeField(
        default=timezone.now)

    create_ticket = models.BooleanField(
        help_text=_('Create a new ticket on a future date'),
        default = False)

    frequency = models.IntegerField(
        help_text=_('Recurrence of Reminder'),
        choices=RECURRENCE_CHOICES,
        default = 0)

    def __str__(self):
        return self.title

    

class TagManager(models.Model):

    TAG_TYPE_CHOICES = (
        (1, _('Ticket')),
        (2, _('Contact')),
        (3, _('Case')),
        (4, _('Vulnerability'))
    )

    tag_type = models.IntegerField(
	_('Tag Type'),
        choices=TAG_TYPE_CHOICES,
        default=1,
    )
    
    created = models.DateTimeField(
	auto_now_add=True
    )

    user = models.ForeignKey(
	settings.AUTH_USER_MODEL,
	on_delete=models.CASCADE,
	blank=True,
	null=True,
	help_text=_('User that created this tag.'),
	verbose_name=_('User'),
    )

    tag = models.CharField(
	max_length=50,
	help_text=_('The tag')
    )

    alert_on_add = models.BooleanField(
        default=False,
        help_text=_('Alert user when adding this tag'),
    )

    description = models.CharField(
        max_length=300,
        help_text=_('Description of tag')
    )

    #If this tag is team-specific, set it here:     
    team = models.ForeignKey(
        Group,
        blank=True,
        null=True,
        help_text=_('Team Tag, otherwise global'),
        on_delete=models.CASCADE
    )

    
class CWEDescriptions(models.Model):

    cwe = models.CharField(
        max_length=1000,
    )
    
class CVEServicesAccount(models.Model):

    team = models.ForeignKey(
        Group,
        help_text=_('VINCE Team'),
	on_delete=models.CASCADE
    )

    org_name = models.CharField(
        _('Organization'),
        max_length=200,
        help_text=_('Organization registered with CVE Services'),
    )
    
    api_key = models.CharField(
        _('API Key'),
        max_length=100,
        help_text=_('API Key'),
    )
    
    email = models.EmailField(
	_('Email'),
	help_text=_('Email associated with the account'),
    )

    first_name = models.CharField(
        max_length=100,
        blank=True,
        null=True)

    last_name = models.CharField(
        max_length=100,
        blank=True,
        null=True)

    active = models.BooleanField(
        default=True)


class BounceEmailNotification(models.Model):

    TRANSIENT=0
    PERMANENT=1
    
    BOUNCE_CHOICES = (
        (TRANSIENT, _('Transient')),
        (PERMANENT, _('Permanent'))
    )
    
    email = models.CharField(
        max_length=320)

    user_id = models.IntegerField(
        blank=True,
        null=True)

    bounce_date = models.DateTimeField(
        default=timezone.now)

    bounce_type = models.IntegerField(
        _('Bounce Type'),
        choices=BOUNCE_CHOICES,
        default=TRANSIENT
    )
    
    subject = models.TextField(
        blank=True,
        null=True)

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.SET_NULL,
        blank=True,
        null=True)

    action_taken = models.BooleanField(
        default = False)

    
