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
from __future__ import unicode_literals
from django.db import models
from django.utils import timezone
from django.contrib.postgres import fields
from bakery.models import BuildableModel
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from bigvince.storage_backends import VRFReportsStorage
from django.conf import settings
#Django 3 and up
from django.db.models import JSONField

class OldJSONField(JSONField):
    """ This was due to legacy support in Django 2.2. from_db_value
    should be explicitily sepcified when extending JSONField """

    def db_type(self, connection):
        return 'json'

    def from_db_value(self, value, expression, connection):
        return value

class VUReportManager(models.Manager):

    def get_queryset(self):
        return super(VUReportManager, self).get_queryset().filter(publish=True)
    
# Create your models here.
class VUReport(BuildableModel):
    detail_views = ('vincepub.views.VUDetailView',)
    vuid = models.CharField(max_length=50, unique=True)
    idnumber = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=500)
    keywords = OldJSONField(blank=True, null=True)
    overview = models.TextField(blank=True, null=True)
    clean_desc = models.TextField(blank=True, null=True)
    impact = models.TextField(blank=True, null=True)
    resolution = models.TextField(blank=True, null=True)
    workarounds = models.TextField(blank=True, null=True)
    sysaffected = models.TextField(blank=True, null=True)
    thanks = models.TextField(blank=True, null=True)
    author = models.CharField(max_length=500, blank=True, null=True)
    public = OldJSONField(blank=True, null=True)
    cveids = OldJSONField(blank=True, null=True)
    certadvisory = OldJSONField(blank=True, null=True)
    uscerttechnicalalert = models.TextField(blank=True, null=True)
    vulnerabilitycount = models.IntegerField(blank=True, null=True)
    datecreated = models.DateTimeField(default = timezone.now)
    publicdate = models.DateTimeField(null=True, blank=True)
    publish = models.BooleanField(default=True)
    datefirstpublished = models.DateTimeField(null=True, blank=True)
    dateupdated = models.DateTimeField(blank=True, null=True)
    revision = models.IntegerField(default = 1)
    vrda_d1_directreport = models.CharField(max_length=10, blank=True, null=True)
    vrda_d1_population = models.CharField(max_length=10, blank=True, null=True)
    vrda_d1_impact = models.CharField(max_length=10, blank=True, null=True)
    cam_widelyknown = models.CharField(max_length=15, blank=True, null=True)
    cam_exploitation = models.CharField(max_length=15, blank=True, null=True)
    cam_internetinfrastructure = models.CharField(max_length=15, blank=True, null=True)
    cam_population = models.CharField(max_length=15, blank=True, null=True)
    cam_impact = models.CharField(max_length=15, blank=True, null=True)
    cam_easeofexploitation = models.CharField(max_length=15, blank=True, null=True)
    cam_attackeraccessrequired = models.CharField(max_length=15, blank=True, null=True)
    cam_scorecurrent = models.CharField(max_length=15, blank=True, null=True)
    cam_scorecurrentwidelyknown = models.CharField(max_length=15, blank=True, null=True)
    cam_scorecurrentwidelyknownexploited = models.CharField(max_length=15, blank=True, null=True)
    ipprotocol = models.CharField(max_length=50, blank=True, null=True)
    cvss_accessvector = models.TextField(blank=True, null=True)
    cvss_accesscomplexity = models.TextField(blank=True, null=True)
    cvss_authentication = models.TextField(blank=True, null=True)
    cvss_confidentialityimpact = models.TextField(blank=True, null=True)
    cvss_integrityimpact = models.TextField(blank=True, null=True)
    cvss_availabilityimpact = models.TextField(blank=True, null=True)
    cvss_exploitablity = models.TextField(blank=True, null=True)
    cvss_remediationlevel = models.TextField(blank=True, null=True)
    cvss_reportconfidence = models.TextField(blank=True, null=True)
    cvss_collateraldamagepotential = models.TextField(blank=True, null=True)
    cvss_targetdistribution = models.TextField(blank=True, null=True)
    cvss_securityrequirementscr = models.TextField(blank=True, null=True)
    cvss_securityrequirementsir = models.TextField(blank=True, null=True)
    cvss_securityrequirementsar = models.TextField(blank=True, null=True)
    cvss_basescore = models.TextField(blank=True, null=True)
    cvss_basevector = models.TextField(blank=True, null=True)
    cvss_temporalscore = models.TextField(blank=True, null=True)
    cvss_temporalvector = models.TextField(blank=True, null=True)
    cvss_environmentalscore = models.TextField(blank=True, null=True)
    cvss_environmentalvector = models.TextField(blank=True, null=True)
    metric = models.FloatField(blank=True, null=True)
    keywords_str = models.TextField(blank=True, null=True)
    cve_str = models.TextField(blank=True, null=True)
    vulnote = models.OneToOneField(
        'VulnerabilityNote',
        blank=True, null=True,
        help_text=('This is used for VINCE published Vul Notes'),
        on_delete=models.CASCADE)
    
    search_vector = SearchVectorField(null=True)

    objects = VUReportManager()
    
    def __str__(self):
        return self.vuid

    def get_absolute_url(self):
        return '/%s' % self.idnumber

    class Meta:
        indexes = [ GinIndex(
            fields = ['search_vector'],
            name = 'vul_gin',
            )
        ]

#These next 3 models are old-style vul notes pre-VINCE

class VendorRecord(models.Model):
    vuid = models.CharField(max_length=20)
    idnumber = models.CharField(max_length=20)
    vendorrecordid = models.CharField(max_length=50)
    vendor = models.CharField(max_length=100)
    status = models.CharField(max_length=100, blank=True, null=True)
    statement = models.TextField(blank=True, null=True)
    vendorinformation = models.TextField(blank=True, null=True)
    vendorurls = OldJSONField(blank=True, null=True)
    addendum = models.TextField(blank=True, null=True)
    datenotified = models.DateTimeField(blank=True, null=True)
    dateresponded = models.DateTimeField(blank=True, null=True)
    datelastupdated = models.DateTimeField(blank=True, null=True)
    revision = models.IntegerField(default=1)

    def __str__(self):
        return "%s: %s" % (self.vuid, self.vendor)

class VendorHTML(models.Model):
    vuid = models.CharField(max_length=20)
    idnumber = models.CharField(max_length=20)
    vendorrecordid = models.CharField(max_length=50)
    statement = models.TextField(blank=True, null=True)
    information = models.TextField(blank=True, null=True)
    urls = models.TextField(blank=True, null=True)
    addendum = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.vendorrecordid
    
class VUReportHTML(models.Model):
    vuid = models.CharField(max_length=50)
    description = models.TextField(blank=True, null=True)
    impact = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    systems = models.TextField(blank=True, null=True)
    overview = models.TextField(blank=True, null=True)
    ack = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.vuid

def gov_update_filename(instance, filename):
    if instance.vrf_id:
        new_filename = "gov_vrf%s_%s" % (instance.vrf_id, filename)
    else:
        new_filename= "gov_novrf_%s" % filename

    return new_filename
    
class PrivateDocument(models.Model):
    uploaded_at = models.DateTimeField(auto_now_add=True)
    upload = models.FileField(storage=VRFReportsStorage())


def update_filename(instance, filename):
    if instance.vrf_id:
        new_filename = "vrf%s_%s" % (instance.vrf_id, filename)
    else:
        new_filename= "novrf_%s" % filename

    return new_filename


class VulCoordRequest(models.Model):
    contact_name = models.CharField(max_length=100)
    contact_org = models.CharField(max_length=100, blank=True, null=True)
    contact_email = models.EmailField(max_length=254, blank=True, null=True)
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    share_release = models.BooleanField(default=True)
    credit_release = models.BooleanField(default=True)
    coord_status = models.CharField(max_length=100)
    vendor_name = models.CharField(max_length=100)
    multiplevendors = models.BooleanField()
    other_vendors = models.TextField(blank=True, null=True)
    first_contact = models.DateTimeField(blank=True, null=True)
    vendor_communication = models.TextField(blank=True, null=True)
    product_name = models.CharField(max_length=100)
    product_version = models.CharField(max_length=100)
    ics_impact = models.BooleanField(default=False)
    vul_description = models.TextField()
    vul_exploit = models.TextField()
    vul_impact = models.TextField()
    vul_discovery = models.TextField()
    vul_public = models.BooleanField(default=False)
    public_references = models.CharField(max_length=1000, blank=True, null=True)
    vul_exploited = models.BooleanField(default=False)
    exploit_references = models.CharField(max_length=1000, blank=True, null=True)
    vul_disclose = models.BooleanField(default=False)
    disclosure_plans = models.CharField(max_length=1000, blank=True, null=True)
    user_file = models.FileField(blank=True, null=True, storage=VRFReportsStorage(), upload_to=update_filename)
    tracking = models.CharField(max_length=100,blank=True, null=True)
    comments = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.id

    
class VulnerabilityNote(models.Model):
     # This is where the content goes, with whatever markup language is used
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
        auto_now_add=True)

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
        return "{settings.CASE_IDENTIFER}{self.vuid}"

    vu_vuid = property(get_vuid)

    def _get_idnumber(self):
        return self.vuid

    idnumber = property(_get_idnumber)
    
    def __str__(self):
        return self.vuid


class NoteVulnerability(models.Model):

    cve = models.CharField(
        _('CVE'),
	max_length=50,
        blank=True,
        null=True)

    description = models.TextField(
        _('Description'))

    note = models.ForeignKey(
        VulnerabilityNote,
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
            return u"%s" % (self.cert_id)

    vul = property(_get_vul)

    def _get_cert_id(self):
        return u"%s%s.%d" % (settings.CASE_IDENTIFIER, self.note.vuid, self.case_increment)

    cert_id = property(_get_cert_id)

class Vendor(models.Model):

    note = models.ForeignKey(
        VulnerabilityNote,
        related_name="vendors",
        on_delete=models.CASCADE)

    contact_date = models.DateTimeField(
        help_text=_('The date that this vendor was first contacted about this vulnerability.'),
        blank=True,
        null=True
    )

    uuid = models.UUIDField(
        help_text=_('The uuid of the contact in track'),
        blank=True,
        null=True,
        editable=False)
    
    vendor = models.CharField(
        max_length=200,
        help_text=_('The name of the vendor that may be affected.')
    )

    references = models.TextField(
        help_text=_('Vendor references for this case'),
        blank=True,
        null=True)

    statement = models.TextField(
        help_text=_('A general vendor statement for all vuls in the case'),
        blank=True,
        null=True)

    dateupdated = models.DateTimeField(
        default=timezone.now
    )

    statement_date = models.DateTimeField(
        blank=True,
        null=True
    )

    addendum = models.TextField(
        help_text=_('CERT Addendum'),
        blank=True,
        null=True)
    
    def get_status(self):
        status = VendorVulStatus.objects.filter(vendor=self).order_by('status').first()
        if status:
            return status.get_status_display()
        else:
            return "Unknown"

    def __str__(self):
        return "%s: %s" % (self.note.vuid, self.vendor)
            
    
class VendorVulStatus(models.Model):
    AFFECTED_STATUS = 1
    UNAFFECTED_STATUS = 2
    UNKNOWN_STATUS = 3

    STATUS_CHOICES = (
        (AFFECTED_STATUS, "Affected"),
        (UNAFFECTED_STATUS, "Unaffected"),
        (UNKNOWN_STATUS, "Unknown")
    )

    vendor = models.ForeignKey(
        Vendor,
        related_name="vendorvulstatus",
        on_delete=models.CASCADE)

    vul = models.ForeignKey(
        NoteVulnerability,
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


    def get_status(self):
        status = self.status
        if status:
            return self.get_status_display()
        else:
            return "Unknown"
