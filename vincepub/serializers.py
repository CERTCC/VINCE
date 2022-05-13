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
from django.contrib.auth.models import User
from rest_framework import serializers
from vincepub.models import *

class VUReportSerializer(serializers.ModelSerializer):
    public = serializers.SerializerMethodField()
    
    class Meta:
        model = VUReport
        #exclude = ['id', 'search_vector', 'cve_str', 'keywords_str', 'publish', 'vulnerabilitycount']
        fields = ("vuid", "idnumber", "name", "keywords", "overview", "clean_desc", "impact", "resolution", "workarounds", "sysaffected", "thanks", "author", "public", "cveids", "certadvisory", "uscerttechnicalalert", "datecreated", "publicdate", "datefirstpublished", "dateupdated", "revision", "vrda_d1_directreport", "vrda_d1_population", "vrda_d1_impact", "cam_widelyknown", "cam_exploitation", "cam_internetinfrastructure", "cam_population", "cam_impact", "cam_easeofexploitation", "cam_attackeraccessrequired", "cam_scorecurrent", "cam_scorecurrent", "cam_scorecurrentwidelyknown", "cam_scorecurrentwidelyknownexploited", "ipprotocol", "cvss_accessvector", "cvss_accesscomplexity", "cvss_authentication", "cvss_confidentialityimpact", "cvss_integrityimpact", "cvss_availabilityimpact", "cvss_exploitablity", "cvss_remediationlevel", "cvss_reportconfidence", "cvss_collateraldamagepotential", "cvss_targetdistribution", "cvss_securityrequirementscr", "cvss_securityrequirementsir", "cvss_securityrequirementsar", "cvss_basescore", "cvss_basevector", "cvss_temporalscore", "cvss_environmentalscore", "cvss_environmentalvector", "metric", "vulnote")

    def get_public(self, obj):
        trim_refs = []
        refs = obj.public
        for r in refs:
            trim_refs.append(r.rstrip())

        return trim_refs

class VendorRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorRecord
        exclude = ['id']

class NewVendorRecordSerializer(serializers.ModelSerializer):
    #This is to match the VendorSerializer for CVE request
    date_added = serializers.CharField(source='datenotified')
    dateupdated = serializers.CharField(source='datelastupdated')
    references = serializers.CharField(source='vendorurls')
    vul = serializers.SerializerMethodField()
    
    class Meta:
        model = VendorRecord
        fields = ("vul", "vendor", "status", "date_added", "dateupdated", "references", "statement")

    def get_vul(self, obj):
        report = VUReport.objects.filter(vuid=obj.vuid).first()
        if report:
            return report.cveids
        else:
            return []


class VRSerializer(serializers.ModelSerializer):
    #this is another serializer to match Vendor to vendorRecord
    vuid = serializers.CharField(source='note.vuid')
    idnumber = serializers.CharField(source='note.idnumber')
    datenotified = serializers.CharField(source='contact_date')
    vendorurls = serializers.CharField(source='references')
    datelastupdated = serializers.CharField(source='dateupdated')
    status = serializers.SerializerMethodField()
    
    class Meta:
        model = Vendor
        fields = ("vuid", "idnumber", "vendor", "status", "statement", "vendorurls", "addendum", "datenotified", "datelastupdated")

    def get_status(self, obj):
        return obj.get_status()
        
class VulSerializer(serializers.ModelSerializer):
    note = serializers.StringRelatedField()
    
    class Meta:
        model = NoteVulnerability
        exclude = ["id"]

class VendorSerializer(serializers.ModelSerializer):
    note = serializers.StringRelatedField()
    
    class Meta:
        model = Vendor
        exclude = ["id", "uuid"]



class VendorIngestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        exclude = ["id", "uuid"]
        
class VendorStrSerializer(serializers.RelatedField):
    def to_representation(self, value):
        return '%s' % value.vendor


class StatusStrSerializer(serializers.RelatedField):
    def to_representation(self, value):
        if value == 1:
            return "Affected"
        elif value == 2:
            return "Not Affected"
        else:
            return "Unknown"
    
class VendorVulSerializer(serializers.ModelSerializer):
    vul = serializers.StringRelatedField()
    vendor = VendorStrSerializer(read_only=True)
    status = StatusStrSerializer(read_only=True)
    
    class Meta:
        model = VendorVulStatus
        exclude = ["id"]

class VVSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorVulStatus
        exclude = ["id"]
        

