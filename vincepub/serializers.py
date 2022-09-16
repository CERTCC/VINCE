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
import os
import json
import uuid
import re

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
        

class CSAFSerializer(serializers.ModelSerializer):
    """
    This serializer starts with a Case and then builds out using both
    OriginalReport and CaseVulnerability(s) to create the CSAF document
    list(VUReport.objects.filter(vuid="VU#865429"))
    """
    document = serializers.SerializerMethodField('get_csafdocument')
    vulnerabilities = serializers.SerializerMethodField('get_csafvuls')
    product_tree = serializers.SerializerMethodField('get_csafprods')
    mproduct_tree = {"branches": []}
    template_json_dir = os.path.join(os.path.dirname(__file__),
                                     '..','vinny','templatesjson', 'csaf')

    class Meta:
        model = VUReport
        fields = ["document","vulnerabilities","product_tree"]

    def get_csafdocument(self,vr):
        tfile = os.path.join(self.template_json_dir,"document.json")
        if not os.path.exists(tfile):
            return {"error": "Template file for csaf missing"}
        csafdocument_template = open(tfile,"r").read()
        vulnote = reverse("vincepub:vudetail", args=[vr.idnumber])
        publicurl = f"{settings.KB_SERVER_NAME}{vulnote}"
        ackurl = f"{settings.KB_SERVER_NAME}{vulnote}#acknowledgements"
        case_status = "final"

        if vr.dateupdated:
            revision_date = vr.dateupdated
            revision_number = vr.dateupdated.strftime("1.%Y%m%d%H%M%S")
        else:
            revision_date = datetime.datetime.now()
            revision_number = revision_date.strftime("1.%Y%m%d%H%M%S")
        if vr.revision:
            revision_number = revision_number + "." + str(vr.revision)
        else:
            revision_number = revision_number + ".0"
        case_version = revision_number
        csafdocument = csafdocument_template % {
            "publicurl": publicurl,
            "ackurl": ackurl,
            "summary": json.dumps(vr.overview),
            "LEGAL_DISCLAIMER": settings.LEGAL_DISCLAIMER,
            "title": json.dumps(vr.name),
            "due_date": vr.publicdate,
            "VINCE_VERSION": settings.VERSION,
            "vu_vuid": vr.vuid,
            "revision_date": revision_date,
            "revision_number": revision_number,
            "case_status": case_status,
            "case_version": case_version
        }
        csafdoc = json.loads(csafdocument, strict=False)
        if vr.vulnote.references and vr.vulnote.references != '':
            refs = re.split('\r?\n',vr.vulnote.references)
            csafdoc["references"] += list(map(lambda x: {"url": x, "summary": x},refs))
        vens = list(Vendor.objects.filter(note=vr.vulnote))
        for ven in vens:
            if ven.statement:
                veninfo = {"category": "other",
                           "text": ven.statement,
                           "title": f"Vendor statment from {ven.vendor}"}
                csafdoc["notes"] += [veninfo]
            if ven.references:
                refs = re.split('\r?\n',ven.references)
                csafdoc["references"] += list(map(lambda x: {"url": x, "summary": f"Reference(s) from vendor \"{ven.vendor}\""},refs))
            if ven.addendum:
                addinfo = {"category": "other",
                           "text": ven.addendum,
                           "title": "CERT/CC comment on {ven.vendor} notes"}
                csafdoc["notes"] += [addinfo]
        return csafdoc

    def get_csafvuls(self, vr):
        self.mproduct_tree = {"branches": []}
        casevuls = list(NoteVulnerability.objects.filter(note__vuid=vr.idnumber))
        csafvuls = []
        tfile = os.path.join(self.template_json_dir,"vulnerability.json")
        csafvul_template = open(tfile,"r").read()
        tfile = os.path.join(self.template_json_dir,"product_tree.json")
        if not os.path.exists(tfile):
            return [{"error": "Template file for csaf missing"}]
        csafproduct_template = open(tfile,"r").read()
        for casevul in casevuls:
            known_affected = []
            known_not_affected = []
            if casevul.cve:
                cve = casevul.cve.upper()
                if cve.find("CVE-") < 0:
                    cve = f"CVE-{cve}"
            else:
                cve = None
            csafvul = csafvul_template % {
                "vuid":  vr.vuid,
                "cve":  cve,
                "title": json.dumps(casevul.description.split(".")[0]+"."),
                "description": json.dumps(casevul.description) }
            csafvulj = json.loads(csafvul,strict=False)
            if cve is None:
                del csafvulj['cve']
            casems = list(VendorVulStatus.objects.filter(vul=casevul))
            for casem in casems:
                csaf_productid = "CSAFPID-"+str(uuid.uuid1())
                vendor = casem.vendor.vendor
                if casem.status == 1:
                    known_affected.append(csaf_productid)
                elif casem.status == 2:
                    known_not_affected.append(csaf_productid)
                if casem.references:
                    if not "references" in csafvulj:
                        csafvulj["references"] = []
                    crfs = re.split('\r?\n',casem.references)
                    csafvulj["references"] += list(map(lambda x: {"url": x, "summary": x, "category": "external"},crfs))
                    if casem.statement:
                        for crf in csafvulj["references"]:
                            crf["summary"] = casem.statement
                csafproduct = csafproduct_template % {
                    "vendor_name": vendor,
                    "csaf_productid": csaf_productid }
                self.mproduct_tree["branches"].append(json.loads(csafproduct,strict=False))
            #Add vendor statement and any reference URLS
            if len(known_affected) > 0:
                csafvulj['product_status'] = {}
                csafvulj['product_status']['known_affected'] = known_affected
            if len(known_not_affected) > 0:
                csafvulj['product_status'] = {}
                csafvulj['product_status']['known_not_affected'] = known_not_affected
            csafvuls.append(csafvulj)
        return csafvuls
    def get_csafprods(self,vr):
        return self.mproduct_tree
