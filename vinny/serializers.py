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
from django.contrib.auth.models import User
from rest_framework import serializers
from vinny.models import Case, Post, VTCaseRequest, CaseMemberStatus, CaseVulnerability, CaseMember, CaseStatement, VCVulnerabilityNote, VinceCommContact
import uuid
import os
import json
import datetime
from django.conf import settings
import logging
from django.urls import reverse

logger = logging.getLogger(__name__)

logger.setLevel(logging.DEBUG)

class VendorInfoSerializer(serializers.ModelSerializer):
    emails = serializers.SerializerMethodField()
    users = serializers.SerializerMethodField()

    def get_emails(self, obj):
        return obj.get_emails()

    def get_users(self, obj):
        emails = obj.get_emails()
        users = User.objects.using('vincecomm').filter(email__in=emails).values_list('vinceprofile__preferred_username', flat=True)
        return list(users)
    
    class Meta:
        model = VinceCommContact
        fields = ['id', 'vendor_name', 'emails', 'users']
        

class CaseSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    
    
    class Meta:
        model = Case
        fields = ("vuid", "created", "status", "summary", "title", "due_date") 

    def get_status(self, obj):
        return obj.get_status_display()


class PostSerializer(serializers.ModelSerializer):
    content = serializers.CharField(source='current_revision.content')
    author = serializers.SerializerMethodField()
    
    class Meta:
        model = Post
        fields = ("created", "author", "pinned", "content")

    def get_author(self, obj):
        if obj.author:
            return {"org": obj.get_org_name(),
                    "active": obj.author.is_active,
                    "name": obj.author.vinceprofile.preferred_username,
                    "email": obj.author.email}
        else:
            return {"org": obj.get_org_name(),
                    "active": False,
                    "name": "User removed",
                    "email": "unknown@example.com"}



class OrigReportSerializer(serializers.ModelSerializer):

    class Meta:
        model = VTCaseRequest
        fields = ('vendor_name', 'product_name', 'product_version', 'vul_description', 'vul_exploit', 'vul_impact', 'vul_discovery', 'vul_public', 'public_references', 'vul_exploited', 'exploit_references', 'vul_disclose', 'disclosure_plans', 'date_submitted', 'share_release', 'contact_name', 'contact_phone', 'contact_email', 'contact_org')
            
    def remove_fields_from_representation(self, representation, remove_fields):
        for remove_field in remove_fields:
            try:
                representation.pop(remove_field)
            except KeyError:
                pass

    def to_representation(self, obj):
        ret = super(OrigReportSerializer, self).to_representation(obj)
        if obj.share_release == False:
            remove_fields = ('contact_name', 'contact_email', 'contact_phone', 'contact_org', 'share_release')
            self.remove_fields_from_representation(ret, remove_fields)
        return ret

class VendorStatusSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    vulnerability = serializers.SerializerMethodField()
    vendor = serializers.SerializerMethodField()
    statement_date = serializers.DateTimeField(source='date_added')
    statement = serializers.SerializerMethodField()
    references = serializers.SerializerMethodField()
    
    class Meta:
        model = CaseMemberStatus
        fields = ["vulnerability", "vendor", "status", "statement", "references", "statement_date"]

    def get_status(self, obj):
        if obj.member.share_status():
            return obj.get_status_display()
        else:
            return "Unknown"

    def get_statement(self, obj):
        if obj.member.share_status():
            return obj.statement
        else:
            return ""
    def get_references(self, obj):
        if obj.member.share_status():
            return obj.references
        else:
            return ""

    def get_vulnerability(self, obj):
        return obj.vulnerability.vul

    def get_vendor(self, obj):
        try:
            return obj.member.group.groupcontact.contact.vendor_name
        except:
            return obj.member.group.name

class VendorStatusUpdateSerializer(serializers.ModelSerializer):
    vendor = serializers.IntegerField(required=False)
    vulnerability = serializers.CharField(max_length=50)
    references = serializers.ListField(child=serializers.URLField(max_length=250, min_length=None, allow_blank=False), allow_empty=True)
    statement = serializers.CharField(max_length=2000, allow_blank=True)
    status = serializers.ChoiceField(choices=['Affected', 'Not Affected', 'Unknown'])
    share = serializers.BooleanField(default=False, required=False)
    
    class Meta:
        model = CaseMemberStatus
        fields = ["vendor", "status", "statement", "references", "vulnerability", "share"]
        
class VendorSerializer(serializers.ModelSerializer):
    vendor = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    statement = serializers.SerializerMethodField()
    references = serializers.SerializerMethodField()
    cert_addendum = serializers.SerializerMethodField()
    date_added = serializers.SerializerMethodField()
    statement_date = serializers.SerializerMethodField()
    
    class Meta:
        model = CaseMember
        fields = ["vendor", "status", "statement", "references", "date_added", "cert_addendum", "statement_date"]

    def get_date_added(self, obj):
        return obj.added
        
    def get_statement(self, obj):
        stmt = obj.get_statement()
        if stmt:
            return stmt[0].statement

    def get_statement_date(self, obj):
        stmt = obj.get_statement()
        if stmt:
            return stmt[0].date_modified
        else:
            return None
        
    def get_references(self, obj):
        stmt = obj.get_statement()
        if stmt:
            return stmt[0].references

    def get_cert_addendum(self, obj):
        stmt = CaseStatement.objects.filter(member=obj).first()
        if stmt:
            return stmt.addendum
        else:
            return None
        
    def get_status(self, obj):
        if obj.share_status():
            status = obj.get_general_status()
            if status == 1:
                return "Affected"
            elif status == 2:
                return "Not Affected"
            else:
                return "Unknown"
        return "Unknown"
            

    def get_vendor(self, obj):
        try:
            return obj.group.groupcontact.contact.vendor_name
        except:
            return obj.group.name
    
class VulSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    
    class Meta:
        model = CaseVulnerability
        fields = ['name', 'cve', 'description', 'date_added']

    def get_name(self, obj):
        return obj.vul



class VulNoteSerializer(serializers.ModelSerializer):
    revision = serializers.IntegerField(source="revision_number")
    references = serializers.SerializerMethodField()
    
    class Meta:
        model = VCVulnerabilityNote
        fields = ["vuid", "title", "content", "references", "datefirstpublished", "vuid", "dateupdated", "published", "revision"]

    def get_references(self, obj):
        return obj.references.splitlines()

class CSAFSerializer(serializers.ModelSerializer):
    """
    This serializer starts with a Case and then builds out using both
    OriginalReport and CaseVulnerability(s) to create the CSAF document
    case = list(Case.objects.filter(vuid="419889"))
    v = list(CaseVulnerability.objects.filter(case=case[0]))
    cs = list(CaseMemberStatus.objects.filter(vulnerability = v[i]))
    case.published || cs[i].member.share_status() then loop
    status = cs[i].status (1 == 'AFFECTED', 2 == 'UNAFFECTED')
    vendor = cs[i].member.group.groupcontact.contact.vendor_name
    """
    document = serializers.SerializerMethodField('get_csafdocument')
    vulnerabilities = serializers.SerializerMethodField('get_csafvuls')
    product_tree = serializers.SerializerMethodField('get_csafprods')
    mproduct_tree = {"branches": []}
    template_json_dir = os.path.join(os.path.dirname(__file__),
                                     'templatesjson', 'csaf')
    
    class Meta:
        model = Case
        fields = ["document","vulnerabilities","product_tree"]


    def to_representation(self, case):
        ret = super().to_representation(case)
        if not ret['vulnerabilities']:        
            del ret['product_tree']
            if hasattr(settings,'CSAF_VUL_EMPTY'):
                ret['vulnerabilities'] = settings.CSAF_VUL_EMPTY
            else:
                ret['vulnerabilities'] = [{"notes": [{"category": "general","text": "No vulnerabilities have been defined at this time for this report"}]}]
        return ret

        
    def get_csafdocument(self,case):
        tfile = os.path.join(self.template_json_dir,"document.json")
        add_document = {}
        if not os.path.exists(tfile):
            return {"error": "Template file for csaf missing"}
        csafdocument_template = open(tfile,"r").read()
        vulnote = reverse("vincepub:vudetail", args=[case.vuid])
        # Either one of this is the way to know l.publicdate or l.published
        if case.publicdate or case.published:
            publicurl = f"{settings.KB_SERVER_NAME}{vulnote}"
            case_status = "final"
        else:
            publicurl = f"{settings.KB_SERVER_NAME}{vulnote}#PendingRelease"
            case_status = "interim"
            if hasattr(settings,"CSAF_TLP_MAP") and settings.CSAF_TLP_MAP.get("PRIVATE"):
                tlp_type = settings.CSAF_TLP_MAP.get("PRIVATE")
                if hasattr(settings,"CSAF_DISTRIBUTION_OPTIONS") and settings.CSAF_DISTRIBUTION_OPTIONS.get(tlp_type):
                    add_document.update(settings.CSAF_DISTRIBUTION_OPTIONS.get(tlp_type))
        ackurl = f"{settings.KB_SERVER_NAME}{vulnote}#acknowledgments"

        if case.modified:
            revision_date = case.modified.isoformat(timespec='seconds')
            revision_number = case.modified.strftime("1.%Y%m%d%H%M%S.0")
            case_version = revision_number
        else:
            revision_date = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
            revision_number = revision_date.strftime("1.%Y%m%d%H%M%S.0")
            case_version = revision_number
        csafdocument = csafdocument_template % {
            "publicurl": publicurl,
            "ackurl": ackurl,
            "summary": json.dumps(case.summary),
            "LEGAL_DISCLAIMER": settings.LEGAL_DISCLAIMER,
            "title": json.dumps(case.title),
            "due_date": case.due_date,
            "VINCE_VERSION": settings.VERSION,
            "ORG_NAME": settings.ORG_NAME,
            "ORG_POLICY_URL": settings.ORG_POLICY_URL,
            "ORG_AUTHORITY": settings.ORG_AUTHORITY,
            "CONTACT_EMAIL": settings.CONTACT_EMAIL,
            "CONTACT_PHONE": settings.CONTACT_PHONE,
            "WEBSITE": settings.KB_SERVER_NAME,
            "vu_vuid": f"{settings.CASE_IDENTIFIER}#{case.vuid}",
            "revision_date": revision_date,
            "revision_number": revision_number,
            "case_status": case_status,
            "case_version": case_version
        }
        csafd = json.loads(csafdocument,strict=False)
        csafd.update(add_document)
        return csafd

    def get_csafvuls(self, case):
        self.mproduct_tree = {"branches": []}
        casevuls = list(CaseVulnerability.objects.filter(case=case, deleted=False))
        if not len(casevuls):
            return None
        csafvuls = []
        tfile = os.path.join(self.template_json_dir,"vulnerability.json")
        csafvul_template = open(tfile,"r").read()
        tfile = os.path.join(self.template_json_dir,"product_tree.json")
        if not os.path.exists(tfile):
            return [{"error": "Template file for csaf missing"}]
        csafproduct_template = open(tfile,"r").read()
        for casevul in casevuls:
            casems = list(CaseMemberStatus.objects.filter(vulnerability = casevul))
            known_affected = []
            known_not_affected = []
            if casevul.cve:
                cve = casevul.cve.upper()
                if cve.find("CVE-") < 0:
                    cve = f"CVE-{cve}"
            else:
                cve = None
            csafvul = csafvul_template % {
                "vuid":  casevul.vul,
                "cve":  cve,
                "ORG_NAME": settings.ORG_NAME,
                "title": json.dumps(casevul.description.split(".")[0]+"."),
                "description": json.dumps(casevul.description) }
            csafvulj = json.loads(csafvul,strict=False)
            if cve is None:
                del csafvulj['cve']
            for casem in casems:
                try:
                    vendor = casem.member.group.groupcontact.contact.vendor_name
                except Exception as e:
                    logger.info(f"Strange vendor without a vendor name {casem} for case # {case}")
                    vendor = "Unspecified"
                if case.published or casem.member.share_status():
                    csaf_productid = "CSAFPID-"+str(uuid.uuid1())
                else:
                    logger.debug(f"Vendor {vendor} for case {case} is not sharing their status")
                    continue
                if casem.status == 1:
                    known_affected.append(csaf_productid)
                elif casem.status == 2:
                    known_not_affected.append(csaf_productid)
                #(1 == 'AFFECTED', 2 == 'UNAFFECTED')
                # we include products that are Unknown
                # so it is clear that we have anounced to this vendor
                # who has not responded.
                csafproduct = csafproduct_template % {
                    "vendor_name": vendor,
                    "csaf_productid": csaf_productid }
                self.mproduct_tree["branches"].append(json.loads(csafproduct))
            if len(known_affected) > 0:
                if not 'product_status' in csafvulj:
                    csafvulj['product_status'] = {}
                csafvulj['product_status']['known_affected'] = known_affected
            if len(known_not_affected) > 0:
                if not 'product_status' in csafvulj:
                    csafvulj['product_status'] = {}
                csafvulj['product_status']['known_not_affected'] = known_not_affected
            csafvuls.append(csafvulj)
        return csafvuls
    def get_csafprods(self,case):
        return self.mproduct_tree
