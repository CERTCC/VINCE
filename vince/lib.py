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
import json
import mimetypes
import os
import re
import pkgutil
import encodings
import boto3
import hashlib
from django.db.models import Q, Count
# from django.utils import six
from dateutil import parser
# from django.utils.safestring import mark_safe
from datetime import date, datetime, timedelta
from django.core.files import File
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import timezone
from django.utils.encoding import smart_text
from vince.models import VulnerabilityCase
# from vince.models import Attachment, EmailTemplate, ArtifactAttachment, TicketArtifact
from vince.models import *
from vinny.models import Message, Case, Post, PostRevision, VinceCommContact, GroupContact, CaseMember, CaseMemberStatus, CaseStatement, CaseVulnerability, VTCaseRequest, VinceCommCaseAttachment, ReportAttachment, VinceCommInvitedUsers, CRFollowUp, VCVUReport, VendorAction, VendorStatusChange, CaseCoordinator, ContactInfoChange, CaseViewed, CaseVulExploit, CaseVulCVSS, CoordinatorSettings, VINCEEmailNotification
from vince.mailer import send_newticket_mail, send_daily_digest_mail, send_reset_mfa_email, get_mail_content
import email
import email.header
import traceback
from io import BytesIO
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.files.base import ContentFile
from botocore.client import Config
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
from vince.settings import VINCE_ASSIGN_TRIAGE, VINCE_IGNORE_TRANSIENT_BOUNCES
from vince.permissions import get_case_case_queue, get_user_case_queue, get_user_gen_queue

def md5_file(f):
    hash_md5 = hashlib.md5()
    b = bytearray(128*1024)
    mv = memoryview(b)
    for n in iter(lambda : f.readinto(mv), 0):
        hash_md5.update(mv[:n])
    return hash_md5.hexdigest()
                          

def get_oof_users():
    event = CalendarEvent.objects.filter(event_id=CalendarEvent.OOF, date__date=date.today()).values_list('user', flat=True)
    span_events = CalendarEvent.objects.filter(event_id=CalendarEvent.OOF, date__date__lte=date.today(), end_date__date__gte=date.today()). values_list('user', flat=True)
    event = event|span_events
    if event:
        return User.objects.filter(id__in=event)
    return []


def get_triage_users(user):

    #get this user's groups
    if user:
        user_groups = user.groups.exclude(groupsettings__contact__isnull=True)
        users = User.objects.filter(groups__in=user_groups)
    else:
        users = User.objects.filter(groups__name='vince')

    #need to do the first query because single day events don't have an end date
    event = CalendarEvent.objects.filter(user__in=users, event_id=1, date__date=date.today()).values_list('user', flat=True)
    span_events = CalendarEvent.objects.filter(user__in=users, event_id=1, date__date__lte=date.today(), end_date__date__gte=date.today()). values_list('user', flat=True)
    event = event|span_events
    if event:
        return User.objects.filter(id__in=event)
    return []

def get_triage_user(user=None):
    users = get_triage_users(user)
    if users:
        return users.first()
    return None

def update_srmail_file():
    if settings.WRITE_SRMAIL:
        try:
            client = boto3.client('sns', settings.AWS_REGION)
            response = client.publish(
                TopicArn=settings.VINCE_TRACK_SNS_ARN,
                Subject="Update SRMAIL File",
                Message="Please update srmail file",
                MessageAttributes={
                    'MessageType': {
                        'DataType': 'String',
                        'StringValue': "UpdateSrmail",
                    },
                    'Group': {
                        'DataType': 'String',
                        'StringValue': "srmail"
                    },
                    'Table': {
                        'DataType': 'String',
                        'StringValue': "srmail"
                    },
                    'Case': {
                        'DataType': 'String',
                        'StringValue': "srmail"
                    },
                    'User': {
                        'DataType': 'String',
                        'StringValue': "srmail"
                    },
                    'Queue': {
                        'DataType': 'String',
                        'StringValue': "srmail"
                    },
                    
                })
            
            logger.debug(f"Response:{response}")
        except:
            logger.debug(traceback.format_exc())



def vince_track_async_email(vendoremail):
    try:
        client = boto3.client('sns', settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_TRACK_SNS_ARN,
            Subject="Send Email",
            Message="Aysnc vendor notification",
            MessageAttributes={
                'MessageType': {
                    'DataType': 'String',
                    'StringValue': "NotifyVendor",
                },
                'Group': {
                    'DataType': 'String',
                    'StringValue': str(vendoremail.id)
                },
                'Table': {
                    'DataType': 'String',
                    'StringValue': "VendorNotification"
                },
                
	    })
        logger.debug(f"Response:{response}")
    except:
        logger.debug(traceback.format_exc())

            
def create_followup(ticket, title, comment=None, user=None, files=None, artifact=None):
    followup = FollowUp(ticket=ticket,
                        title=title,
                        date=timezone.now(),
                        comment=comment,
                        user=user,
                        artifact=artifact
                        )
    followup.save()

    if files:
        process_attachments(followup, [files])

    return followup

def download_vrf(vrf_id):

    vrf = CaseRequest.objects.filter(vrf_id=vrf_id).first()
    key = f"{settings.VRF_REPORT_DIR}/{vrf_id}.txt"

    s3client = boto3.client('s3', region_name=settings.AWS_REGION,
                            config=Config(signature_version='s3v4'))

    return s3client.generate_presigned_url('get_object',
                 Params={'Bucket':settings.VP_PRIVATE_BUCKET_NAME,
                         'Key':key},
                ExpiresIn=120)

def process_s3_download(followup, key, filesize=10, filetype='application/octet-stream'):

    att = Attachment(
        action = followup,
        file=key,
        filename=key,
        mime_type=filetype,
        size=filesize
    )

    att.save()

    artifact = TicketArtifact(type = "file",
                              title = key,
                              value = key,
                              description = "File attached to Report",
                              ticket= followup.ticket)
    artifact.save()
    followup.artifact = artifact
    followup.save()
    # add artifact
    #this is an artifact attachmnet                                                                  
    aa = ArtifactAttachment(artifact=followup.artifact,
                            attachment = att)
    aa.save()
    return att
    

def process_attachments(followup, attached_files):
    attachments = []
    logger.debug("IN PROCESS ATTACHMENTS")
    for attached in attached_files:
        logger.debug(attached)
        if attached.size:
            filename = smart_text(attached.name)
            logger.debug(filename)
            try:
                mime_type = attached.content_type
            except:
                mime_type = mimetypes.guess_type(filename, strict=False)[0]
                if not(mime_type):
                    mime_type = 'application/octet-stream'
                    
            att = Attachment(
                action=followup,
                file=attached,
                filename=os.path.basename(filename),
                mime_type=mime_type,
                size=attached.size,
            )
            att.save()

            if followup.artifact:
                #this is an artifact attachmnet
                aa = ArtifactAttachment(artifact=followup.artifact,
                                        attachment = att)
                aa.save()
            
            attachments.append([filename, att.file, att.id])
    return attachments

import difflib

def process_message_attachments(followup, message):
    for attachment in message.messageattachment_set.all():

        #copy this object                                                             
        copy_source = {'Bucket': settings.VINCE_SHARED_BUCKET,
                       'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+ str(attachment.file.file.name)
        }
        #copy file into s3 bucket                                                     
        s3 = boto3.resource('s3', region_name=settings.AWS_REGION)
        bucket = s3.Bucket(settings.PRIVATE_BUCKET_NAME)
        bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(attachment.file.uuid))        
        logger.debug(attachment.file.filename)

        att = Attachment(
            action=followup,
            file=attachment.file.file,
            filename=os.path.basename(attachment.file.filename),
            mime_type=attachment.file.mime_type,
            size=attachment.file.size,
        )
        att.save(using='default')

        if followup.ticket:
            artifact = TicketArtifact(type = "file",
                                      title = attachment.file.filename,
                                      value = attachment.file.filename,
                                      description = "File attached to Message",
                                      ticket= followup.ticket)
            artifact.save()

            followup.artifact = artifact
            followup.save()

            #this is an artifact attachmnet 
            aa = ArtifactAttachment(artifact=followup.artifact,
                                    attachment = att)
            aa.save(using='default')




def simple_merge(txt1, txt2):
    """Merges two texts"""
    differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
    diff = differ.compare(txt1.splitlines(1), txt2.splitlines(1))

    content = "".join([l[2:] for l in diff])

    return content


def push_s3_data(bucket, key, data):
    s3client = boto3.client('s3', region_name='us-east-1')
    s3client.put_object(
        Body=(bytes(json.dumps(data, cls=DjangoJSONEncoder).encode('UTF-8'))),
        Bucket=bucket,
        Key=key)


def update_vinny_case_vulnote(instance, case):
    if instance.published and case:
        if case.note:
            case.note.vuid = settings.CASE_IDENTIFIER+instance.vuid
            case.note.idnumber = instance.vuid
            case.note.name = instance.vulnote.current_revision.title
            case.note.datecreated = instance.vulnote.created
            case.note.publicdate = instance.publicdate
            case.note.datefirstpublished = instance.vulnote.date_published
            case.note.dateupdated = instance.vulnote.modified
            case.note.save()
        else:
            note = VCVUReport(vuid=settings.CASE_IDENTIFIER+instance.vuid,
                              idnumber = instance.vuid,
                              name = instance.vulnote.current_revision.title,
                              datecreated = instance.vulnote.created,
                              publicdate = instance.publicdate,
                              datefirstpublished = instance.vulnote.date_published,
                              dateupdated = instance.vulnote.modified)
            note.save()
            case.note = note
            case.save()

def update_case_assignment(instance):
    vcuser = User.objects.using('vincecomm').filter(username=instance.assigned.username).first()
    case = Case.objects.filter(vuid=instance.case.vuid).first()
    if vcuser and case:
        coordinator = CaseCoordinator.objects.update_or_create(case=case,
                                                               assigned=vcuser)

def delete_case_assignment(instance):
    vcuser = User.objects.using('vincecomm').filter(username=instance.assigned.username).first()
    case = Case.objects.filter(vuid=instance.case.vuid).first()
    if case:
        coordinator = CaseCoordinator.objects.filter(case=case, assigned=vcuser)
        if coordinator:
            coordinator.delete()


def update_vinny_cr(instance):
    cr = instance
    vtcr = VTCaseRequest.objects.filter(id=cr.vc_id).first()
    if vtcr:
        #get owner
        if cr.queue.team:
            logger.debug(cr.queue.team)
            try:
                contact = VinceCommContact.objects.filter(vendor_id=cr.queue.team.groupsettings.contact.id).first()
                #lookup group
                vcgroup = GroupContact.objects.using('vincecomm').filter(contact=contact, vincetrack=True).first()
                if vcgroup:
                    logger.debug("GOT GROUP")
                    #set coordinator access
                    vtcr.coordinator = vcgroup.group
                    logger.debug("SETTING GROUP")
            except:
                logger.debug("EXCEPTION")
                logger.debug(traceback.format_exc())
                pass

        vtcr.vrf_id = cr.vrf_id
        vtcr.share_release = cr.share_release
        vtcr.credit_release = cr.credit_release
        vtcr.why_no_attempt= cr.why_no_attempt
        vtcr.comm_attempt = cr.comm_attempt
        vtcr.please_explain = cr.please_explain
        vtcr.vendor_name = cr.vendor_name
        vtcr.multiplevendors = cr.multiplevendors
        vtcr.other_vendors = cr.other_vendors
        vtcr.first_contact = cr.first_contact
        vtcr.vendor_communication = cr.vendor_communication
        vtcr.product_name = cr.product_name
        vtcr.ics_impact = cr.ics_impact
        vtcr.product_version = cr.product_version
        vtcr.vul_description = cr.vul_description
        vtcr.vul_exploit = cr.vul_exploit
        vtcr.vul_impact = cr.vul_impact
        vtcr.vul_discovery = cr.vul_discovery
        vtcr.vul_public = cr.vul_public
        vtcr.public_references = cr.public_references
        vtcr.vul_exploited = cr.vul_exploited
        vtcr.exploit_references = cr.exploit_references
        vtcr.vul_disclose = cr.vul_disclose
        vtcr.disclosure_plans = cr.disclosure_plans
        if cr.share_release:
            vtcr.contact_name = cr.contact_name
            vtcr.contact_org = cr.contact_org
            vtcr.contact_email = cr.contact_email
            vtcr.contact_phone = cr.contact_phone
        vtcr.save()
        
def update_vinny_case(instance):
    case = Case.objects.filter(vuid=instance.vuid).first()
    vtcr = None
    if case:

        #update case assignments
        assignments = CaseAssignment.objects.filter(case=instance)
        for assignment in assignments:
            vcuser = User.objects.using('vincecomm').filter(username=assignment.assigned.username).first()
            if vcuser:
                coordinator = CaseCoordinator.objects.update_or_create(case=case,
                                                                       assigned=vcuser)

        case.title = instance.title
        case.due_date = instance.due_date
        case.publicdate = instance.publicdate
        case.summary = instance.summary
        case.status = instance.status
        case.publicurl = instance.publicurl
        case.save()
        if instance.case_request:
            cr = CaseRequest.objects.filter(id=instance.case_request.id).first()
            if cr == None:
                update_vinny_case_vulnote(instance, case)
                return
            if case.cr:
                if case.cr.status != case.status:
                    crfup = CRFollowUp(cr = case.cr,
                                       title = f"Status Change from {case.cr.get_status} to {case.get_status}",
                                       comment = "Case Status Change")
                    crfup.save()
                case.cr.vrf_id=cr.vrf_id
                case.cr.share_release = cr.share_release
                case.cr.credit_release = cr.credit_release
                case.cr.why_no_attempt= cr.why_no_attempt
                case.cr.comm_attempt = cr.comm_attempt
                case.cr.please_explain = cr.please_explain
                case.cr.vendor_name = cr.vendor_name
                case.cr.multiplevendors = cr.multiplevendors
                case.cr.other_vendors = cr.other_vendors
                case.cr.first_contact = cr.first_contact
                case.cr.vendor_communication = cr.vendor_communication
                case.cr.product_name = cr.product_name
                case.cr.ics_impact = cr.ics_impact
                case.cr.product_version = cr.product_version
                case.cr.vul_description = cr.vul_description
                case.cr.vul_exploit = cr.vul_exploit
                case.cr.vul_impact = cr.vul_impact
                case.cr.vul_discovery = cr.vul_discovery
                case.cr.vul_public = cr.vul_public
                case.cr.public_references = cr.public_references
                case.cr.vul_exploited = cr.vul_exploited
                case.cr.exploit_references = cr.exploit_references
                case.cr.vul_disclose = cr.vul_disclose
                case.cr.disclosure_plans = cr.disclosure_plans
                case.cr.status = case.status
                if cr.share_release:
                    case.cr.contact_name = cr.contact_name
                    case.cr.contact_org = cr.contact_org
                    case.cr.contact_email = cr.contact_email
                    case.cr.contact_phone = cr.contact_phone
                case.cr.save()
                vtcr = case.cr
            elif cr.vc_id:
                # vtcaserequest exists, just not associated
                vtcr = VTCaseRequest.objects.filter(id=cr.vc_id).first()
                if vtcr:
                    case.cr = vtcr
                    case.save()
                    vtcr.status = case.status
                    vtcr.save()
            if not(vtcr):
                logger.debug("GOT THE CASE REQUEST!!!!")
                vtcr = VTCaseRequest(vrf_id=cr.vrf_id,
		                     share_release = cr.share_release,
                                     credit_release = cr.credit_release,
		                     why_no_attempt= cr.why_no_attempt,
                                     comm_attempt = cr.comm_attempt,
                                     please_explain = cr.please_explain,
                                     vendor_name = cr.vendor_name,
                                     multiplevendors = cr.multiplevendors,
                                     other_vendors = cr.other_vendors,
                                     first_contact = cr.first_contact,
                                     vendor_communication = cr.vendor_communication,
                                     product_name = cr.product_name,
                                     ics_impact = cr.ics_impact,
                                     product_version = cr.product_version,
                                     vul_description = cr.vul_description,
                                     vul_exploit = cr.vul_exploit,
                                     vul_impact = cr.vul_impact,
                                     vul_discovery = cr.vul_discovery,
                                     vul_public = cr.vul_public,
		                     public_references = cr.public_references,
		                     vul_exploited = cr.vul_exploited,
                                     status = case.status,
                                     exploit_references = cr.exploit_references,
                                     vul_disclose = cr.vul_disclose,
                                     disclosure_plans = cr.disclosure_plans,
                                     date_submitted = cr.date_submitted)

                if cr.share_release:
                    vtcr.contact_name = cr.contact_name
                    vtcr.contact_org = cr.contact_org
                    vtcr.contact_email = cr.contact_email
                    vtcr.contact_phone = cr.contact_phone
                vtcr.save(using='vincecomm')
                case.cr = vtcr
                case.save()

    else:
        case = Case(vuid=instance.vuid,
                    title=instance.title,
                    due_date=instance.due_date,
                    publicdate=instance.publicdate,
                    publicurl=instance.publicurl,
                    summary=instance.summary,
                    vince_id=instance.id)
        case.save(using='vincecomm')
        if instance.case_request:
            cr = CaseRequest.objects.filter(id=instance.case_request.id).first()
            if cr == None:
                update_vinny_case_vulnote(instance, case)
                return
            if cr.vc_id:
                logger.debug(f"vc id is {cr.vc_id}") 
                # vtcaserequest exists, just not associated 
                vtcr = VTCaseRequest.objects.filter(id=cr.vc_id).first()
                if vtcr:
                    case.cr = vtcr
                    case.save()
                    vtcr.status = case.status
                    vtcr.save()
            if not(vtcr):
                vtcr = VTCaseRequest(vrf_id=cr.vrf_id,
                                     share_release = cr.share_release,
                                     credit_release = cr.credit_release,
                                     why_no_attempt= cr.why_no_attempt,
                                     comm_attempt = cr.comm_attempt,
                                     please_explain = cr.please_explain,
                                     vendor_name = cr.vendor_name,
                                     multiplevendors = cr.multiplevendors,
                                     other_vendors = cr.other_vendors,
                                     first_contact = cr.first_contact,
                                     vendor_communication = cr.vendor_communication,
                                     product_name = cr.product_name,
                                     ics_impact = cr.ics_impact,
                                     product_version = cr.product_version,
                                     vul_description = cr.vul_description,
                                     vul_exploit = cr.vul_exploit,
                                     vul_impact = cr.vul_impact,
                                     vul_discovery = cr.vul_discovery,
                                     vul_public = cr.vul_public,
                                     public_references = cr.public_references,
                                     vul_exploited = cr.vul_exploited,
                                     exploit_references = cr.exploit_references,
                                     vul_disclose = cr.vul_disclose,
                                     date_submitted = cr.date_submitted,
                                     status = case.status,
                                     disclosure_plans = cr.disclosure_plans)
                if cr.share_release:
                    vtcr.contact_name = cr.contact_name
                    vtcr.contact_org = cr.contact_org
                    vtcr.contact_email = cr.contact_email
                    vtcr.contact_phone = cr.contact_phone
                vtcr.save(using='vincecomm')
                case.cr = vtcr
                case.save()

    update_vinny_case_vulnote(instance, case)
    

def update_vinny_post(case, post):
    vcase = Case.objects.filter(vuid=case.vuid).first()

    #get vinny_user
    vcuser = User.objects.using('vincecomm').filter(username=post.user.username).first()
    
    #do we have this post already?                                           
    opost = Post.objects.filter(case=vcase, vince_id=post.id).first()
    if opost:
        rev = PostRevision()
        rev.inherit_predecessor(opost)
        rev.content = post.content
        rev.deleted = False
        rev.user = vcuser
        opost.add_revision(rev)
        title = "Published Edited Post"
    else:
        vpost = Post(case=vcase,
                     author= vcuser,
                     pinned=True,
                     vince_id=post.id)
        title = "Published Post"
        vpost.save()
        vpost.add_revision(PostRevision(content=post.content), save=True)

    followup = CaseAction(case = case,
                          user = post.user,
                          title=title,
                          date=timezone.now(),
                          notification=post,
                          action_type=1)

    followup.save()


def update_vinny_team_settings(gs):
    #lookup group in VinceComm
    if gs.contact == None:
        #only update if this group is tied to a contact
        return
    vincecomm_group = GroupContact.objects.filter(contact__uuid=gs.contact.uuid).first()

    #update coordinator settings
    if vincecomm_group == None:
        # make sure group doesn't already exist
        oldgroup = Group.objects.using('vincecomm').filter(name=gs.contact.uuid).first()
        if oldgroup:
            group = oldgroup
        else:
            group = Group(name=gs.contact.uuid)
            group.save(using='vincecomm')

        vincecomm_contact=VinceCommContact.objects.filter(uuid=gs.contact.uuid).first()
        vincecomm_group = GroupContact(group=group, contact=vincecomm_contact, vincetrack=True)
        vincecomm_group.save()

    settings = CoordinatorSettings.objects.update_or_create(group=vincecomm_group.group,
                                                            defaults={
                                                                'team_signature':gs.team_signature,
                                                                'team_email':gs.team_email,
                                                                'disclosure_link':gs.disclosure_link
                                                            })
    

# cp is case participant - if it exists it's being called by the track coordinator
# inviting another coordinator to the case
# otherwise it's being called by the case signal
def add_coordinator_case(case, contact, cp=None):
    vcase = Case.objects.filter(vuid=case.vuid).first()

    if vcase:
        vincecomm_contact=VinceCommContact.objects.filter(uuid=contact.uuid).first()
        #search GroupContact
        group = GroupContact.objects.filter(contact=vincecomm_contact).first()
    
        if group == None:
            # make sure group doesn't exist already
            oldgroup = Group.objects.using('vincecomm').filter(name=contact.uuid).first()
            if oldgroup:
                group = oldgroup
            else:
                group = Group(name=contact.uuid)
                group.save(using='vincecomm')

            gc = GroupContact(group=group, contact=vincecomm_contact)
            gc.save()
            group = gc

    if cp:
        vince_id = cp.id
    else:
        # add [lead] coordinator here
        cp, created = CaseParticipant.objects.update_or_create(case=case,
                                                               group=True,
                                                               contact=contact,
                                                               defaults={"added_by": case.owner,
                                                                         'coordinator': True,
                                                                         'status': "Lead",
                                                                         "user_name": contact.vendor_name})

        if created:
            cp.added_to_case = timezone.now()
            cp.save()
            
        #check to see if there is one by the same name with no contact
        cps = CaseParticipant.objects.filter(case=case, group=True, coordinator=True, user_name = contact.vendor_name, contact__isnull=True).first()
        if cps:
            # edit date on new caseparticipant to match what it used to be
            if created:
                cp.added_to_case = cps.added_to_case
                cp.save()
            # this is a duplicate due to a model change in CaseParticipant after 11/2021
            cps.delete()

        if vcase == None:
            # this case wasn't created in VINCEComm - so no need to do the rest
            return
            
        vcase.team_owner = group.group
        vcase.save()
                                                                         
        vince_id = cp.id
    member, created = CaseMember.objects.update_or_create(case=vcase, group=group.group,
                                                          defaults={'coordinator':True,
                                                                    'vince_id':vince_id})

        
    
        
def add_vendor_vinny_case(case, contact, user):
    vcase = Case.objects.filter(vuid=case.vuid).first()

    if vcase == None:
        # this may not be a VINCEComm case
        return

    vincecomm_contact=VinceCommContact.objects.filter(vendor_id=contact.id).first()
    #search GroupContact                                             
    group = GroupContact.objects.filter(contact=vincecomm_contact).first()
    if group == None:
	# make sure group doesn't exist already                      
        oldgroup = Group.objects.using('vincecomm').filter(name=contact.uuid).first()
        if oldgroup:
            group = oldgroup
        else:
            group = Group(name=contact.uuid)
            group.save(using='vincecomm')

        gc = GroupContact(group=group, contact=vincecomm_contact)
        gc.save()
        group = gc

    member = CaseMember.objects.filter(case=vcase, group=group.group).first()
    if member:
        #vendor already exists                                       
        pass
    else:
        member = CaseMember(case=vcase,
                            group=group.group)
#                            user = user)
        member.save()


def get_casemember_from_vc(vendor, case):
    vcase = Case.objects.filter(vuid=case.vuid).first()

    vincecomm_contact = VinceCommContact.objects.filter(vendor_id = vendor.contact.id).first()
    group = GroupContact.objects.filter(contact=vincecomm_contact).first()
    if group == None:
        return None
    
    member = CaseMember.objects.filter(case=vcase, group=group.group).first()
    if member:
        return member
    else:
        return None
        
def remove_participant_vinny_case(case, participant):
    vcase = Case.objects.filter(vuid=case.vuid).first()

    if vcase == None:
        # not a VINCEComm case
        return
    
    if participant.contact:
        vincecomm_contact=VinceCommContact.objects.filter(uuid=participant.contact.uuid).first()
        logger.debug("FOUND CONTACT + %s" % vincecomm_contact.vendor_name)
        #search GroupContact
        group = GroupContact.objects.filter(contact=vincecomm_contact).first()
        if group:
            member = CaseMember.objects.filter(case=vcase, group=group.group).first()
            if member:
                logger.debug("FOUND MEMBER GROUP")
                member.delete()
    elif participant.group:
        #old code, prior to adding contact to CaseParticipant model
        vincecomm_contact=VinceCommContact.objects.filter(vendor_name=participant.user_name).first()
        logger.debug("FOUND CONTACT + %s" % vincecomm_contact.vendor_name)
        #search GroupContact
        group = GroupContact.objects.filter(contact=vincecomm_contact).first()
        if group:
            member = CaseMember.objects.filter(case=vcase, group=group.group).first()
            if member:
                logger.debug("FOUND MEMBER GROUP")
                member.delete()
    else:
        member = CaseMember.objects.filter(case=vcase, participant__username__iexact=participant.user_name).first()
        logger.debug("FOUND MEMBER %s" % member)
        if member:
            #remove this participant
            member.delete()
        
    
    invitedusers = VinceCommInvitedUsers.objects.filter(case=vcase, email=participant.user_name)
    for u in invitedusers:
        logger.debug("removing invited user")
        u.delete()

        
def remove_vendor_vinny_case(case, contact, user):
    vcase = Case.objects.filter(vuid=case.vuid).first()
    vincecomm_contact=VinceCommContact.objects.filter(vendor_id=contact.id).first()
    logger.debug("FOUND CONTACT + %s" % vincecomm_contact.vendor_name)
    #search GroupContact
    group = GroupContact.objects.filter(contact=vincecomm_contact).first()
    logger.debug(group)
    if group:
        member = CaseMember.objects.filter(case=vcase, group=group.group).first()
        logger.debug("FOUND MEMBER")
        if member:
            # remove this vendor
            member.delete()
            action = action_vendor(case, "Vendor Access Removed from Case", "Vendor " + contact.vendor_name + " removed from case", 1, user)


def rm_vul_vinny_case(case, vul):
    vcase = Case.objects.filter(vince_id=case.id).first()
    if vcase == None:
        return

    vvul = CaseVulnerability.objects.filter(case=vcase, vince_id=vul.id).first()
    if vvul:
        vvul.delete()

def update_vinny_cvss(vul):

    #lookup vul
    vvul = CaseVulnerability.objects.filter(vince_id=vul.vul.id).first()
    if vvul:
        #lookup cvss
        cvss = CaseVulCVSS.objects.filter(vul=vvul).first()
        if cvss:
            cvss.last_modified = vul.last_modified
            cvss.vector = vul.vector
            cvss.score=vul.score
            cvss.severity=vul.severity
            cvss.save()
        else:
            cvss = CaseVulCVSS(last_modified=vul.last_modified,
                               vul=vvul,
                               vector=vul.vector,
                               score=vul.score,
                               severity=vul.severity)
            cvss.save()
            

def rm_vinny_exploit(exploit):
    ex = CaseVulExploit.objects.filter(vince_id=exploit.id).first()
    if ex:
        ex.delete()
        
def update_vinny_exploit(exploit):

    ex = CaseVulExploit.objects.filter(vince_id=exploit.id).first()
    if ex:
        ex.reference_date = exploit.reference_date
        ex.link = exploit.link
        ex.reference_type = exploit.reference_type
        ex.notes = exploit.notes
        ex.save()
        
    
def add_vul_vinny_case(case, vul):
    vcase = Case.objects.filter(vince_id=case.id).first()
    if vcase == None:
        return
    logger.debug(vcase)

    #do we have this case already?                                                                       
    vvul = CaseVulnerability.objects.filter(case=vcase, vince_id=vul.id).first()

    if vvul:
        vvul.cve = vul.cve
        vvul.description = vul.description
        vvul.ask_vendor_status = vul.ask_vendor_status
        vvul.deleted = vul.deleted
        vvul.save()
    else:
        vvul = CaseVulnerability(case=vcase,
                                 vince_id=vul.id,
                                 description = vul.description,
                                 ask_vendor_status = vul.ask_vendor_status,
                                 case_increment = vul.case_increment,
                                 cve = vul.cve)
        vvul.save()

    #does this vul have exploits?
    exploits = VulExploit.objects.filter(vul=vul, share=True)
    for ex in exploits:
        update_vinny_exploit(ex)


def add_participant_vinny_case(case, cp):
    vcase = Case.objects.filter(vuid=case.vuid).first()

    if vcase == None:
        logger.debug(f"Case {case.vuid} doesn't exist in VINCEComm")
        return
    
    username = cp.user_name

    if cp.added_by:
        vincecomm_coordinator = User.objects.using('vincecomm').filter(username=cp.added_by.username).first()
    else:
        vincecomm_coordinator = None

    if cp.group:
        contact = Contact.objects.filter(vendor_name=username).first()
        if not contact:
            return
        vincecomm_contact=VinceCommContact.objects.filter(vendor_id=contact.id).first()
        group = GroupContact.objects.filter(contact=vincecomm_contact).first()
        if group == None:
	    # make sure group doesn't exist already                                                             
            oldgroup = Group.objects.using('vincecomm').filter(name=contact.uuid).first()
            if oldgroup:
                group = oldgroup
            else:
                group = Group(name=contact.uuid)
                group.save(using='vincecomm')

            gc = GroupContact(group=group, contact=vincecomm_contact)
            gc.save()
            group = gc
        member, created = CaseMember.objects.update_or_create(case=vcase,
                                                              group=group.group,
                                                              defaults = {'reporter_group':True,
                                                                          'coordinator':False,
                                                                          'user':vincecomm_coordinator,
                                                                          'vince_id':cp.id,})

    else:
        user = User.objects.using('vincecomm').filter(username=username).first()
        if user:
            # find generic vul group                                       
            group = Group.objects.using('vincecomm').filter(name=case.vuid).first()
            if group:
                group.user_set.add(user)
            else:
                group = Group(name=case.vuid)
                group.save(using='vincecomm')
                group.user_set.add(user)

            
            member, created = CaseMember.objects.update_or_create(case=vcase,
                                                                  group=group,
                                                                  participant=user,
                                                                  defaults = {'coordinator': cp.coordinator,
                                                                              'user': vincecomm_coordinator,
                                                                              'vince_id': cp.id,
                                                                  })
        
            if created:
                logger.warning("Added user %s to case %s" % (username, vcase.title))
            else:
                logger.debug("Member already exists")
            

    # add invited user for later permissions check
        else:
            vciu = VinceCommInvitedUsers.objects.filter(case=vcase, email=username).first()
            if vciu:
                logger.debug("User already in this list")
            else:
                vciu = VinceCommInvitedUsers(case=vcase, email=username,
                                             user=vincecomm_coordinator,
                                             coordinator=cp.coordinator,
                                             vince_id=cp.id)
                vciu.save()
    
    followup = CaseAction(case = case,
                          title="Notified Participant: %s" % cp.user_name,
                          date=timezone.now(),
                          user = cp.added_by,
                          action_type = 0)
    followup.save()
    return followup

            
def status_display(num):
    if num == 1:
        return "Affected"
    elif num == 2:
        return "Not Affected"
    else:
        return "Unknown"
    
def action_vendor_update_status(case, vul, vendor, old_status, new_status):

    if old_status:
        comment = "%s changed their status on %s from %s to %s" % (vendor, vul.vul, status_display(old_status), status_display(new_status))
        title = f"Status Change for {vendor} on Vul {vul.vul}"
    else:
        comment = "%s added a status on %s: %s" % (vendor, vul.vul, status_display(new_status))
        title = f"New Status for {vendor} on Vul {vul.vul}"
    
    action = CaseAction(case = case,
                        title = title,
                        date = timezone.now(),
                        vendor = vendor,
                        action_type = 4,
                        comment=comment)
    action.save()

    return action

def action_vendor(case, title, comment, action_type=1, user=None):
    
    action = CaseAction(case = case,
                        title = title,
                        date = timezone.now(),
                        comment=comment,
                        action_type=action_type)
    if user:
        action.user=user
        
    action.save()
    
    return action


def create_action(attributes, body):
    logger.debug(attributes)
    logger.debug(body)
    user = attributes['User']
    group = attributes['Group']
    case = attributes['Case']
    table = attributes['Table']


    if table == "GroupAdmin":
        # find contact change
        contactchange = int(case)
        change = ContactInfoChange.objects.filter(id=contactchange).first()
        if change:
            contact = Contact.objects.filter(id = change.contact.vendor_id).first()
            if change.new_value:
                email = EmailContact.objects.filter(email=change.new_value, contact=contact).first()
                # create GroupAdmin
                if email:
                    admin = GroupAdmin.objects.update_or_create(contact=contact,
                                                                email=email)
                else:
                    logger.debug(f"Email {change.new_value} does not exist yet. Once approved, it will be added.")
                    action = Action(title=f"Contact Info Change requires coordinator approval: New user {change.new_value} promoted to group administrator.",
                                    comment=body)
                    
                    action.save()
                    return
                
            elif change.old_value:
                logger.debug(f"removing user {change.old_value} as group admin")
                email = EmailContact.objects.filter(email=change.old_value, contact=contact).first()
                # remove group admin
                admin = GroupAdmin.objects.filter(email=email, contact=contact).first()
                if admin:
                    admin.delete()

            # auto approved
            change.approved = True
            change.save()

    else:
        # is this a completion of the contact verification process?
        # find contact change
        contact = Contact.objects.filter(vendor_name=group).first()
        if contact:
            vccontact = VinceCommContact.objects.filter(vendor_id=contact.id).first()
            #get new emails added
            cic = ContactInfoChange.objects.filter(contact=vccontact,model="Email",field="email address").exclude(new_value__isnull=True)
            for email in cic:
                #check to see if we have a contact verification open for this user/contact
                ca = ContactAssociation.objects.filter(contact=contact, email=email.new_value, complete=False).first()
                if ca:
                    fup = FollowUp(ticket=ca.ticket,
                                   title=f"Admin {user} completed contact association process - added email {email.new_value}",
                                   comment="Contact Association Process Complete")
                    fup.save()
                    ca.complete=True
                    ca.save()
                    ca.ticket.status=Ticket.CLOSED_STATUS
                    ca.ticket.resolution = "Group admin completed contact association process"
                    ca.ticket.save()
            
    action = Action(title="Contact information change",
                    comment=body)

    action.save()

            

def update_vendor_view_status(attributes, body):

    logger.debug(attributes)
    logger.debug(body)
    user = attributes['User']
    group = attributes['Group']
    case = attributes['Case']
    table = attributes['Table']
    vendor = None
    case = VulnerabilityCase.objects.filter(vuid=case).first()
    if case == None:
        return None

    title = "%s (%s)" % (body, user)
    if table == "CaseParticipant":
        cp = CaseParticipant.objects.filter(case=case, user_name__iexact=user).first()
        if cp:
            cp.status = "Notified/Seen"
            cp.save()

    elif group:
        vendor = VulnerableVendor.objects.filter(case=case, contact__uuid=group).first()
        if vendor:
            vendor.seen = True
            vendor.save()
            title = f"{vendor.contact.vendor_name} viewed case {settings.CASE_IDENTIFIER}{case.vuid}"
        else:
            # this is probably a participant group
            cp = CaseParticipant.objects.filter(case=case, contact__uuid=group).first()
            if cp:
                if "Lead" in cp.status:
                    # not necessary to record an additional action
                    return
                cp.status = "Notified/Seen"
                cp.save()

    action = CaseAction(case=case,
                        title=title,
                        action_type=7,
                        date=timezone.now())
    if vendor:
        action.vendor = vendor
    action.save()

    
def update_vendor_status_statement(statement):
    # create vendorcontact

    org = statement.get('org_name')
    if org == None:
        return None
    vendor = None
        
    if statement.get('tracking'):
        tracking = statement["tracking"]
        if tracking.find('#') > 0:
            caseid = tracking[tracking.find('#'):]
            vendor = VulnerableVendor.objects.filter(case__vuid=case, vendor=org).first()

    if vendor == None:
        return None
    
    if statement.get('reporter_name') and statement.get('reporter_email') and statement.get('org_name'):
        vendor_data = VendorContactData(org_name = statement['org_name'],
                                        email = statement['reporter_email'],
                                        other_emails = statement.get('other_emails'),
                                        phone = statement.get('reporter_phone'),
                                        title = statement.get('reporter_org'),
                                        person = statement['reporter_name'])
    

    if vendor.statement:
        #vendor already made a statement - don't automatically overwrite it.
        return None
    else:
        vendor.statement = statement.get('statement')
        vendor.vendor_contact = vendor_data
        vendor.submission_type = "kb"
        vendor.save()
    
    
def update_vendor_status(attributes, body):
    logger.debug(attributes)
    logger.debug(body)
    user = attributes['User']
    group = attributes['Group']
    vuid = attributes['Case']

    status_change = False
    other_change = False
    
    case = VulnerabilityCase.objects.filter(vuid=vuid).first()
    if case == None:
        return None
    
    vc_case = Case.objects.filter(vuid=vuid).first()
    if vc_case == None:
        return None

    if group == "None":
        return None
    
    stats = CaseMemberStatus.objects.filter(member__case=vc_case, member__group__name=group)

    logger.debug(stats)
    
    vendor = VulnerableVendor.objects.filter(case=case, contact__uuid=group).first()

    if vendor == None:
        send_error_sns(vuid, "Vendor Statement", f"Vendor Doesn't Exist: no vendor for {case.vutitle} with name {group}")
        logger.warning(f"we don't have a vendor for {case.vutitle} for group {group}")
        return None
    
    actions = []
    for stat in stats:
        if stat.vulnerability:
            vul = Vulnerability.objects.filter(id=stat.vulnerability.vince_id).first()
            status = VendorStatus.objects.filter(vul=vul, vendor=vendor).first()
            mod = 0
            if status:
                if stat.date_modified > status.date_modified:
                    logger.debug(f"updating vendor status for {stat}")
                    logger.debug(f"VC{stat.date_modified} VT {status.date_modified}")
                    status.statement = stat.statement
                    status.references = stat.references
                    old_status = status.status
                    status.status = stat.status
                    status.date_modified = stat.date_modified
                    status.approved = False
                    status.user = user
                    mod = 1
                    status.save()
            elif vul:
                old_status = None
                mod = 1
                status = VendorStatus.objects.update_or_create(vul=vul,
                                                               vendor=vendor,
                                                               defaults={'user': user,
                                                                         'statement': stat.statement,
                                                                         'references': stat.references,
                                                                         'approved': False,
                                                                         'status': stat.status})

            if mod:
                if old_status != stat.status:
                    action = action_vendor_update_status(case, vul, vendor, old_status, stat.status)
                    actions.append(action.comment)

    # get general statements
    stats = CaseStatement.objects.filter(case = vc_case, member__group__name=group)
    for stat in stats:
        if vendor.statement_date:
            if (stat.date_modified > vendor.statement_date):
                no_changes = all([vendor.statement == stat.statement,
                                  vendor.references == stat.references,
                                  vendor.share == stat.share])
                if no_changes:
                    continue
        if vendor.statement != stat.statement:
            vendor.statement = stat.statement
            action = action_vendor(vendor.case, "Vendor Statement", f"{vendor.vendor} ({user}) updated statement", 4)
            action.vendor = vendor
            action.save()
            actions.append(action.comment)
        if vendor.references != stat.references:
            action = action_vendor(vendor.case, "Vendor References", f"{vendor.vendor} ({user}) updated references", 4)
            action.vendor = vendor
            action.save()
            vendor.references = stat.references
            actions.append(action.comment)
        if vendor.share != stat.share:
            actions.append(f"{vendor.vendor} user ({user}) updated share permissions from {vendor.share} to {stat.share}.")
            vendor.share = stat.share
            

    if actions:
        vendor.approved = False
        vendor.statement_date = timezone.now()
        vendor.save()
        if vendor.approve_ticket:
            # ticket exists
            logger.debug("TICKET EXISTS")
            vendor.approve_ticket.status = Ticket.OPEN_STATUS
            vendor.approve_ticket.save()
            ticket = vendor.approve_ticket
        else:
            # create a ticket for the case
            queue = get_case_case_queue(case)
            logger.debug("CREATE TICKET")
            link_to_stmt = reverse("vince:vendorstatus", args=[vendor.id])
            ticket = Ticket(title = body,
                            created = timezone.now(),
                            status = Ticket.OPEN_STATUS,
                            queue = queue,
                            case = case,
                            description = f"Statement requires approval\r\n\r\nView Statement: {settings.SERVER_NAME}{link_to_stmt}")

            #if we eventually wanted to send a closed message to user that changed status,
            # we could add submitter_email=user to this ticket creation.
            oof_users = get_oof_users()
            ca = CaseAssignment.objects.filter(case=case).exclude(assigned__in=oof_users).first()
            if ca:
                ticket.assigned_to = ca.assigned
            elif VINCE_ASSIGN_TRIAGE:
                if triage:
                    ticket.assigned_to = get_triage_user()
            ticket.save()
            vendor.approve_ticket = ticket
            vendor.save()
            #add the ticketcontact to associate ticket to contact
            tktc = TicketContact.objects.update_or_create(ticket=ticket,
                                                          contact=vendor.contact)

        # probably should be a config variable if these tickets create dependencies
        #dep = CaseDependency.objects.update_or_create(case=case, depends_on=ticket)
        link_to_stmt = reverse("vince:vendorstatus", args=[vendor.id])
        comment = "\r\n".join(actions)
        comment = f"{comment}\r\n\r\nView Statement: {settings.SERVER_NAME}{link_to_stmt}"
        followup = FollowUp(ticket=ticket,
                            title=f"Vendor statement requires approval\r\n\r\nView Statement: {settings.SERVER_NAME}{link_to_stmt}",
                            date=timezone.now(),
                            comment=comment)

        followup.save()

        

def create_case_msg_action(case, user, title, msg):
    # user should be email so we can lookup in the proper db

    cm = CaseMessageAction.objects.filter(thread=msg.thread.id, message=msg.id).first()
    if cm:
        # we already have it
        return
    else:
        reply = False
        om = CaseMessageAction.objects.filter(thread=msg.thread.id).order_by('-date').first()
        if om:
            if om.message:
                msg = Message.objects.filter(id=om.message).first()
                if msg:
                    if msg.sender.username != user:
                        reply = True

        logger.debug(f"adding case msg {msg.id} action {title} {msg.content}")
        ca = CaseMessageAction(case=case,
                               title=title,
                               message=msg.id,
                               thread=msg.thread.id,
                               comment=msg.content,
                               action_type=3,
                               date=timezone.now(),
                               replied=reply)
        ca.save()    

        # if vincetrack user is responsible for action, record it.
        vt_user = User.objects.filter(username=user).first()
        if vt_user:
            ca.user = vt_user
            ca.save()

            
def create_case_post_action(attributes, body):
    msgtype = attributes['MessageType']
    title = body
    submitter = attributes['User']
    vuid = attributes['Case']
    #post id is in group field
    post_id = attributes['Group']

    if msgtype == "EditPost":
        action_type = 11
    elif msgtype == "PostRemoved":
        action_type = 12
    else:
        #new post
        action_type = 2
        
    case = VulnerabilityCase.objects.filter(vuid=vuid).first()
    if case == None:
        return None
    post = Post.objects.filter(id=int(post_id)).first()
    if post:
        if post.current_revision:
            #vt user?
            vt_user = User.objects.filter(username=submitter).first()
            ca = CaseAction(case=case,
                            title=title,
                            post = post.id,
                            action_type = action_type,
                            comment=post.current_revision.content,
                            date=timezone.now())
            if vt_user:
                ca.user = vt_user
            ca.save()

             
def update_ticket(ticket, message):
    title = "Reply from %s" % message.sender.vinceprofile.preferred_username
    #search for Ticket

    followup = FollowUp(ticket= Ticket.objects.get(id=ticket),
                        title = title,
                        date = timezone.now(),
                        comment = message.content)    
    

    vt_user = User.objects.filter(email = message.sender.email, is_active=True).first()
    if vt_user:
        if vt_user.groups.filter(name='vince').exists():
            #this is a VINCETrack user
            followup.user = vt_user
        else:
            vt_user = None

    followup.save()

    fm = FollowupMessage(followup = followup,
                         msg = message.id)
    fm.save()
        
    files = process_message_attachments(followup, message)

    tkt = Ticket.objects.filter(id=ticket).first()
    if tkt:
        if vt_user and (vt_user == tkt.assigned_to):
            # if this is a vincetrack user - mark ticket as closed.
            tkt.status = Ticket.CLOSED_STATUS
            tkt.save()
        elif vt_user and not(tkt.assigned_to):
            #if ticket is unassigned and person that replied is a Track user,
            #assign the ticket to that user and close it.
            tkt.status = Ticket.CLOSED_STATUS
            tkt.assigned_to = vt_user
            tkt.save()
        elif tkt.status in [Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS]:
            tkt.status = Ticket.REOPENED_STATUS
            if tkt.assigned_to:
                if tkt.assigned_to.is_active == False:
                    #if this user is no longer active, unassign ticket to alert triage that ticket is reopened
                    tkt.assigned_to = None
            tkt.save()
            
            
    
    # this happens on followup signal
    #send_updateticket_mail(followup, files)
    
    return tkt


def _create_ticket(queue_name, title, description, submitter, case=None, add_contact=True):
    queue = TicketQueue.objects.filter(title=queue_name).first()
    if queue == None:
        send_error_sns(f"QUEUE {queue_name} Misconfiguration", f"Misconfiguration of Queues", f"Received ticket request for {queue_name} but queue does not exist.")
        queue = TicketQueue.objects.filter(title="General").first()

    if len(title) > 200:
        description = f"Title: {title}\r\n\r\n{description}"
        title = title[:190] + ".."
        
    ticket = Ticket(title = title,
                    created = timezone.now(),
                    status = Ticket.OPEN_STATUS,
                    queue = queue,
                    description = description,
                    submitter_email = submitter)

    if VINCE_ASSIGN_TRIAGE:
        ticket.assigned_to = get_triage_user()
        
    ticket.save()
    if case:
        c = VulnerabilityCase.objects.filter(vuid=case).first()
        if c:
            ticket.case = c
            # reassign to person assigned to case
            oof_users =	get_oof_users()
            ca = CaseAssignment.objects.filter(case=c).exclude(assigned__in=oof_users).first()
            if ca:
                ticket.assigned_to = ca.assigned
            ticket.save()


    # this makes sure the user that made this ticket doesn't get notified
    fup_user = User.objects.filter(username=submitter).first()
    
    followup = FollowUp(ticket=ticket,
                        title="New VinceComm Message",
                        date=timezone.now(),
                        comment=description,
                        user=fup_user)

    followup.save()

    #does submitter email exist in contactdb
    if add_contact:
        contact = EmailContact.objects.filter(email=submitter)
        for c in contact:
            tktc = TicketContact.objects.update_or_create(contact=c.contact,
                                                          ticket=ticket)

    return followup


def create_request_ticket(attributes, body):
    queue_name = attributes.get('Queue', "Inbox")
    title = body
    description = body
    submitter = attributes['User']
    vuid = attributes.get('Case')
    fup = _create_ticket(queue_name, title, description, submitter, vuid)
    

#def create_ticket(queue_name, title, description, submitter, vuid=None, msg=None):
def create_ticket(attributes, body):
    queue_name = attributes.get('Queue', "Inbox")
    title = body
    description = body
    submitter = attributes['User']
    vuid = attributes.get('Case')
    group = attributes.get('Group')
    message = attributes.get('Message')

    logger.debug("IN CREATE TICKET")
    logger.debug(attributes)
    
    if vuid == "None":
        vuid = None

    if title == "Case access requested":
        create_request_ticket(attributes, body)
        return

    #is submitter track user - i.e. is this a direct message?
    track_user = User.objects.filter(email=submitter).first()

    if message != "None":
        try:
            message = int(message)
        except:
            send_error_sns("Message", f"Error creating ticket for {message}",
                           f"Error occurred when creating ticket for message, Expected a message ID, received something else: {message}")
            return
    else:
        send_error_sns("Message", "Error creating ticket for message",
                       f"Error occurred when creating ticket for message, Expected a message ID, but message not populated.")
        return
    
    if vuid:
        case = VulnerabilityCase.objects.filter(vuid=vuid).first()
        if case == None:
            return None
        queue = get_case_case_queue(case)
        # don't use queue name from message - get queue assocated with case
        queue_name = queue.title
        vc_case = Case.objects.filter(vuid=vuid).first()
        if vc_case == None:
            return None
        
    msg = Message.objects.filter(id=message).first()

    logger.debug(msg.id)
    
    if msg:
        tm = TicketThread.objects.filter(thread=msg.thread.id).first()
        if tm:
            fm = FollowupMessage.objects.filter(msg=msg.id)
            if fm:
                logger.debug("ALREADY HAVE THIS MSG")
                return
            else:
                # this is an update
                update_ticket(tm.ticket, msg)
        else:
            if track_user:
                # don't make ticket/contact connection bc it will make coordinator contact - which is every ticket
                followup =_create_ticket(queue_name, title, msg.content, msg.sender.email, vuid, False)
                # make ticket/contact connection here.
                if msg.thread.to_group:
                    #need to split the to_group for group threads:
                    group_threads = msg.thread.to_group.split(", ")
                    for g in group_threads:
                        contact = Contact.objects.filter(vendor_name=g)
                        for c in contact:
                            tktc = TicketContact.objects.update_or_create(contact=c,
                                                                          ticket=followup.ticket)
                else:
                    for u in msg.thread.userthread_set.exclude(user__groups__name='vincetrack'):
                        contact = EmailContact.objects.filter(email=u.user.username)
                        for c in contact:
                            tktc = TicketContact.objects.update_or_create(contact=c.contact,
                                                                          ticket=followup.ticket)

            else:
                followup =_create_ticket(queue_name, title, msg.content, msg.sender.email, vuid, True)
            files = process_message_attachments(followup, msg)
            #commenting this out 3/1/21 bc followup signal sends an alert
            #if not track_user:
                #I don't think this is necessary because Followup will send email on ticket
            #    send_newticket_mail(followup=followup, files=files, user=None)
            tm = TicketThread(thread=msg.thread.id,
                              ticket=followup.ticket.id)
            
            tm.save()
            
            fm = FollowupMessage(followup = followup,
                                 msg = msg.id)
            fm.save()

            if track_user and title.startswith('Direct Message'):
                # does this user have write access to the queue?
                if not(QueuePermissions.objects.filter(queue__title=queue_name, group__in=track_user.groups.all(), group_write=True).exists()):
                    queue = get_user_gen_queue(track_user)
                    followup.ticket.queue = queue
                #change ticket status if this message was direct from track user                
                followup.ticket.assigned_to = track_user
                followup.ticket.status = Ticket.IN_PROGRESS_STATUS
                followup.ticket.save()

                #create_followup(followup.ticket, "Direct Message Ticket Opened and auto-closed")



def parse_attachment(message_part):
    try:
        content_disposition = message_part.get("Content-Disposition", None)
    except AttributeError:
        return None
    if message_part.get_content_type() == "application/pgp-signature":
        # don't want pgp attachments
        return
    if content_disposition:
        dispositions = content_disposition.strip().split(";")
        if bool(content_disposition and dispositions[0].lower() in ["attachment", "inline"]):
            logger.debug("IN ATTACHMENT")
            file_data = message_part.get_payload(decode=True)
            attachment = BytesIO(file_data)
            attachment.content_type = message_part.get_content_type()
            if file_data:
                attachment.size = len(file_data)
            else:
                return None
            logger.debug("ATTACHMENT SIZE IS %d" % attachment.size)
            attachment.name = None
            attachment.create_date = None
            attachment.mod_date = None
            attachment.read_date = None
            logger.debug(dispositions)
            for param in dispositions[1:]:
                logger.debug("IN PARAMS")
                name,value = param.split("=")
                # remove bogus linefeed junk
                name = name.strip("\\r\\n ").lower()
                # now take care of other whitespace
                name = name.strip()
                # handle multi-entry filenames correctly
                if name.startswith("filename"):
                    # we've got text, so initialize for realz
                    if not attachment.name:
                        attachment.name = ""
                    # remove extraneous quotes
                    value = value.strip('\"')
                    attachment.name += value
                    logger.debug("attachment.name is %s" % attachment.name)
                elif name == "create-date":
                    attachment.create_date = value  #TODO: datetime
                elif name == "modification-date":
                    attachment.mod_date = value #TODO: datetime
                elif name == "read-date":
                    attachment.read_date = value #TODO: datetime
            logger.debug(attachment.name)
            return InMemoryUploadedFile(attachment, None,
                                        attachment.name,
                                        attachment.content_type,
                                        attachment.size, None)

    return None

def create_ticket_for_error_email(filename, bucket, queue=None, from_email=None, body=None, cert_id=None, case=None):
    if queue == None:
        queue = TicketQueue.objects.filter(queue_type=1, from_email=bucket).first()

    if len(body) > 5000:
        #truncate long bodies
        body = body[:5000] + "\n====TRUNCATED===="
    
    if queue:
        ticket = Ticket(title = f"Error retrieving email from {bucket} for mail ID: {cert_id}",
			created = timezone.now(),
                        status = Ticket.OPEN_STATUS,
                        queue = queue,
                        submitter_email = from_email,
                        description = f"Error retrieving email: {filename}\n{body}")

        if VINCE_ASSIGN_TRIAGE:
            ticket.assigned_to = get_triage_user()

        if case:
            ticket.case = case
            oof_users =	get_oof_users()
            ca = CaseAssignment.objects.filter(case=case).exclude(assigned__in=oof_users).first()
            if ca:
                ticket.assigned_to = ca.assigned

        ticket.save()

        #does submitter email exist in contactdb
        if from_email:
            name_only, from_email_only = email.utils.parseaddr(from_email)
            if from_email_only != '':
                contact = EmailContact.objects.filter(email=from_email_only)
                for c in contact:
                    tktc = TicketContact.objects.update_or_create(contact=c.contact,
                                                                  ticket=ticket)

        
        if body:
            return ticket
        else:
            followup = FollowUp(ticket=error_ticket,
                                title=f"Email Received: Problems Retrieving for mail ID: {cert_id}",
                                date=timezone.now(),
                                email_id=filename,
                                email_bucket=bucket)
            followup.save()
        return ticket
    
def all_encodings():
    modnames = set([modname for importer, modname, ispkg in pkgutil.walk_packages(path=[os.path.dirname(encodings.__file__)], prefix='')])
    aliases = set(encodings.aliases.aliases.values())
    return modnames.union(aliases)

def try_other_encodings(obj):
    message = None
    for enc in all_encodings():
        try:
            message = obj.get()['Body'].read().decode(enc)
        except Exception:
            continue
        else:
            logger.debug(f"succeeded with encoding {enc}")
            break

    return message

def email_try_other_encodings(obj):
    message = None
    for enc in all_encodings():
        try:
            message = obj.decode(enc)
        except Exception:
            continue
        else:
            logger.debug(f"succeeded with encoding {enc}")
            break

    return message


def get_bounce_stats(email, vcuser):
    bs = {}
    bounces = BounceEmailNotification.objects.filter(email=email).order_by('bounce_date')
    if bounces:
        bs["num_bounces"] = bounces.count()
        bs["first_bounce"] = bounces.first().bounce_date
        bs["last_bounce"] = bounces.last().bounce_date
        bs["transient_bounces"] = bounces.filter(bounce_type=BounceEmailNotification.TRANSIENT).count()
        bs["permanent_bounces"] = bounces.filter(bounce_type=BounceEmailNotification.PERMANENT).count()
    else:
        bs["num_bounces"] = 0
    vc_emails = 0
    if vcuser:
        emails = VINCEEmailNotification.objects.filter(user=vcuser).order_by('date_sent')
        vc_emails = emails.count()

    ec = EmailContact.objects.filter(email=email).values_list('contact__id', flat=True)
    # this would give all the potential cases this user has been notified
    vendors = VulnerableVendor.objects.filter(contact__in=ec, contact_date__isnull=False).values_list('id', flat=True)
    #get vendor notifications
    notifications = VendorNotification.objects.filter(vendor__in=vendors, emails__icontains=email).count()
    other_emails = VinceEmail.objects.filter(to__icontains=email).count()
    bs['total_emails_sent'] = vc_emails+notifications+other_emails
    bs['vc_emails'] = vc_emails
    bs['notifications']=notifications
    bs['other_emails']=other_emails
    return bs

def create_bounce_record(email_to, bounce_type, subject, ticket=None):
    #create bounce
    #is this email tied to a useR?
    vc_user = User.objects.using('vincecomm').filter(email=email_to).first()
    if (bounce_type == 'Transient'):
        b_type = BounceEmailNotification.TRANSIENT
    else:
        b_type = BounceEmailNotification.PERMANENT

    
    bounce = BounceEmailNotification(email=email_to,
                                     bounce_type = b_type,
                                     subject = subject,
                                     ticket=ticket)
    if vc_user:
        bounce.user_id=vc_user.id

    bounce.save()

    if ticket == None:
        return
    
    if (b_type == BounceEmailNotification.PERMANENT):
        if vc_user:
            if vc_user.is_active:
                user_link = reverse("vince:vcuser", args=[vc_user.id])
                user_link = f"{settings.SERVER_NAME}{user_link}"
                followup = FollowUp(ticket=ticket,
                                    title=f"Permanent bounce to {email_to}. Consider removing user immediately",
                                    comment=user_link)
                followup.save()
            else:
                bounce.action_taken=True
                bounce.save()
        else:
            contact = EmailContact.objects.filter(email=email_to, status=True)
            contact_links = []
            for c in contact:
                tktc = TicketContact.objects.update_or_create(contact=c.contact,
                                                              ticket=ticket)

                contact_links.append(c.contact.vendor_name)
            comment = ", ".join(contact_links)
            if contact_links:
                followup = FollowUp(ticket=ticket,
                                    title=f"Permanent bounce to {email_to}. Consider removing email from contact",
                                    comment=f"Email found in the following contacts: {comment}")
                followup.save()
            if len(contact_links) == 0:
                #No action to take other than to tell let someone know their email wasn't received
                bounce.action_taken=True
                bounce.save()

    else:
        # this is a TRANSIENT bounce
        # pull helpful stats
        #get number of bounces
        bs = get_bounce_stats(email_to, vc_user)
        comment = f"Bounce Stats:\r\nTotal Bounces: {bs['num_bounces']}\r\nFirst Bounce: {bs['first_bounce']}\r\n Last Bounce: {bs['last_bounce']}\r\nTotal Emails Sent: {bs['total_emails_sent']}"
        if vc_user:
            user_link = reverse("vince:vcuser", args=[vc_user.id])
            user_link = f"{settings.SERVER_NAME}{user_link}"
            comment = f"{comment}\r\n{user_link}"
        else:
            contact = EmailContact.objects.filter(email=email_to, status=True)
            for c in contact:
                tktc = TicketContact.objects.update_or_create(contact=c.contact,
                                                              ticket=ticket)
        followup = FollowUp(ticket=ticket,
                            title=f"Transient bounce Stats for {email_to}",
                            comment=comment)
        followup.save()
                

def create_bounce_ticket(headers, bounce_info):
    subject = headers.get("subject")
    email_to = headers.get("to")
    email_to_str = ", ".join(email_to)
    email_from = headers.get("from")
    email_from_str = ", ".join(email_from)
    bounce_type = bounce_info.get('bounceType')
    date = headers.get("date")


    if (bounce_type == "Transient") and VINCE_IGNORE_TRANSIENT_BOUNCES:
        for email in email_to:
            create_bounce_record(email, bounce_type, subject)
        return

    ticket = None
    case = None
    queues = list(TicketQueue.objects.all().values_list('slug', flat=True))
    #General queue is the only one where slug != title
    queues.extend(list(TicketQueue.objects.all().values_list('title', flat=True)))
    rq= '|'.join(queues)
    queue = TicketQueue.objects.filter(title="General").first()
    if queue == None:
        # this is misconfigured!                                                        
        send_error_sns("ticket queues", "misconfiguration for bounced emails",
                       f"Received email but no queues configured for this bucket. Defaulting to General queue")
        queue = TicketQueue.objects.filter(title="General").first()
    nqueue = None
    # do ticket search for                                                                               
    rq = "(?i)(" + rq + ")-(\d+)"
    m = re.search(rq, subject)
    if m:
        q = m.group(1)
        tid = m.group(2)
        logger.debug(f"Q is {q} and tid is {tid}")
        nqueue = TicketQueue.objects.filter(Q(slug__iexact=q) | Q(title__iexact=q)).first()
        if nqueue:
            ticket = Ticket.objects.filter(id=int(tid), queue=nqueue).first()
            if ticket:
                if ticket.status in [Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS]:
                    ticket.status = Ticket.REOPENED_STATUS
                    if ticket.assigned_to:
                        if ticket.assigned_to.is_active==False:
                            #if user is inactive, unassign this ticket
                            ticket.assigned_to = None
                    ticket.save()
                followup = FollowUp(ticket=ticket,
                                    title=f"Email Bounce Notification from {email_from_str} to {email_to_str}",
                                    date=timezone.now())
                if bounce_info:
                    followup.comment = json.dumps(bounce_info)
                followup.save()

                for email in email_to:
                    create_bounce_record(email, bounce_type, subject, ticket)
                return
    if not ticket:
        m = re.search(f'{settings.CASE_IDENTIFIER}(\d+)', subject, re.IGNORECASE)
        if m:
            # search for case for vu#                                           

            case = VulnerabilityCase.objects.filter(vuid=m.group(1)).first()
            if case:
                queue = get_case_case_queue(case)

    ticket = Ticket(title = f"Email Bounce Notification to {email_to_str}",
                    created = timezone.now(),
                    status = Ticket.OPEN_STATUS,
                    queue = queue,
                    description = f"Email Bounce Notification from {email_from_str} to {email_to_str}.\r\n Subject: {subject}",
                    submitter_email = email_from_str)
    if case:
        ticket.case = case
        oof_users =	get_oof_users()
        ca = CaseAssignment.objects.filter(case=case).exclude(assigned__in=oof_users).first()
        if ca:
            ticket.assigned_to = ca.assigned

    ticket.save()

    followup = FollowUp(ticket=ticket,
                        title=f"Email Bounce Notification from {email_from_str} to {email_to_str}",
                        date=timezone.now())

    if bounce_info:
        followup.comment = json.dumps(bounce_info)
    
    followup.save()

    for email in email_to:
        create_bounce_record(email, bounce_type, subject, ticket)
                                     
    

def create_ticket_from_email_s3(filename, bucket_name):
    s3 = boto3.resource('s3', region_name='us-east-1')

    obj = s3.Object(bucket_name, filename)

    message = None

    try:
        message = obj.get()['Body'].read().decode('utf-8')
    
    except:        
        logger.debug(traceback.format_exc())
        logger.warning(f"File does not exist: {filename}")
        if obj:
            message = try_other_encodings(obj)
        else:
            message = None

    if message:
        followup = create_ticket_from_email(filename, message, bucket_name)
    else:
        followup = create_ticket_for_error_email(filename, bucket_name, None)


def add_comment_to_ticket(ticket, body, subject, to_email, from_email, xcert_id, filename=None, bucket=None):

    from_email_only = None

    if from_email:
        name_only, from_email_only = email.utils.parseaddr(from_email)
    
    title = f"New Email received from {from_email} \"[{subject}]\" to {to_email}"
    if xcert_id and (xcert_id != "NO CERT ID"):
        title = f"{title}: CERT MESSAGE ID: {xcert_id}"
        
    if len(title) > 300:
        title = title[:290] + ".."
    
    followup = FollowUp(ticket=ticket,
                        title=title,
                        date=timezone.now(),
                        email_id=filename,
                        email_bucket=bucket,
                        comment = body)
    if from_email_only:
        vince_user = User.objects.filter(email=from_email_only).first()
        if vince_user:
            followup.user = vince_user

    followup.save()
    
    # this happens on followup signal
    #send_updateticket_mail(followup, files=None, user=None)    
    # this is just repetitive
    #if ticket.case:
    #    ca = CaseAction(case=ticket.case,
    #                    title=f"New Email from {from_email}: CERT Message ID: {xcert_id}",
    #                    comment=subject,
    #                    action_type=8)
    #    ca.save()

    if ticket.status in [Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS]:
        ticket.status = Ticket.REOPENED_STATUS
        if ticket.assigned_to:
            if ticket.assigned_to.is_active==False:
                #if user is inactive, unassign this ticket                                                                                                                    
                ticket.assigned_to = None

        ticket.save()
        
    return followup
        

def email_header_decode_helper(data, errors='backslashreplace'):
    # decode_header returns tuples containing the data field and encoding type.
    # In this usage, we only supply one data field and so we only want the first
    # tuple, and we only care about the returned data part, not the encoding type.

    logger.debug(data)
    if not(data):
        return None
    
    header_data = email.header.decode_header(data)
    header_parts = []
    for (blob, encoding) in header_data:
        # now we could have bytes, and we need to return ascii-encoded string, so do
        # python decoding magic.
        try:
            if isinstance(blob, bytes):
                blob = blob.decode('us-ascii', errors=errors)
        except UnicodeDecodeError:
            logger.error(f"Failed to decode text from header, data: '{blob}', encoding: '{encoding}'")
            blob = "[encoded text failed to decode]"
        header_parts.append(blob)
    header = " ".join(header_parts)

    return header


def create_ticket_from_email(filename, body, bucket):
    #decode base64 email
    b = email.message_from_string(body)
    to_email = email_header_decode_helper(b['to'])
    from_email = email_header_decode_helper(b['from'])
    from_email_only = None
    name_only = None
    
    if from_email:
        name_only, from_email_only = email.utils.parseaddr(from_email)

    if to_email:
        name_only, to_email_only = email.utils.parseaddr(to_email)
    else:
        to_email_only = None

    subject = email_header_decode_helper(b['subject'])

    xcert_id = b.get('x-cert-index', "NO CERT ID")

    if to_email_only and to_email_only in settings.IGNORE_EMAILS_TO:
        logger.warning(f"Ignoring email TO: {to_email_only} FROM: {from_email} CERT_ID: {xcert_id} SUBJECT: {subject}")  
        return
    
    email_msg = None
    # default the charset to utf-8, and we'll set it below if we get something valid
    email_msg_charset = 'utf-8'
    attachments = []
    encrypted_content = False
    if b.is_multipart():
        for part in b.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            cdesc = str(part.get('Content-Description'))
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                email_msg = part.get_payload(decode=True)
                # try to get the content charset, default to utf-8
                email_msg_charset = part.get_content_charset('utf-8')
                logger.debug("GOT THE PLAIN TEXT PART")
            elif ctype == 'text/html' and 'attachment' not in cdispo and email_msg is None:
                email_msg = part.get_payload(decode=True)
                # try to get the content charset, default to utf-8
                email_msg_charset = part.get_content_charset('utf-8')
                logger.debug("NO text/plain YET, TAKING text/html PART FOR BODY")
            elif ctype == 'application/pgp-encrypted' or (ctype == 'application/octet-stream' and 'PGP' in cdesc):
                encrypted_content = True
                logger.debug("Encrypted content found")
            else:
                if (isinstance(part.get_payload(), list)):
                    if len(part.get_payload()) > 1:
                        i = 1
                        logger.debug(len(part.get_payload()))
                        while i < len(part.get_payload()):
                            # this has attachment
                            attachment = part.get_payload()[i]
                            attachment = parse_attachment(attachment)
                            i = i+1
                            if attachment:
                                logger.debug(attachment)
                                attachments.append(attachment)

    else:
        email_msg = b.get_payload(decode=True)

    if email_msg:
        try:
            email_msg = email_msg.decode(email_msg_charset)
        except:
            email_msg = email_try_other_encodings(email_msg)

        if email_msg == None:
            #last ditch effort
            try:
                email_msg = email_msg.decode('utf-8', errors='replace')
            except:
                # tried and failed
                logger.debug(traceback.format_exc())
                email_msg = None

        if email_msg:
           if len(email_msg) > settings.VINCE_MAX_EMAIL_LENGTH:
               email_msg = email_msg[:settings.VINCE_MAX_EMAIL_LENGTH] + "....\ntruncated"
    
    # now do regex on subject:
    case = None
    vrf_id = None
    ticket = None

    #null bucket names for queues are anyone's game
    if settings.TEAM_SPECIFIC_EMAIL_QUEUE:
        # only search queues associated with this bucket
        queues = list(TicketQueue.objects.filter(Q(from_email=bucket)|Q(from_email__isnull=True)).values_list('slug', flat=True))
        #General queue is the only one where slug != title
        queues.extend(list(TicketQueue.objects.filter(Q(from_email=bucket)|Q(from_email__isnull=True)).values_list('title', flat=True)))
    else:
        # we want to match on all queue names in case it gets sent to the wrong email address
        queues = list(TicketQueue.objects.all().values_list('slug', flat=True))
        queues.extend(list(TicketQueue.objects.all().values_list('title', flat=True)))
        
    queues = list(set(queues))
    rq= '|'.join(queues)
    logger.debug(queues)
    logger.debug(rq)
    
    #this is the default queue - the general queue for this bucket
    queue = TicketQueue.objects.filter(from_email=bucket, queue_type=1).first()
    if queue == None:
        # this is misconfigured!
        send_error_sns("ticket queues", "misconfiguration",
                       f"Received email from bucket {bucket} but no queues configured for this bucket. Defaulting to General queue")
        queue = TicketQueue.objects.filter(title="General").first()
    
    nqueue = None

    # do ticket search for
    rq = "(?i)(" + rq + ")-(\d+)"
    m = re.search(rq, subject)
    if m:
        q = m.group(1)
        tid = m.group(2)
        logger.debug(f"Q is {q} and tid is {tid}")
        nqueue = TicketQueue.objects.filter(Q(slug__iexact=q) | Q(title__iexact=q)).first()
        if nqueue:
            ticket = Ticket.objects.filter(id=int(tid), queue=nqueue).first()
            if ticket:
                case = ticket.case
                if ticket.status in [Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS]:
                    ticket.status = Ticket.REOPENED_STATUS
                    if ticket.assigned_to:
                        if ticket.assigned_to.is_active==False:
                            #if user is inactive, unassign this ticket
                            ticket.assigned_to = None
                    ticket.save()
                    
                if email_msg:
                    followup = add_comment_to_ticket(ticket,
                                                     email_msg,
                                                     subject,
                                                     to_email,
                                                     from_email,
                                                     xcert_id,
                                                     filename,
                                                     bucket)
                else:
                    if encrypted_content:
                        followup = add_comment_to_ticket(ticket,
                                                         "Email with encrypted content detected",
                                                         subject,
                                                         to_email,
                                                         from_email,
                                                         xcert_id,
                                                         filename,
                                                         bucket)
                    else:
                        followup = add_comment_to_ticket(ticket,
                                                         "Error decoding email",
                                                         subject,
                                                         to_email,
                                                         from_email,
                                                         xcert_id,
                                                         filename,
                                                         bucket)
                queue = None
    
    if not ticket:       
        #didn't find a ticket, so search cases
        case_regex = f"{settings.CASE_IDENTIFIER}(\d+)"
        m = re.search(case_regex, subject, re.IGNORECASE)
        if m:
            # search for case for vu#
            case = VulnerabilityCase.objects.filter(vuid=m.group(1)).first()
            if case:
                queue = get_case_case_queue(case)
        else:
            report_regex = f"{settings.REPORT_IDENTIFIER}([-0-9A-Z]+)"
            m = re.search(report_regex, subject, re.IGNORECASE)
            if m:
                vrf_id = m.group(1)

    if email_msg == None:
        if encrypted_content:
            # set a friendly message and continue so we add it where appropriate
            email_msg = f"Email with encrypted content detected in mail ID: {xcert_id}"
        else:
            error_ticket = create_ticket_for_error_email(filename, bucket, queue, from_email, body, xcert_id, case)
            followup = FollowUp(ticket=error_ticket,
                                title=f"Email Received: Problems Retrieving for mail ID: {xcert_id}",
                                date=timezone.now(),
                                email_id=filename,
                                email_bucket=bucket,
                                comment=f"From: {from_email}, To: {to_email}, Subject: {subject}")

            followup.save()
            logger.warning("Error retrieving email")
            return
                        
    if vrf_id:
        cr = CaseRequest.objects.filter(vrf_id=vrf_id).first()
        if cr:
            ticket = cr
            title = f"New Email received from {from_email} \"[{subject}]\" to {to_email}: CERT Message ID: {xcert_id}"
            if len(title) > 300:
                title = title[:290] + ".."
            followup = FollowUp(ticket=ticket,
                                title=title,
                                date=timezone.now(),
                                email_id=filename,
                                email_bucket=bucket,
                                comment = email_msg)

            followup.save()
            queue = None
            if cr.status in [Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS]:
                cr.status = Ticket.REOPENED_STATUS
                if cr.assigned_to:
                    if cr.assigned_to.is_active==False:
                        #if user is inactive, unassign this ticket                                                                                                                    
                        cr.assigned_to = None
                cr.save()
            #send_updateticket_mail(followup, files=None, user=None)

    if len(from_email) > 200:
        from_email = from_email[:200] + ".."
            
    vince_user = None
    if queue:
        ticket = Ticket(title = subject,
                        created = timezone.now(),
                        status = Ticket.OPEN_STATUS,
                        queue = queue,
                        description = email_msg,
                        submitter_email = from_email_only)

        if VINCE_ASSIGN_TRIAGE:
            ticket.assigned_to = get_triage_user()

        if case:
            ticket.case = case
            oof_users =	get_oof_users()
            ca = CaseAssignment.objects.filter(case=case).exclude(assigned__in=oof_users).first()
            if ca:
                ticket.assigned_to = ca.assigned

        ticket.save()

        #does submitter email exist in contactdb
        if from_email_only:
            contact = EmailContact.objects.filter(email=from_email_only)
            for c in contact:
                tktc = TicketContact.objects.update_or_create(contact=c.contact,
                                                              ticket=ticket)
            # is this email from a VINCE User?
            vince_user = User.objects.filter(email=from_email_only).first()
            logger.debug(f"Is this from a vince user? {vince_user} : {from_email_only}")
        
        if len(to_email) > 200:
            to_email = to_email[:200] + ".."

        title = f"New Email received from {from_email} to {to_email}: CERT Message ID: {xcert_id}"
        if len(title) > 300:
            title = f"New Email received from {from_email}: CERT Message ID: {xcert_id}"
            
        followup = FollowUp(ticket=ticket,
                            title=title,
                            email_id=filename,
                            email_bucket=bucket,
                            date=timezone.now(),
                            user=vince_user)
        
        followup.save()

        #DON'T THINK THIS IS NECESSARY...
        #if case:
        #    ca = CaseAction(case=case,
        #                    title=f"New Email from {from_email}: CERT Message ID: {xcert_id}",
        #                    comment=subject,
        #                    user=vince_user,
        #                    action_type=8)
        #    ca.save()
        if not case:
            # this only emails people that have subscribed to all tickets on a queue
            send_newticket_mail(followup=followup, files=None, user=vince_user)

    for attachment in attachments:
        #hash file in memory
        file_hash = md5_file(attachment)
        logger.debug(file_hash)
        logger.debug(ticket)
        #lookup this filehash
        if case:
            #if there is a case, look at artifacts across all tickets in the case
            prevartifact = TicketArtifact.objects.filter(file_hash=file_hash, ticket__case=case).first()
        else:
            #otherwise if its just a ticket, make sure we're not attaching the same file to the ticket
            prevartifact = TicketArtifact.objects.filter(file_hash=file_hash, ticket=ticket).first()

        logger.debug(prevartifact)
        if prevartifact:
            #already got this file - so skip it
            continue
        
        artifact = TicketArtifact(type = "file",
                                  title = attachment.name,
                                  value = attachment.name,
                                  file_hash=file_hash,
                                  description = "File attached to Email",
                                  ticket= ticket)
        artifact.save()
        followup = FollowUp(ticket=ticket,
                            title=f"Attachment to Email",
                            date=timezone.now(),
                            email_id=filename,
                            email_bucket=bucket,
                            user=vince_user,
                            artifact=artifact)
        
        followup.save()
        ats = process_attachments(followup, [attachment])
        

    return followup
    
#def create_new_message(title, description, submitter, vuid=None):
    
def add_case_artifact(attributes, message):
    submitter = attributes['User']
    vuid = attributes['Case']
    table = attributes['Table']

    if table == "CaseArtifact":
        case = VulnerabilityCase.objects.filter(vuid=vuid).first()
        
        # find attachment:
        attachments = VinceCommCaseAttachment.objects.filter(action__case__vuid=vuid)

        for attachment in attachments:
            # do we have it already?
            if attachment.attachment:
                ca = CaseArtifact.objects.filter(title = attachment.attachment.name,
                                                 case=case).first()
            elif attachment.file:
                ca = CaseArtifact.objects.filter(title=attachment.file.filename,
                                                 case=case).first()
            else:
                continue
        
            if ca:
                continue
            else:
                #copy this object
                copy_source = {'Bucket': settings.VINCE_SHARED_BUCKET,
                               'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+str(attachment.file.file.name)
                }
                #copy file into s3 bucket
                s3 = boto3.resource('s3', region_name=settings.AWS_REGION)
                bucket = s3.Bucket(settings.PRIVATE_BUCKET_NAME)
                bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(attachment.file.uuid))

                ca = CaseArtifact(type="file",
                                  title=attachment.file.filename,
                                  value=attachment.file.filename,
                                  description="vincecomm uploaded attachment",
                                  case=case)
                
                ca.save()
            
                # create the followup                                                         
                followup = CaseAction(case=case,
                                      title="Artifact added from VinceComm",
                                      date=timezone.now(),
                                      artifact=ca,
                                      action_type=7)
                followup.save()
    
                ats = process_attachments(followup, [attachment.file.file])
                for at in ats:
                    af = Attachment.objects.filter(id=at[2]).first()
                    logger.debug("making attachment public")
                    logger.debug(af)
                    af.filename=attachment.file.filename
                    af.public=True
                    af.save()

                    #rename file                                                                                                                                                              
                    copy_source = {'Bucket': settings.PRIVATE_BUCKET_NAME,
                                   'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+ str(attachment.file.uuid)
                    }
                    bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(af.uuid))
                    #assign to new key and save
                    af.file.name = str(af.uuid)
                    af.save()
                    #delete the old one
                    s3.Object(settings.PRIVATE_BUCKET_NAME, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(attachment.file.uuid)).delete()
                    
                    # now connect this back to vince
                    attachment.vince_id=af.id
                    attachment.save()
    elif table == "CaseRequestArtifact":

        cr = CaseRequest.objects.filter(vrf_id = vuid).first()

        # find attachment
        attachments = ReportAttachment.objects.filter(action__cr__vrf_id=vuid)

        for attachment in attachments:
            if attachment.file:
                ca = TicketArtifact.objects.filter(title=attachment.file.filename,
                                                   ticket=cr.ticket_ptr).first()
                if ca:
                    continue

            #copy this object                                                                   
            copy_source = {'Bucket': settings.VINCE_SHARED_BUCKET,
                           'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+str(attachment.file.file.name)
            }
            #copy file into vincetrack s3 bucket
            s3 = boto3.resource('s3', region_name=settings.AWS_REGION)
            bucket = s3.Bucket(settings.PRIVATE_BUCKET_NAME)
            bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(attachment.file.uuid))
            
            ca = TicketArtifact(type="file",
                                title=attachment.file.filename,
                                value=attachment.file.filename,
                                description="vincecomm uploaded attachment",
                                ticket=cr.ticket_ptr)
            
            ca.save()

            # create the followup
            followup = FollowUp(ticket=cr.ticket_ptr,
                                title="Artifact added from VinceComm",
                                date=timezone.now(),
                                artifact=ca)
            
            followup.save()

            ats = process_attachments(followup, [attachment.file.file])
            for at in ats:
                af = Attachment.objects.filter(id=at[2]).first()
                af.filename=attachment.file.filename
                af.public=True
                af.save()

                #rename file
                copy_source = {'Bucket': settings.PRIVATE_BUCKET_NAME,
                               'Key': settings.AWS_PRIVATE_MEDIA_LOCATION+"/"+ str(attachment.file.uuid)
                }
                bucket.copy(copy_source, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(af.uuid))
                #assign to new key and save
                af.file.name = str(af.uuid)
                af.save()
                #delete the old one
                s3.Object(settings.PRIVATE_BUCKET_NAME, settings.AWS_PRIVATE_MEDIA_LOCATION + "/" + str(attachment.file.uuid)).delete()

                
            
def update_case_request(attributes, message):
    submitter = attributes['User']
    vuid = attributes['Case']
    table = attributes['Table']
    cr_id = attributes['Group']

    if table == "Ticket":
        cr = CaseRequest.objects.filter(vrf_id = vuid).first()
        vtcr = VTCaseRequest.objects.filter(vrf_id = vuid).first()
        
        if vtcr and cr:
            if cr_id != "None":
                f = CRFollowUp.objects.filter(id=int(cr_id)).first()
            else:
                f = CRFollowUp.objects.filter(cr__vrf_id=vuid).order_by('-date').first()
            if f:
                if f.user:
                    title = f"{f.user.email} {f.title}"
                    u = User.objects.filter(email=f.user.email).first()
                else:
                    title = f"{f.title}"
                    u = None
                cf = FollowUp(ticket=cr.ticket_ptr, date=f.date,
                              title = title, comment=f.comment, user=u)
                cf.save()
                #REOPEN ticket if closed.
                if cr.status in [Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS]:
                    cr.status = Ticket.REOPENED_STATUS
                    if cr.assigned_to:
                        if cr.assigned_to.is_active==False:
                            #if user is inactive, unassign this ticket
                            cr.assigned_to = None

                    cr.save()
            else:
                cf = FollowUp(ticket=cr.ticket_ptr, title=message, comment=f'Error finding CR Comment in VINCEComm - see VINCEComm for details about comment left by {submitter}')    
        else:
            _create_ticket("General", f"Update to deleted CR: {vuid}", f"{submitter} commented on deleted CR", submitter)

                    

def update_vc_vul_status(instance):
    # instance is a VT VendorStatus
    # need to get vul, vendor from that
    vt_vul = instance.vul
    vt_vendor = instance.vendor

    vcuser = User.objects.using('vincecomm').filter(username=instance.user).first()
    cv = CaseVulnerability.objects.filter(vince_id=vt_vul.id).first()

    old_statement = None
    old_references = None
    old_status = None
    member = get_casemember_from_vc(vt_vendor, vt_vul.case)
    approval = False
    if member:
        # is this an approval?
        status = CaseMemberStatus.objects.filter(member=member, vulnerability=cv).first()
        if status:
            nochanges = all([status.status==instance.status,
                             status.references==instance.references,
                             status.statement==instance.statement])
            if nochanges:
                if (status.approved != instance.approved) and (status.approved == False):
                    logger.debug(f"APPROVAL {status.approved}, {instance.approved}")
                    approval = True
            else:
                old_statement = status.statement
                old_references = status.references
                old_status = status.status
        status, created = CaseMemberStatus.objects.update_or_create(member=member, vulnerability=cv,
                                                                    defaults={'status':instance.status, 'user':vcuser,
                                                                              'references':instance.references,
                                                                              'statement':instance.statement,
                                                                              'approved':instance.approved})
        if created:
            va = VendorAction(member=member, user=vcuser,
                              case=member.case,
                              title=f"Coordinator created status for {cv.vul}")
            va.save()
            vs = VendorStatusChange(action=va, field="status", new_value=instance.status)
            vs.save()
            if instance.statement:
                va = VendorAction(member=member, user=vcuser,
                                  case=member.case,
                                  title=f"Coordinator created statement for {cv.vul}")
                va.save()
                vs = VendorStatusChange(action=va, field="statement", new_value=instance.statement)
                vs.save()
            if instance.references:
                va = VendorAction(member=member, user=vcuser,
                                  case=member.case,
                                  title=f"Coordinator added references for {cv.vul}")
                va.save()
                vs = VendorStatusChange(action=va, field="references", new_value=instance.references)
                vs.save()
                
        elif approval:
            vcuser = User.objects.using('vincecomm').filter(username=instance.user_approved.username).first()
            va = VendorAction(member=member, user=vcuser,
                              case=member.case,
                              title=f"Coordinator approved status for {cv.vul}")
            va.save()
            vs = VendorStatusChange(action=va, field="approved", new_value="Approved")
            vs.save()
        elif not nochanges:
            if old_statement != instance.statement:
                va = VendorAction(member=member, user=vcuser,
                                  case=member.case,
                                  title=f"Coordinator updated statement for {cv.vul}")
                va.save()
                vs = VendorStatusChange(action=va, field="statement", old_value=old_statement, new_value=instance.statement)
                vs.save()
            if old_references != instance.references:
                va = VendorAction(member=member, user=vcuser,
                                  case=member.case,
                                  title=f"Coordinator updated references for {cv.vul}")
                va.save()
                vs = VendorStatusChange(action=va, field="references", old_value=old_references, new_value=instance.references)
                vs.save()
            if old_status != instance.status:
                va = VendorAction(member=member, user=vcuser,
                                  case=member.case,
                                  title=f"Coordinator updated status for {cv.vul}")
                va.save()
                vs = VendorStatusChange(action=va, field="status", old_value=old_status, new_value=instance.status)
                vs.save()
            



def send_error_sns(vul_id, issue, error):
    subject = "Problem with %s for %s" % (issue, vul_id)
    try:
        client = boto3.client('sns', settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_ERROR_SNS_ARN,
            Subject=subject,
            Message=error)
        logger.debug("Response:{}".format(response))

    except:
        logger.debug('Error publishing to SNS')


def publish_vul_note(vu_dict, key):
    s3client = boto3.client('s3', region_name=settings.AWS_REGION)
    s3client.put_object(Body=json.dumps(vu_dict), Bucket=settings.S3_UPDATE_BUCKET_NAME, Key=key)


def send_vt_daily_digest(user):

    text = "" 
    cases = []
    
    n = VTDailyNotification.objects.filter(user=user)

    diff_cases = n.distinct('case')
    
    s = user.usersettings.settings.get('email_preference', 1)
    if int(s) == 1:
        html = True
    else:
        html = False

    for x in diff_cases:
        if html:
            text = text + f'<h3><a href=\"{settings.SERVER_NAME}{x.case.get_absolute_url()}\">{settings.CASE_IDENTIFIER}{x.case.vuid}</a> Changes</h3><ul>'
        else:
            text = text + f'{settings.CASE_IDENTIFIER}{x.case.vuid} Changes\r\n---------------\r\n'

        # get notifications for each case
        notes = n.filter(case=x.case).values_list('action_type').order_by('action_type').annotate(count=Count('action_type')).order_by('-count')
        logger.debug(notes)
        for y in notes:
            if y[0] == 1:
                ntext = f'{y[1]} changes to the case'
            elif y[0] == 2:
                last_viewed = CaseViewed.objects.filter(user__username=user.username, case__vuid=x.case.vuid).first()
                if last_viewed:
                    unread = n.filter(case=x.case, action_type=2, action__date__gt=last_viewed.date_viewed).count()
                    ntext = f'{y[1]} new posts ({unread} Unread)'
                else:
                    ntext = f'{y[1]} new posts ({y[1]} Unread)'
            elif y[0] == 3:
                msgs = n.filter(case=x.case, action_type=3, followup__ticket__status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS]).count()
                ntext = f'{y[1]} new messages ({msgs} open)'
            elif y[0] == 4:
                opentix = n.filter(case=x.case, action_type=4, followup__ticket__status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS]).count()
                ntext = f'{y[1]} vendor status updates ({opentix} require approval)'
            else:
                opentix = n.filter(case=x.case, action_type__in=[5,6,7,8], followup__ticket__status__in=[Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.IN_PROGRESS_STATUS]).distinct('followup__ticket__id').count()
                ntext = f'{y[1]} new tickets in the case ({opentix} OPEN)'

            if html:
                text = text + f'<li>{ntext}</li>'
            else:
                text = text + f'{ntext}\r\n'

        if html:
            text = text + "</ul>"
        
            
    send_daily_digest_mail(user, text)

    # now delete these so we can reset for the next day
    for x in n:
        x.delete()
        

def generate_vt_reminders(user):
    today = datetime.today()
    today_str = today.strftime('%Y-%m-d')
    ticket_reminder = user.usersettings.settings.get('reminder_tickets', True)

    #cut tickets for defined reminders for this user
    tkt_rems = VinceReminder.objects.filter(user=user, create_ticket=True, alert_date__year=today.year, alert_date__month=today.month, alert_date__day=today.day)
    logger.debug(tkt_rems)

    for x in tkt_rems:
        #new ticket
        if x.case:
            queue = get_user_case_queue(x.user)
        else:
            queue = get_user_gen_queue(x.user)

        t = Ticket(title = x.title,
                   submitter_email = 'VINCE Reminder System',
                   assigned_to = x.user,
                   case=x.case,
                   queue = queue,
                   description=f"Auto generated from VINCE reminder created by {x.created_by.email} for {x.user.email} on {x.created}: {x.title}")
        t.save()
        if x.frequency:
            #if recurrence is set, move reminder out to the next frequency
            x.alert_date = x.alert_date + timedelta(days=x.frequency)
            x.save()
        else:
            #delete reminder once ticket has been created
            x.delete()

    if settings.VINCE_DEV_SYSTEM:
        # don't generate auto - reminders on dev - just too much to cleanup
        return


        
    if ticket_reminder and (date.today().weekday() in [2,6]):
        logger.debug(f"REMINDERS FOR {user.email}")
        all_open_tickets = Ticket.objects.filter(assigned_to=user).exclude(status__in=[Ticket.CLOSED_STATUS, Ticket.DUPLICATE_STATUS])
        
        date_14 = today - timedelta(days=14)
        date_14_str = date_14.strftime('%Y-%m-%d')
        ota_le_14 = all_open_tickets.filter(modified__lte=date_14_str)

        for t in ota_le_14:

            rem = VinceReminder.objects.update_or_create(
                title=f'Ticket {t.title} is OPEN and has not been modified for over 14 days. Do you want to close or update this ticket?',
                ticket=t,
                user=user,
                defaults={'alert_date':timezone.now()})

    my_cases = CaseAssignment.objects.filter(assigned=user).distinct().values_list('case', flat=True)
    #get all active, non-published cases
    cases = VulnerabilityCase.objects.filter(id__in=my_cases, status=1).exclude(vulnote__date_published__isnull=True)
    
    case_reminder = user.usersettings.settings.get('reminder_publication', True)
    if case_reminder:
        logger.debug(f"CASE REMINDERS FOR {user.email}")
        for c in cases:
            if user.usersettings.settings.get('muted_cases'):
                if c.id in user.usersettings.settings['muted_cases']:
                    # skip this case
                    continue
            if c.due_date == None:
                continue
            due_date = c.due_date.strftime('%Y-%m-%d')
            if date.today() > c.due_date.date():
                
                rem = VinceReminder.objects.update_or_create(
                    title=f'Case {c.vu_vuid} was expected to be published on {due_date}. Do you want to change the date?',
                    case=c,
                    user=user,
                    defaults = {'alert_date':timezone.now()})
            else:
                rem = VinceReminder.objects.update_or_create(
                    title=f'Case {settings.CASE_IDENTIFIER}{c.vuid} is expected to be published TODAY.',
                    case=c,
                    user=user,
                    defaults = {'alert_date':timezone.now()})

    vendors_seen = user.usersettings.settings.get('reminder_vendor_views', True)

    # run on Sundays and Wednesdays
    if vendors_seen and (date.today().weekday() in [2,6]):
        logger.debug(f"Vendor view REMINDERS FOR {user.email}")
        date_7 = today - timedelta(days=7)
        date_7_str = date_7.strftime('%Y-%m-%d')
        for c in cases:
            if user.usersettings.settings.get('muted_cases'):
                if c.id	in user.usersettings.settings['muted_cases']:
                    # skip this case
                    continue
            vendors = list(VulnerableVendor.objects.filter(case=c, seen=False, contact_date__lte=date_7_str).exclude(contact_date__isnull=True).values_list('contact__vendor_name', flat=True))
            if vendors:
                vendor_str = ", ".join(vendors)
                old_rems = VinceReminder.objects.filter(title__icontains="have not viewed",
                                                        case=c,
                                                        user=user).first()
                if old_rems:
                    old_rems.title = f'{len(vendors)} have not viewed case {c.vu_vuid}: {vendor_str}'
                    old_rems.alert_date = timezone.now()
                    old_rems.save()
                else:
                    rem = VinceReminder(
                        title=f'{len(vendors)} have not viewed case {c.vu_vuid}: {vendor_str}',
                        case=c,
                        user=user,
                        alert_date=timezone.now())
            else:
            #this case is good - remove any reminder
                old_rems = VinceReminder.objects.filter(title__icontains="have not viewed",
                                                        case=c,
                                                        user=user)
                for x in old_rems:
                    x.delete()

    # vendor status

    vendor_status = user.usersettings.settings.get('reminder_vendor_status', True)
    # RUN on Sundays
    # find cases expected to publish during this week
    if vendor_status and date.today().weekday() == 6:
        logger.debug(f"VENDOR STATUS REMINDERS FOR {user.email}")
        date_7 = today + timedelta(days=6)
        date_7_str = date_7.strftime('%Y-%m-%d')
        today_str = today.strftime('%Y-%m-%d')
        soon_cases = cases.filter(due_date__gte=today_str, due_date__lte=date_7_str).exclude(due_date__isnull=True)
        for s in soon_cases:
            if user.usersettings.settings.get('muted_cases'):
                if s.id	in user.usersettings.settings['muted_cases']:
                    # skip this case
                    continue
            #look for vendors without statements
            vendors = list(VulnerableVendor.objects.filter(case=s, seen=True, statement_date__isnull=True).values_list('contact__vendor_name', flat=True))
            if vendors:
                vendor_str = ", ".join(vendors)
                old_rems = VinceReminder.objects.filter(title__icontains="provided a statement",
                                                        case=c,
                                                        user=user).first()
                if old_rems:
                    old_rems.title=f"{len(vendors)} have not provided a statement to case {c.vu_vuid}: {vendor_str}",
                    old_rems.alert_date = timezone.now()
                    old_rems.save()
                else:
                    rem = VinceReminder(
                        title=f"{len(vendors)} have not provided a statement to case {c.vu_vuid}: {vendor_str}",
                        case=c,
                        user=user,
                        alert_date=timezone.now())
                    rem.save()
            else:
                old_rems = VinceReminder.objects.filter(title__icontains="provided a statement",
                                                        case=c,
                                                        user=user)
                for x in old_rems:
                    x.delete()

    #old cases
    old_cases = user.usersettings.settings.get('reminder_cases', True)
    if old_cases:
        logger.debug(f'REMIND ABOUT OLD CASES')
        date_14 = today - timedelta(days=14)
        date_14_str = date_14.strftime('%Y-%m-%d')

        old_c = cases.filter(modified__lte=date_14_str)
        for x in old_c:
            if user.usersettings.settings.get('muted_cases'):
                if x.id	in user.usersettings.settings['muted_cases']:
                    # skip this case
                    continue
            rem = VinceReminder.objects.update_or_create(
                title=f"Case {x.vu_vuid} hasn't been modified in over 14 days.",
                case=x,
                user=user,
                defaults={'alert_date':timezone.now()})

        new_c = cases.exclude(modified__lt=date_14_str)
        for x in new_c:
            old_rems = VinceReminder.objects.filter(title__icontains="been modified in over 14 days",
                                                    case=c,
                                                    user=user)
            for x in old_rems:
                x.delete()
            
def send_worker_email_all(to, subject, content, tkt, from_user):

    try:
        client = boto3.client('sns', settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_TRACK_SNS_ARN,
            Subject="Send email all",
            Message="email all",
            MessageAttributes={
                'MessageType': {
                    'DataType': 'String',
                    'StringValue': "EmailAll",
                },
                'Message': {
                    'DataType': 'String',
                    'StringValue': content
                },
                'Subject': {
                    'DataType': 'String',
                    'StringValue': subject
                },
                'To_group': {
                    'DataType': 'String',
                    'StringValue': to
                },
                'Ticket': {
                    'DataType': 'String',
                    'StringValue': str(tkt)
                },
                'From_User': {
                    'DataType': 'String',
                    'StringValue': str(from_user)
                },
            })

        logger.debug(f"Response:{response}")
    except:
        logger.debug(traceback.format_exc())
            
            
def reset_user_mfa(attributes, body):
    logger.debug(attributes)
    logger.debug(body)

    email = attributes['User']

    user = User.objects.using('vincecomm').filter(username=email).first()
    if not user:
        send_error_sns("MFA Reset", "MFA Reset Initiation Error", f"User with email {email} requested MFA reset, but user does not exist")
        return

    queue = TicketQueue.objects.filter(title='Inbox').first()

    if not queue:
        send_error_sns("MFA Reset", "Configuration Error for MFA Reset", f"User with email {email} requested MFA reset, but Inbox queue does not exist")
        return
    
    ticket = Ticket(title = f"Confirm MFA reset for {user.email}",
                    status = Ticket.CLOSED_STATUS,
                    submitter_email = email,
                    queue = queue,
                    description=f"User initiated MFA reset\r\nReason:\r\n{body}")
    ticket.save()

    # don't create more of these, if one exists already                                                                                    

    mfatkt = MFAResetTicket.objects.update_or_create(user_id=int(user.id),
                                                     ticket=ticket)
    
    email_template = EmailTemplate.objects.get(template_name="mfa_reset_request")
    
    
    notification = VendorNotificationEmail(subject=email_template.subject,
                                           email_body = email_template.plain_text)
    notification.save()
    
    email = VinceEmail(ticket=ticket,
                       notification=notification,
                       email_type=1,
                       to=user.email)
    email.save()

    send_reset_mfa_email(user, ticket, "mfa_reset_request")

    email_content = get_mail_content(ticket, "mfa_reset_request")
    
    fup = FollowUp(title=f"Email sent to {user.email} confirming MFA reset request.",
                   comment=email_content,
                   ticket=ticket)
    
    fup.save()





        
    

        

        

        
