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
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
import json
from vince.apps import VinceTrackConfig
from vince.models import VinceSQS, TicketQueue, FollowUp, CaseRequest, AdminPGPEmail, Contact, ContactGroup, EmailContact, PhoneContact, ContactPgP, GroupMember, VendorNotification, VTDailyNotification, GroupSettings
import os
import boto3
import traceback
from django.conf import settings
from django.template.loader import get_template
from django.forms.models import model_to_dict

from vince.forms import TicketForm, CreateCaseRequestForm
from vince.lib import update_vendor_status, update_vendor_view_status, create_ticket, create_case_post_action, create_action, process_s3_download, add_case_artifact, update_case_request, create_ticket_from_email_s3, update_vendor_status_statement, create_bounce_ticket, send_vt_daily_digest, generate_vt_reminders, reset_user_mfa, prepare_and_send_weekly_report
from vinny.lib import send_post_email, send_usermention_notification
from django.contrib.auth.models import User
from vinny.models import PostRevision
from vince.serializers import CaseRequestSerializer
import re
from shutil import copyfile
from vince.mailer import send_newticket_mail, send_encrypted_mail, send_vendor_email_notification, send_email_to_all
import tempfile
import datetime
from django.utils import dateformat
from datetime import timedelta
from datetime import timezone
from collections import namedtuple
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def send_sns(vul_id, issue, error):
    subject = "%s: %s" % (vul_id, issue)
    try:
        client = boto3.client('sns',settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_ERROR_SNS_ARN,
            Subject=subject,
            Message=error)
        print("Response:{}".format(response))

    except:
        logger.debug(traceback.format_exc())
        print('Error publishing to SNS')


def vince_retrieve_submission(cr, vrf, attachment):

    s3 = boto3.resource('s3', region_name=settings.AWS_REGION)

    logger.debug(cr.request_type)

    if cr.request_type == CaseRequest.GOV_FORM:
        logger.debug("THIS IS A GOV FORM!")
        filename = "GOV_reports/%s.txt" % vrf
    else:
        filename = f"{settings.VRF_REPORT_DIR}/{vrf}.txt"
    
    obj = s3.Object(settings.VP_PRIVATE_BUCKET_NAME, filename)

    message = None
    try:
        message = obj.get()['Body'].read().decode('utf-8')

        if message:
            cr.description = message
            cr.save()
        #create the followup                                                          
        followup = FollowUp(ticket=cr, title=cr.title)
        followup.save()
        attach_object = None
        if attachment:
            logger.debug(attachment)
            copy_source = {'Bucket': settings.VP_PRIVATE_BUCKET_NAME,
                           'Key': settings.VRF_PRIVATE_MEDIA_LOCATION+"/"+attachment
            }
            #copy file into s3 bucket
            bucket = s3.Bucket(settings.PRIVATE_BUCKET_NAME)
            bucket.copy(copy_source, f'{settings.AWS_PRIVATE_MEDIA_LOCATION}/{attachment}')
            logger.debug("COPYING FILE")
            cr.user_file = attachment
            cr.save()
            logger.debug(cr.user_file.size)
            logger.debug(obj.content_length)
            logger.debug(obj.content_type)
            attach_object = process_s3_download(followup, attachment, obj.content_length, obj.content_type)

        if cr.request_type == CaseRequest.GOV_FORM:
            emails = AdminPGPEmail.objects.filter(active=True)
            report_template = get_template('vince/email-fwd-dotgov.txt')
            for email in emails:
                rv = send_encrypted_mail(email, cr.vrf_subject, report_template.render(context=model_to_dict(cr)), attach_object)
                if rv:
                    fup = FollowUp(ticket=cr, title=f"Error forwarding encrypted email to {email.email}", comment=rv)
                    fup.save()
                    continue
                fup = FollowUp(ticket=cr, title=f"Successfully forwarded email to {email.email}")
                fup.save()
            
        send_newticket_mail(followup=followup, files=None, user=None)

    except:
        logger.debug(traceback.format_exc())
        logger.warning("File does not exist")

        
@csrf_exempt
def vc_daily_digest(request):
    #we don't want to return 404s too many times so just return a success
    # for this periodic task
    return JsonResponse({'response':'success'}, status=200)
            

@csrf_exempt
def send_daily_digest(request):
    logger.debug("Received track daily digest request")

    if request.method == 'POST':
        taskname = request.META.get('HTTP_X_AWS_SQSD_TASKNAME')
        logger.debug(taskname)
        logger.debug(request.META.get('HTTP_X_AWS_SQSD_SCHEDULED_AT'))
        if taskname != "vtdailydigest":
            return HttpResponse(status=404)

        notifications = VTDailyNotification.objects.all().distinct('user').values_list('user', flat=True)

        users = User.objects.filter(id__in=notifications)

        for u in users:
            send_vt_daily_digest(u)

        return JsonResponse({'response':'success'}, status=200)


@csrf_exempt
def send_weekly_report(request):
    logger.debug("vinceworker send_weekly_report view triggered")

    if request.method == 'POST':
        taskname = request.META.get('HTTP_X_AWS_SQSD_TASKNAME')
        logger.debug(taskname)
        logger.debug(request.META.get('HTTP_X_AWS_SQSD_SCHEDULED_AT'))
        if taskname != 'weeklyreport':
            return HttpResponse(status=404)

        prepare_and_send_weekly_report()

        return JsonResponse({'response':'success'}, status=200)


@csrf_exempt
def generate_reminders(request):
    logger.debug("Received request for generating reminders")

    if request.method == "POST":
        taskname = request.META.get('HTTP_X_AWS_SQSD_TASKNAME')
        logger.debug(taskname)
        logger.debug(request.META.get('HTTP_X_AWS_SQSD_SCHEDULED_AT'))
        if taskname != "vtgenreminders":
            return HttpResponse(status=404)

        users = User.objects.filter(groups__name=VinceTrackConfig.name)

        for u in users:
            generate_vt_reminders(u)

        return JsonResponse({'response':'success'}, status=200)
        

@csrf_exempt
def ingest_vulreport(request):
    logger.debug("Received request")
    logger.debug(f"Request method is: {request.method}")

    if request.method == 'POST':
        try:
            message = request.body.decode('utf-8')
            attributes = {}
            body_data = json.loads(message)
            logger.debug(body_data)
            if body_data.get('MessageAttributes'):
                if body_data['MessageAttributes'].get('MessageType'):
                    attributes['MessageType'] = body_data['MessageAttributes'].get('MessageType').get('Value')
                    if body_data['MessageAttributes'].get('Case'):
                        attributes['Case'] = body_data['MessageAttributes'].get('Case').get('Value')
                    if body_data['MessageAttributes'].get('Queue'):
                        attributes['Queue'] = body_data['MessageAttributes'].get('Queue').get('Value')
                    if body_data['MessageAttributes'].get('Table'):
                        attributes['Table'] = body_data['MessageAttributes'].get('Table').get('Value')
                    if body_data['MessageAttributes'].get('User'):
                        attributes['User'] = body_data['MessageAttributes'].get('User').get('Value')
                    if body_data['MessageAttributes'].get('Group'):
                        attributes['Group'] = body_data['MessageAttributes'].get('Group').get('Value')
                    if body_data['MessageAttributes'].get('ReportType'):
                        attributes['ReportType'] = body_data['MessageAttributes'].get('ReportType').get('Value')
                    if body_data['MessageAttributes'].get('Message'):
                        attributes['Message'] = body_data['MessageAttributes'].get('Message').get('Value')
            govqueue = TicketQueue.objects.filter(title="GOV").first()
            vulqueue = TicketQueue.objects.filter(title="CR").first()
            
        except Exception:
            logger.debug(f"Message is not valid json")
            error_msg = "%s" % (traceback.format_exc())
            logger.debug(error_msg)
            #send_sns('vinceworker', 'issue with json load of HTTP POST', error_msg)
            return HttpResponse(status=404)

        if attributes.get('MessageType'):
            #this is a message
            message = body_data.get('Message')
            if attributes['MessageType'] == "UpdateSrmail":
                return write_srmail(request)
            if attributes['MessageType'] == "UpdateStatus":
                update_vendor_status(attributes, message)
                logger.debug("updated vendor status")
            elif attributes['MessageType'] == 'VendorLogin':
                update_vendor_view_status(attributes, message)
            elif attributes['MessageType'] in ['NewTicket', 'MessageReply']:
                create_ticket(attributes, message)
            elif attributes['MessageType'] in ['NewPost', 'EditPost', 'PostRemoved']:
                logger.debug("vendor posted in vc")
                create_case_post_action(attributes, message)
            elif attributes['MessageType'] == 'EditContact':
                create_action(attributes, message)
            elif attributes['MessageType'] == 'NewFile':
                add_case_artifact(attributes, message)
            elif attributes['MessageType'] == 'CRUpdate':
                update_case_request(attributes, message)
            elif attributes['MessageType'] == 'ResetMFA':
                reset_user_mfa(attributes, message)
            elif attributes['MessageType'] == 'PostNotify':
                post = body_data['MessageAttributes'].get('Post').get('Value')
                instance = get_object_or_404(PostRevision, id=int(post))
                emails = send_usermention_notification(instance.post, instance.content)
                send_post_email(instance.post, emails)
            elif attributes['MessageType'] == 'NotifyVendor':
                notification = get_object_or_404(VendorNotification, id=int(attributes['Group']))
                send_vendor_email_notification([notification.vendor.contact.id], notification.vendor.case, notification.notification.subject, notification.notification.email_body)
            elif attributes['MessageType'] == 'EmailAll':
                content = body_data['MessageAttributes'].get('Message').get('Value')
                subject = body_data['MessageAttributes'].get('Subject').get('Value')
                to_group = body_data['MessageAttributes'].get('To_group').get('Value')
                from_user = body_data['MessageAttributes'].get('From_User').get('Value')
                ticket = body_data['MessageAttributes'].get('Ticket').get('Value')
                from_user = get_object_or_404(User, email=from_user)
                send_email_to_all(to_group, subject, content, from_user, ticket)
                
            return JsonResponse({'response':'success'}, status=200)
                
        try:
            data = json.loads(body_data['Message'])
            logger.debug(data)
            if "notificationType" in data:
                #this is a bounce or a complaint
                if data['notificationType'] in ["Bounce", "Complaint"]:
                    mail = data.get("mail")
                    if mail:
                        headers = mail.get("commonHeaders")
                        if headers:
                            create_bounce_ticket(headers, data.get("bounce"))
                            return JsonResponse({'response':'success'}, status=200)
                    send_sns("email bounce", "Bounce notification received, but unexpected format", json.dumps(data))
                    return JsonResponse({'response':'success'}, status=200)
            
            if "receipt" in data:
                if data['receipt'].get('action'):
                    if data["receipt"]["action"].get("type") == "S3":
                        # this is an email notification
                        #if data["receipt"]["action"].get("bucketName") == settings.EMAIL_BUCKET:
                        email_msg = create_ticket_from_email_s3(data["receipt"]["action"].get("objectKey"), data["receipt"]["action"].get("bucketName"))
                        return JsonResponse({'response':'success'}, status=200)
            data['submission_type'] = 'web'

            if data.get('affected_website'):
                logger.debug("THIS IS A GOV FORM")
                data['request_type'] = CaseRequest.GOV_FORM
                data['queue'] = govqueue.id
                data['product_name'] = data['affected_website']
            elif data.get('ics_impact') and (data.get('ics_impact') == True):
                #is there an ICS queue?
                icsqueue = TicketQueue.objects.filter(title='INL-CR').first()
                if icsqueue:
                    data['queue'] = icsqueue.id
                else:
                    data['queue'] = vulqueue.id
            else:
                data['queue'] = vulqueue.id

            cr = CaseRequestSerializer(data=data)
            if (cr.is_valid()):
                cr = cr.save()
                if cr.request_type == CaseRequest.VRF_FORM:
                    if data.get('vc_id'):
                        cr.vc_id = data.get('vc_id')
                        cr.save()
                if cr.contact_email:
                    cr.submitter_email = cr.contact_email
                    cr.save()

                vince_retrieve_submission(cr, data['vrf_id'], data.get('s3_file_name'))
                return JsonResponse({'response':'success'}, status=200)
            else:
                logger.debug(cr.errors)
            
        except:
            logger.debug(traceback.format_exc())
            
    return HttpResponse(f"Request: {request}")


def find_cryptos(ckeys, f, srmail):

    Range = namedtuple('Range', ['start', 'end', 'key_id', 'proto'])
    range_list = []
    expired_list = []
    added_list = []
    dummy_range = Range(start=datetime.datetime(1999,12,21), end=datetime.datetime(2099,12,21),key_id="ABC123", proto="PGP")
    for key in ckeys:
        enddate = key.enddate
        startdate = key.startdate
        if enddate != "INDEFINITE":
            enddateobj = datetime.datetime.strptime(enddate, '%Y%m%d')
            if enddateobj < datetime.datetime.now():
                # don't care about expired ones                                                                                                                         
                expired_list.append(key)
                continue
            if startdate != "EPOCH":
                startdateobj = datetime.datetime.strptime(key.startdate, '%Y%m%d')
                r1 = Range(start=startdateobj, end=enddateobj, key_id=key.pgp_key_id, proto=key.pgp_protocol)
                range_list.append(r1)
            else:
                r1 = Range(start=None, end=enddateobj, key_id=key.pgp_key_id, proto=key.pgp_protocol)
                range_list.append(r1)
        else:
            if startdate != "EPOCH":
                startdateobj = datetime.datetime.strptime(key.startdate, '%Y%m%d')
                r1 = Range(start=startdateobj, end=None, key_id=key.pgp_key_id, proto=key.pgp_protocol)
                range_list.append(r1)
            else:
                r1 = Range(start=None, end=None, key_id=key.pgp_key_id, proto=key.pgp_protocol)
                range_list.append(r1)

    while len(range_list) > 1:
        earliest_start = min(range_list, key=lambda k: k.start if (k.start != None) else dummy_range.start)
        earliest_end = min(range_list, key=lambda k: k.end if (k.end != None) else  dummy_range.end)
        for old in added_list:
            # make sure not "EPOCH"
            if old.start and earliest_start.start:
                # if they are the same - change the new one to the end + 1
                if old.start == earliest_start.start:
                    # remove this one from the list
                    rllen = len(range_list)
                    range_list = [x for x in range_list if not(x.key_id == old.key_id)]
                    newrllen = len(range_list)
                    if rllen != newrllen:
                        # did we remove a key? not adding it back if it's not there.
                        if old.end:
                            earliest_start = Range(start=old.end + timedelta(days=1), end=earliest_start.end, key_id=old.key_id, proto=earliest_start.proto)
                            # add it back to the list
                            range_list.append(earliest_start)
        if len(range_list) == 0:
            # make sure we didn't just remove all of the keys in the last for loop
            break
        # find all keys in this range
        if earliest_start.start:
            write_start = earliest_start.start.strftime("%Y%m%d")
        else:
            write_start = "EPOCH"
        if earliest_end.end:
            f.write(srmail + "\tCRYPTO\t" + write_start + "\t" + earliest_end.end.strftime("%Y%m%d") + "\t" + earliest_start.proto)
        else:
            f.write(srmail + "\tCRYPTO\t" + write_start + "\tINDEFINITE\t" + earliest_start.proto)
        for r in range_list:
            if r.start and earliest_start.start:
                latest_start = max(earliest_start.start, r.start)
            elif r.start:
                latest_start = r.start
            else:
                latest_start = earliest_start.start

            if earliest_end.end and r.end:
                early_end = min(earliest_end.end, r.end)
                delta = (early_end - latest_start).days + 1
                overlap = max(0, delta)
                if overlap:
                    f.write("\tKEY=" + r.key_id)
            elif earliest_end.end and earliest_start.start:
                #most likely the r.end is INDEFINITE so just make sure start is before end
                if r.start <= earliest_end.end:
                    f.write("\tKEY=" + r.key_id)
            else:
                f.write("\tKEY=" + r.key_id)
            added_list.append(Range(start=earliest_start.start, end=earliest_end.end, key_id=r.key_id, proto=earliest_start.proto))
        f.write("\n")
        # remove from range_list the keys with this date range
        new_list = []
        for x in range_list:
            try:
                #don't care about start... if x.end is before the earliest_end - this one has been added
                #if x.start >= earliest_start.start and x.end <= earliest_end.end:
                if x.end <= earliest_end.end:
                    continue
                else:
                    new_list.append(x)
            except:
                # can't compare nonetypes with <=
                if x.start == earliest_start.start and x.end == earliest_end.end:
                    continue
                else:
                    new_list.append(x)
        range_list = new_list

    if len(range_list) == 1:
        crypto = range_list[0]
        for old in added_list:
            if crypto.end == None and old.end == None:
                # both "INDEFINITE"
                crypto = None
                break
            # make sure not "EPOCH"
            elif old.start and crypto.start:
                # if they are the same - change the new one to the end + 1
                if old.start <= crypto.start:
                    if old.end:
                        crypto = Range(start=old.end + timedelta(days=1), end=crypto.end, key_id=crypto.key_id, proto=crypto.proto)
                if crypto.end and old.end:
                    if crypto.end <= old.end:
                    # this one is encompassed in range of an old one
                        crypto = None
                        break
        if crypto:
            if crypto.start:
                write_start = crypto.start.strftime("%Y%m%d")
            else:
                write_start = "EPOCH"
            if crypto.end:
                f.write(srmail + "\tCRYPTO\t" + write_start + "\t" + crypto.end.strftime("%Y%m%d") + "\t" + crypto.proto)
            else:
                f.write(srmail + "\tCRYPTO\t" + write_start + "\tINDEFINITE\t" + crypto.proto)
            f.write("\tKEY=" + crypto.key_id + "\n")
            added_list.append(crypto)

    #write expired keys
    for crypto in expired_list:
        f.write(srmail + "\tCRYPTO\t" + crypto.startdate + "\t" + crypto.enddate + "\t" + crypto.pgp_protocol)
        f.write("\tKEY=" + crypto.pgp_key_id + "\n")


# This writes all active contact information into a strangely-formatted
# text file that only the authors truly understand
def write_srmail(request):
    logger.debug(f"WRITING SRMAIL")
    logger.debug(f"Request method is: {request.method}")
    if request.method != 'POST':
        return render(request, 'vincepub/404.html', {}, status=404)

    tmp = tempfile.NamedTemporaryFile()

    with open(tmp.name, 'w') as f:
        f.write("#Generated by VINCE: " + dateformat.format(datetime.datetime.now(), 'F j, Y, P T') + "\n\n")

        #create or update an all-vendor group:
        all_vendor_contact_group = ContactGroup.objects.filter(name="_all_vendors").first()
        if all_vendor_contact_group:

            #remove any current, inactive contacts
            inactive_members = GroupMember.objects.filter(group=all_vendor_contact_group, contact__active=False)
            for x in inactive_members:
                x.delete()

            #remove any non-vendors
            not_vendors = GroupMember.objects.filter(group=all_vendor_contact_group).exclude(contact__vendor_type='Vendor')
            for x in not_vendors:
                x.delete()
                
            all_vendor_contacts = Contact.objects.filter(active=True, vendor_type='Vendor')
            for c in all_vendor_contacts.exclude(groupmember__group = all_vendor_contact_group):
                try:
                    mem = GroupMember.objects.update_or_create(contact=c, group=all_vendor_contact_group)
                    logger.debug(f"Contact {c} needs to be added to all_vendors group")
                except Exception as e:
                    logger.debug(f"Contact {c} failed to be added to  all_vendors group error {e}")

        #write all the groups
        groups = ContactGroup.objects.order_by("srmail_peer_name")
        for group in groups:
            if group.status != "Active":
                logger.warning("not writing %s due to %s status" % (group.srmail_peer_name, group.status))
                continue
            srmail_peer_name = group.srmail_peer_name
            srmail_members = []
            members = GroupMember.objects.filter(group=group).order_by('contact__srmail_peer')
            # Don't write inactive contacts or groups to a srmail group - causes an error in srmail                                             
            for member in members:
                if member.contact:
                    if member.contact.active and len(member.contact.emailcontact_set.all()) > 0:
                        srmail_members.append(member.contact.srmail_peer)
                elif member.group_member:
                    if member.group_member.group.status == "Active":
                        srmail_members.append(member.group_member.group.srmail_peer_name)
            f.write("+"+srmail_peer_name+"\t"+' '.join(srmail_members[0:])+"\n")

        #create an all-contact group:
        all_contact = list(Contact.objects.filter(active=True, vendor_type='Contact').exclude(emailcontact__isnull=True).distinct().values_list('srmail_peer', flat=True))
        f.write("+_all_contacts\t"+' '.join(all_contact[0:])+"\n")
        f.write("\n")

        #create an all-coord group:
        all_coordinators = list(Contact.objects.filter(active=True, vendor_type='Coordinator').exclude(emailcontact__isnull=True).distinct().values_list('srmail_peer', flat=True))
        f.write("+_all_coordinators\t"+' '.join(all_coordinators[0:])+"\n")
        f.write("\n")
        
        contacts = Contact.objects.order_by("srmail_peer")
        for contact in contacts:
            try:
                srmail = contact.srmail_peer
                emails = EmailContact.objects.filter(contact=contact, status=True)
                if len(emails) == 0:
                    # don't write contacts without an email address, even if it's inactive
                    continue
                if (contact.active) or "Inactive" in contact.vendor_name:
                    vendor_name = srmail + "\tORG\t" + contact.vendor_name + "\n"
                    f.write(vendor_name.encode('ascii', 'ignore').decode('ascii'))
                    vendor_name = srmail + "\tVAR\tNAME\t" + contact.vendor_name + "\n"
                    f.write(vendor_name.encode('ascii', 'ignore').decode('ascii'))
                else:
                    vendor_name = srmail + "\tORG\t" + contact.vendor_name + " (Inactive)\n"
                    f.write(vendor_name.encode('ascii', 'ignore').decode('ascii'))
                    vendor_name = srmail + "\tVAR\tNAME\t" + contact.vendor_name + " (Inactive)\n"
                    f.write(vendor_name.encode('ascii', 'ignore').decode('ascii'))
                if contact.srmail_salutation:
                    f.write(srmail + "\tVAR\tsalutation\t" + contact.srmail_salutation + "\n")

                emails = EmailContact.objects.filter(contact=contact, status=True)
                for email in emails:
                    if not email.email:
                        logger.warn(f"Email field missing for Contact {email}")
                        continue
                    email_changed = ""
                    if not email.email_function:
                        email.email_function = "TO"
                        email_changed += "Field email.email_function is missing "
                    if not email.name:
                        email.name = email.email
                        email_changed += "Field email.name is missing "
                    email_str = srmail + "\t" + email.email_function + "\t" + email.email + "\t" + email.name + "\n"
                    if email_changed != "":
                        try:
                            email.save()
                            logger.debug(f"Updated email metadata for Contact {email} with {email_changed}")
                        except Exception as e:
                            logger.warning(f"Could not update email missing information {email_changed} for Contact {email} error {e}")
                    f.write(email_str.encode('ascii', 'ignore').decode('ascii'))
                phones = PhoneContact.objects.filter(contact=contact)
                for phone in phones:
                    if (contact.active):
                        if phone.comment:
                            f.write(srmail + "\tPHONE\t" + phone.phone_type + "\t" + phone.country_code + " " + phone.phone + "\t" + phone.comment + "\n")
                        else:
                            f.write(srmail + "\tPHONE\t" + phone.phone_type + "\t" + phone.country_code + " " + phone.phone + "\n")
                    else:
                        if phone.comment:
                            f.write(srmail + "\tPHONE\t" + phone.phone_type + "\t" + phone.country_code + " " + phone.phone + "\t" + phone.comment + " (Inactive)\n")
                        else:
                            f.write(srmail + "\tPHONE\t" + phone.phone_type + "\t" + phone.country_code + " " + phone.phone + "\t (Inactive)\n")

                cryptos = ContactPgP.objects.filter(contact=contact,revoked=False)
                if cryptos:
                    find_cryptos(cryptos, f, srmail)
                if contact.location:
                    f.write(srmail + "\tVAR\tlocation\t" + contact.location + "\n")
                if contact.lotus_id:
                    f.write(srmail + "\tVAR\tVEND\t" + str(contact.lotus_id).zfill(6) + "\n")
                if not(contact.active):
                    f.write(srmail + "\tSTATUS\tDISABLED\n")
                f.write("\n")
            except:
                logger.warning(f"Problem writing {srmail}")
                send_sns(srmail, "Problem writing to srmail file", traceback.format_exc())
                continue

        f.close()
        f = open(tmp.name, 'rb')


        #copyfile(tmp.name, "cmgr-contact-test.srmail")
        
        s3 = boto3.client('s3', region_name=settings.AWS_REGION)
        s3.put_object(Body=f,
                      Bucket=settings.ANCIENT_SRMAIL_BUCKET,
                      Key="cmgr-contacts.srmail")
                      
        #send_sns("SRMAIL", "SRMAIL FILE WRITTEN", "SRMAIL file successfully rewritten")
        
        
    return JsonResponse({'response':'success'}, status=200)
