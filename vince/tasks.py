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
from __future__ import absolute_import, unicode_literals

import json
import os
import traceback

import boto3
from celery.utils.log import get_task_logger
from django.conf import settings
from vince.forms import TicketForm, CreateCaseRequestForm
from vince.lib import (
    parse_vul_report,
    process_s3_download,
    update_vendor_status,
    update_vendor_view_status,
    parse_vendor_statement,
    update_vendor_status_statement,
    create_ticket,
    create_case_post_action,
    create_action,
    add_case_artifact,
    update_case_request,
    create_ticket_from_email,
    create_ticket_from_email_s3,
)
from vince.models import *
from vinny.lib import update_post, add_vendor_case, add_vul_case, add_participant_case
from vince.mailer import send_newticket_mail, send_encrypted_mail
from vinny.models import *
from vince.serializers import CaseRequestSerializer
from .celery import app
import email

logger = get_task_logger(__name__)
logger.setLevel(logging.DEBUG)


def vince_retrieve_submission(cr, reporttype, vrf, attachment):

    s3 = boto3.resource("s3", region_name="us-east-2")

    if reporttype == "gov":
        filename = "GOV_reports/%s.txt" % vrf
    else:
        filename = "VRF_submissions/%s.txt" % vrf

    obj = s3.Object(settings.VP_PRIVATE_BUCKET_NAME, filename)

    logger.debug(obj)

    message = None
    try:
        message = obj.get()["Body"].read().decode("utf-8")
        logger.debug(message)

        if message:
            cr.description = message
            cr.save()

        # create the followup
        followup = FollowUp(ticket=cr, title=cr.title)
        followup.save()
        if attachment:
            followup = FollowUp.objects.get(ticket=cr)
            process_s3_download(followup, attachment)

        send_newticket_mail(followup=followup, files=None, user=None)

    except:
        logger.debug(traceback.format_exc())
        logger.warning("File does not exist")


def vince_retrieve_vrf(bucket, filename, queue, request_type, attachment=None):

    s3 = boto3.resource("s3", region_name="us-east-2")

    obj = s3.Object(bucket, filename)

    logger.debug(obj)

    message = None
    try:
        message = obj.get()["Body"].read().decode("utf-8")

        logger.debug(message)
    except:
        logger.debug(traceback.format_exc())
        logger.warning("File does not exist")

    if message:

        if request_type == 2:
            logger.warning("Vendor Statement!")
            cr = parse_vendor_statement(message)
            rv = update_vendor_status_statement(cr)
            if rv == None:
                queue = TicketQueue.objects.filter(title=queue).first()
                data = {"title": "New Vendor Statement", "queue": queue.id, "body": message}
                form = TicketForm(data)
                form.fields["queue"].choices = [(queue.id, queue.title)]
                if form.is_valid():
                    ticket = form.save()
                else:
                    logger.debug(form.errors)

        else:
            logger.warning("CREATING CASE REQUEST!!!")

            # now make a case request
            cr = parse_vul_report(message)
            cr["submission_type"] = "web"
            # this is just a value to get it past the form validity check
            # the queue choice in form.save takes precendence over form option
            logger.debug("queue is %s" % queue)
            queue = TicketQueue.objects.filter(title=queue).first()
            if queue:
                cr["queue"] = queue.id
            else:
                cr["queue"] = 2
            form = CreateCaseRequestForm(cr)
            # add default queue options
            form.fields["queue"].choices = [(q.id, q.title) for q in TicketQueue.objects.all()]
            logger.debug(cr["queue"])
            if form.is_valid():
                logger.warning("saving case")
                case = form.save(submission=message, queue=queue)
                case.request_type = request_type
                case.save()
            else:
                logger.warning("ERRRORS WITH CASE")
                logger.debug(form.errors)

        if attachment:
            os.umask(0)
            followup = FollowUp.objects.get(ticket=case)
            path = "vince/attachments/%s/%s" % (case.ticket_for_url, followup.id)
            att_path = os.path.join(settings.MEDIA_ROOT, path)
            if settings.DEFAULT_FILE_STORAGE == "django.core.files.storage.FileSystemStorage":
                if not os.path.exists(att_path):
                    os.makedirs(att_path, 0o777)

            logger.debug(att_path)
            logger.debug(attachment)
            f_path = os.path.join(att_path, attachment)
            key = "VRF_uploaded_files/" + attachment
            copy_source = {"Bucket": bucket, "Key": key}
            # copy file into s3 bucket
            bucket = s3.Bucket("vincetrack")
            bucket.copy(copy_source, "vince_attachments/" + attachment)
            process_s3_download(followup, attachment)
            # attach it to ticket


#            s3.download_file(bucket, key, f_path)


def vince_delete_sqs(message):
    queue_url = settings.AWS_UPDATE_QUEUE
    sqs = boto3.client("sqs")

    response = sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message.receipt_handle)

    logger.warning("deleting message...")
    logger.debug(response)
    message.deleted_from_queue = True
    message.save()


def delete_sqs(url, receipt_handle):
    sqs = boto3.client("sqs")

    response = sqs.delete_message(QueueUrl=url, ReceiptHandle=receipt_handle)


@app.task
def vince_poll_vinny_sqs():
    logger.warning("polling sqs...")

    queue_url = "https://sqs.us-east-1.amazonaws.com/137743039930/vinny"
    sqs = boto3.client("sqs")
    messages = []
    while True:
        response = sqs.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["SentTimestamp"],
            MaxNumberOfMessages=1,
            MessageAttributeNames=["All"],
            WaitTimeSeconds=20,
        )

        try:
            messages.extend(response["Messages"])
        except KeyError:
            logger.debug("breaking")
            break

    for message in messages:
        receipt_handle = message["ReceiptHandle"]
        try:
            resp = json.loads(message["Body"])
            obj_key = resp["Records"][0]["s3"]["object"]["key"]
            logger.debug(resp["Records"][0]["eventName"])
        except:
            logger.debug(resp)
            logger.debug(traceback.format_exc())
            response = sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
            continue
        s3 = boto3.resource("s3", region_name="us-east-1")
        obj = s3.Object("bigvince", obj_key)
        if obj:
            fkey = obj.key
            body = obj.get()["Body"].read().decode("utf-8")
            case = json.loads(body)
            if fkey.startswith("post"):
                update_post(case)
            elif fkey.startswith("addvendors"):
                add_vendor_case(case)
            elif fkey.startswith("vul"):
                add_vul_case(case)
            elif fkey.startswith("participant"):
                add_participant_case(case)
            else:
                oldcase = Case.objects.filter(vuid=case["vuid"]).first()
                if oldcase:
                    # do update
                    oldcase.title = case["title"]
                    oldcase.due_date = case["due_date"]
                    oldcase.summary = case["summary"]
                    oldcase.save()
                else:
                    # create a case
                    newcase = Case(
                        vuid=case["vuid"],
                        title=case["title"],
                        due_date=case["due_date"],
                        summary=case["summary"],
                        vince_id=case.get("id", 0),
                    )
                    newcase.save()

        # delete message
        try:
            response = sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
            logger.debug("deleted message")
        except:
            logger.debug(response)
            logger.debug("problem deleting message")
        # do something


@app.task
def vince_pub_report_sqs():
    logger.warning("polling sqs...")

    queue_url = settings.VINCE_TRACK_SNS_ARN
    sqs = boto3.client("sqs", settings.AWS_REGION)
    messages = []

    govqueue = TicketQueue.objects.filter(title="GOV").first()
    vulqueue = TicketQueue.objects.filter(title="CR").first()

    while True:
        response = sqs.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["SentTimestamp"],
            MaxNumberOfMessages=1,
            MessageAttributeNames=["All"],
            WaitTimeSeconds=20,
        )

        try:
            messages.extend(response["Messages"])
        except KeyError:
            break

    for message in messages:
        receipt_handle = message["ReceiptHandle"]
        try:
            reporttype = "vul"
            resp = json.loads(message["Body"])
            if "MessageAttributes" in resp:
                attr = resp["MessageAttributes"]
                reporttype = attr["ReportType"]["Value"]

            if "Message" in resp:
                data = json.loads(resp["Message"])

                data["submission_type"] = "web"
                if data["credit_release"] == "No":
                    data["credit_release"] = False
                else:
                    data["credit_release"] = True
                if reporttype == "gov":
                    data["request_type"] = CaseRequest.GOV_FORM
                    data["queue"] = govqueue.id
                    data["product_name"] = data["affected_website"]
                else:
                    data["queue"] = vulqueue.id

                cr = CaseRequestSerializer(data=data)
                if cr.is_valid():
                    cr = cr.save()
                    if cr.request_type == CaseRequest.VRF_FORM:
                        vcr = cr.pk
                        # duplicate this in vincecomm
                        cr.pk = None
                        vc_cr = cr.save(using="vincecomm")
                        #### now add vc_id in vt instance for vrfs
                        cr.vc_id = vc_cr.id
                        cr.pk = vcr
                        cr.save()

                    response = sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
                    vince_retrieve_submission(cr, reporttype, data["vrf_id"], data.get("s3_file_name"))

                    if cr.request_type == CaseRequest.GOV_FORM:
                        # test sending email
                        send_encrypted_mail(
                            settings.DEFAULT_FROM_EMAIL, "Test sending encrypted mail from VINCE", "This is a test"
                        )

                else:
                    logger.debug(cr.errors)

        except:
            logger.debug(traceback.format_exc())
            logger.debug("ERROR loading message")
            response = sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)


@app.task
def vince_poll_sqs():
    logger.warning("polling sqs...")

    queue_url = settings.AWS_UPDATE_QUEUE
    sqs = boto3.client("sqs")
    messages = []
    while True:
        response = sqs.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["SentTimestamp"],
            MaxNumberOfMessages=1,
            MessageAttributeNames=["All"],
            WaitTimeSeconds=20,
        )

        try:
            messages.extend(response["Messages"])
        except KeyError:
            break

    for message in messages:
        receipt_handle = message["ReceiptHandle"]
        if "MessageAttributes" in message:
            # this is a message
            attributes = {}
            attr = message["MessageAttributes"]
            attributes["MessageType"] = attr["MessageType"]["StringValue"]
            attributes["Case"] = attr["Case"]["StringValue"]
            if "Queue" in attr:
                attributes["Queue"] = attr["Queue"]["StringValue"]
            attributes["Table"] = attr["Table"]["StringValue"]
            attributes["User"] = attr["User"]["StringValue"]
            if "Group" in attr:
                attributes["Group"] = attr.get("Group").get("StringValue")

            if attributes["MessageType"] == "UpdateStatus":
                update_vendor_status(attributes, message["Body"])
                logger.debug("updated vendor status")
            elif attributes["MessageType"] == "VendorLogin":
                update_vendor_view_status(attributes, message["Body"])
            elif attributes["MessageType"] == "NewTicket":
                logger.debug("NEED TO CREATE A NEW TICKET")
                create_ticket(attributes, message["Body"])
            elif attributes["MessageType"] in ["NewPost", "EditPost"]:
                create_case_post_action(attributes, message["Body"])
            elif attributes["MessageType"] == "EditContact":
                create_action(attributes, message["Body"])
            elif attributes["MessageType"] == "NewFile":
                add_case_artifact(attributes, message["Body"])
            elif attributes["MessageType"] == "CRUpdate":
                update_case_request(attributes, message["Body"])
            logger.debug("deleting item")
            delete_sqs(queue_url, receipt_handle)
        else:
            # this is an event
            try:
                resp = json.loads(message["Body"])
            except:
                logger.debug("ERROR loading message")
            try:
                obj_key = resp["Records"][0]["s3"]["object"]["key"]
                logger.debug(resp["Records"][0]["eventName"])
                bucket = resp["Records"][0]["s3"]["bucket"]["name"]
                if obj_key.startswith("GOV"):
                    logger.debug("IN GOV")
                    report_type = 3
                    queue_name = "GOV"
                elif obj_key.startswith("Vendor"):
                    report_type = 2
                    queue_name = "General"
                else:
                    report_type = 1
                    queue_name = "CR"
                vince_retrieve_vrf(bucket, obj_key, queue_name, report_type)
            except:
                logger.debug(traceback.format_exc())
                pass

            if "Message" in resp:
                message = resp["Message"]
                email_msg = None
                try:
                    msg = json.loads(message)
                    if "content" in msg:
                        # this is email
                        content = msg["content"]
                        email_msg = create_ticket_from_email(content)
                    elif "receipt" in msg:
                        if msg["receipt"].get("action"):
                            if msg["receipt"]["action"].get("type") == "S3":
                                # this is an email notification
                                # When CERTmail goes live we will probably want to switch the following:
                                if msg["receipt"]["action"].get("bucketName") == settings.EMAIL_BUCKET:
                                    logger.debug(
                                        "vince_poll_sqs is processing an email that showed up in the S3 bucket"
                                    )
                                    # if msg["receipt"]["action"].get("bucketName") == "vince-email":
                                    email_msg = create_ticket_from_email_s3(msg["receipt"]["action"].get("objectKey"))
                except:
                    logger.debug(traceback.format_exc())
                    pass

                if email_msg:
                    delete_sqs(queue_url, receipt_handle)
                else:
                    cr = parse_vul_report(resp["Message"])

                    if ("title" in cr) and ("vrf_id" in cr):
                        newcr = VinceSQS(
                            title=cr["title"],
                            date_submitted=cr["date_submitted"],
                            vrf_id=cr["vrf_id"],
                            receipt_handle=receipt_handle,
                            report_type=cr["report_type"],
                        )
                        newcr.save()
                        if "filename" in cr:
                            logger.debug("GOT FILE %s" % cr["filename"])
                            newcr.attached_file = cr["filename"]
                            newcr.save()
                        vince_delete_sqs(newcr)
                        if newcr.report_type == 2:
                            key = "Vendor_statements/%s.txt" % cr["vrf_id"]
                            queue_name = "General"
                        elif newcr.report_type == 3:
                            key = "GOV_reports/%s.txt" % cr["vrf_id"]
                            queue_name = "GOV"
                        else:
                            key = "VRF_submissions/%s.txt" % cr["vrf_id"]
                            queue_name = "CR"
                        vince_retrieve_vrf(
                            settings.S3_INCOMING_REPORTS, key, queue_name, newcr.report_type, newcr.attached_file
                        )
                    else:
                        delete_sqs(queue_url, receipt_handle)
