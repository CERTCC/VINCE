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
import os
import boto3
import traceback
from django.conf import settings
import logging
from vinny.lib import send_post_email, send_usermention_notification, send_vc_daily_digest, send_message_to_all_group, create_mail_notice
from vinny.models import PostRevision, VCDailyNotification, Message
from vinny.mailer import send_newmessage_mail
from django.contrib.auth.models import User, Group

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
        logger.debug("Error in send_sns " + traceback.format_exc())
        print('Error publishing to SNS')


@csrf_exempt
def vincecomm_send_email(request):
    logger.debug("Received comm request")

    if request.method == 'POST':
        try:
            message = request.body.decode('utf-8')
            attributes = {}
            body_data = json.loads(message)
            logger.debug(f"Email body is {body_data}")

            if body_data.get('MessageAttributes'):
                if body_data['MessageAttributes'].get('MessageType'):
                    attributes['MessageType'] = body_data['MessageAttributes'].get('MessageType').get('Value')

        except Exception:
            error_msg = "%s" % (traceback.format_exc())
            logger.debug("Message is not valid json Error is " + error_msg)
            #send_sns('vinceworker', 'issue with json load of HTTP POST', error_msg)
            return HttpResponse(status=404)

        if attributes.get('MessageType'):
            #this is a message
            message = body_data.get('Message')
            if attributes['MessageType'] == "PostNotify":
                attributes['Post'] = body_data['MessageAttributes'].get('Post').get('Value')
                post = attributes.get('Post')
                instance = get_object_or_404(PostRevision, id=int(post))
                emails = send_usermention_notification(instance.post, instance.content)
                send_post_email(instance.post, emails)
            elif attributes['MessageType'] == "MessageNotify":
                attributes['Message'] = body_data['MessageAttributes'].get('Message').get('Value')
                message = attributes.get('Message')
                instance = get_object_or_404(Message, id=int(message))
                #now get all people to send this to
                for u in instance.thread.userthread_set.exclude(user=instance.sender):
                    send_newmessage_mail(instance, u.user)
                    create_mail_notice(u.user)
            elif attributes['MessageType'] == "MessageNotifyAll":
                content = body_data['MessageAttributes'].get('Message').get('Value')
                subject = body_data['MessageAttributes'].get('Subject').get('Value')
                to_group = body_data['MessageAttributes'].get('To_group').get('Value')
                from_user = body_data['MessageAttributes'].get('From_User').get('Value')
                from_group = body_data['MessageAttributes'].get('From_Group').get('Value')
                from_user = get_object_or_404(User, email=from_user)
                from_group = get_object_or_404(Group, id=int(from_group))
                send_message_to_all_group(to_group, subject, content, from_user, from_group.groupcontact.contact.vendor_name)
                
                
            return JsonResponse({'response':'success'}, status=200)


    return HttpResponse(f"Request: {request}")



@csrf_exempt
def send_daily_digest(request):

    if request.method == 'POST':
        taskname = request.META.get('HTTP_X_AWS_SQSD_TASKNAME')
        logger.debug(f"Task name is {taskname}")
        logger.debug("HTTP SQS Schedule at value is " + request.META.get('HTTP_X_AWS_SQSD_SCHEDULED_AT'))
        if taskname != "dailydigest":
            return HttpResponse(status=404)

        notifications = VCDailyNotification.objects.all().distinct('user').values_list('user', flat=True)

        users = User.objects.filter(id__in=notifications)

        for u in users:
            send_vc_daily_digest(u)

        return JsonResponse({'response':'success'}, status=200)




@csrf_exempt
def vt_daily_digest(request):
    #we don't want to return 404s too many times so just return a success
    # for this periodic task
    return JsonResponse({'response':'success'}, status=200)


