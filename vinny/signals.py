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
import logging
from django.dispatch import receiver
from django.db.models.signals import post_save
from vinny.models import PostRevision, message_sent
from vinny.lib import send_comm_worker
from django.dispatch import Signal

logger = logging.getLogger(__name__)


@receiver(post_save, sender=PostRevision)
def send_notification(sender, instance, created, **kwargs):
    if created:
        if instance.revision_number == 0:
            #emails = send_usermention_notification(instance.post, instance.content)
            #send_post_email(instance.post, emails)
            send_comm_worker(instance)
            return
        
    logger.info("this is an update, no need to send")

    
@receiver(message_sent)
def send_message_notification(sender, message, thread, reply, **kwargs):
    send_comm_worker(None, message)
