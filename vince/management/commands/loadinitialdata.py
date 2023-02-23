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
import os.path
from os import path
from django.core.management.base import BaseCommand
from django.core.management import call_command
from vince.models import *
from vinny.models import *

from django.contrib.auth.models import Group
from django.conf import settings

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Load Initial Data'

    def handle(self, *args, **options):
        #if EmailTemplate.objects.count() > 0:
        #    logger.info("Email templates exist. Skipping creation.")
        #else:
        #load updated templates all the time
        if TicketQueue.objects.count() > 0:
            logger.info("Ticket queues exist. Skipping creation.")
        else:
            logger.info("Loading ticket queues.")
            call_command('loaddata', 'TicketQueue.json')
            logger.info("Done loading ticket queues.")


        if settings.VINCE_NAMESPACE == 'vince':
            if Group.objects.count() > 0:
                logger.info("Groups already exist")
            else:
                logger.info("Loading Groups.")
                call_command('loaddata', 'auth_group.json')
                logger.info("Done loading groups.")

            logger.info("Loading email templates.")
            if EmailTemplate.objects.count() > 0:
                logger.info("Email Templates already exist")
                # just need to update templates, not rewrite them
                call_command('loadtemplates', 'vince/fixtures/EmailTemplate.json')
            else:
                call_command('loaddata', 'EmailTemplate.json')
                logger.info("Done loading email templates.")

            if CWEDescriptions.objects.count() > 0:
                logger.info("CWE Info already exists")
            else:
                call_command('loadcwe', 'vince/fixtures/cwe_regular.json')
                logger.info("Done loading CWE Info")
                
            #call_command('copy_contact_uuid')

            #logger.info("Loading Contact Info")
            #if settings.INITIAL_CONTACT_FILE:
                #if path.exists(settings.INITIAL_CONTACT_FILE):
            #        call_command('loadsrmail', 'cmgr-contacts.srmail')
            #        logger.info("Done loading contacts")
            #        logger.info("Copy contacts to vincecomm")
            #        call_command('copy_contacts')
            #        logger.info("Done copying contacts to vincecomm")

        elif settings.VINCE_NAMESPACE == "vinny":
            logger.info("Removing all Email Templates in vincecomm")
            EmailTemplate.objects.using('vincecomm').all().delete()
            logger.info("Loading email templates for vincecomm.")
            call_command('loaddata', 'EmailTemplate.json')
            logger.info("Done loading email templates for vincecomm.")
            num_templates = EmailTemplate.objects.using('vincecomm').count()
            logger.info(f"Vincecomm has {num_templates} Email Templates")
            if Group.objects.using('vincecomm').count() > 0:
                logger.info("VINCEComm groups already exist")
            else:
                logger.info("Loading VINCEComm Groups.")
                call_command('loaddata', 'authgroup.vincecomm.json')
                logger.info("Done loading VINCEComm Groups.")
