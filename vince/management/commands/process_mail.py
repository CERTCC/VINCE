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

from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command
import sys
import os
import json
from vince.models import *
from vince.lib import create_ticket_from_email_s3
from datetime import datetime, timedelta
from datetime import timezone
import dateutil.parser
import boto3
import traceback

class Command(BaseCommand):
    help = 'Read an email from S3 given the object key'

    def add_arguments(self, parser):
        parser.add_argument('--key', nargs=1, type=str, help='Object Key to Read')
        parser.add_argument('--bucket', nargs=1, type=str, help='Bucket to read from')

    def handle(self, *args, **options):

        self.stdout.write("Reading email " + options['key'][0] + " from bucket " + options['bucket'][0])
        email_msg = create_ticket_from_email_s3(options['key'][0], options['bucket'][0])
        self.stdout.write(self.style.SUCCESS("Successfully read email"))
        
