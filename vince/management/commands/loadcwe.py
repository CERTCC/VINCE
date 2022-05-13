# -*- coding: utf-8 -*-                                                         
from __future__ import unicode_literals
import os
import sys
import json
from django.core.management.base import BaseCommand, CommandError
from vince.models import CWEDescriptions
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Import vulnerability data into postgres db'
    
    def add_arguments(self, parser):
        parser.add_argument('in', nargs=1, type=str)

        
    def handle(self, *args, **options):
        with open(options['in'][0], 'r') as f:
            data = json.load(f)
            num_cwes = 0
            for x in data["examples"]:
                c = CWEDescriptions.objects.update_or_create(cwe = x)
                num_cwes = num_cwes + 1

            logger.info(f"Updated {num_cwes} CWEs")

                


                        
