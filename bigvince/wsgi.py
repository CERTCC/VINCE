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
"""
WSGI config for bigvince project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/howto/deployment/wsgi/
"""

import os
import sys
from django.core.wsgi import get_wsgi_application
from django.conf import settings
from django.urls import get_resolver
import pprint

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bigvince.settings')

application = get_wsgi_application()

# # Debug probe: log critical settings at startup
# with open("/tmp/django_startup.log", "a") as f:
#     f.write("=== Django starting under Gunicorn ===\n")
#     f.write(f"DJANGO_SETTINGS_MODULE: {os.environ.get('DJANGO_SETTINGS_MODULE')}\n")
#     f.write(f"IS_KBWORKER: {os.environ.get('IS_KBWORKER')}\n")
#     try:
#         import django
#         django.setup()
#         from django.conf import settings as dj_settings
#         f.write(f"settings.IS_KBWORKER: {getattr(dj_settings, 'IS_KBWORKER', 'MISSING')}\n")
#     except Exception as e:
#         f.write(f"Error during settings load: {e}\n")


# try:
#     from django.urls import get_resolver
#     with open("/tmp/django_startup.log", "a") as f:
#         f.write("Loaded URL patterns:\n")
#         for p in get_resolver().url_patterns:
#             f.write(f"  {p}\n")
# except Exception as e:
#     with open("/tmp/django_startup.log", "a") as f:
#         f.write(f"Error listing URL patterns: {e}\n")


# with open("/tmp/django_startup.log", "a") as f:
#     f.write("=== Listing all URL patterns (expanded) ===\n")
#     def list_patterns(patterns, prefix=""):
#         for p in patterns:
#             if hasattr(p, 'url_patterns'):  # resolver
#                 list_patterns(p.url_patterns, prefix + str(p.pattern))
#             else:
#                 f.write(f"{prefix}{p.pattern}\n")
#     list_patterns(get_resolver().url_patterns)