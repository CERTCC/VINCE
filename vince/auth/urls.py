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
# DM21-1126
########################################################################
from django.urls import path

from .views import whoami  # uncomment to enable the whoami debug endpoint

urlpatterns = [
    # The whoami endpoint is disabled by default.  It is a development/testing
    # helper that returns JSON describing the authenticated user.
    #
    # To enable it locally:
    #   1. Uncomment the import above.
    #   2. Uncomment the path() entry below.
    #   3. Ensure DEBUG=True and AUTH_BACKEND_MODE=local in your environment.
    #      The view enforces DEBUG=True itself (returns HTTP 403 otherwise), but
    #      keeping it wired up in production is an unnecessary attack surface.
    #
    path("whoami/", whoami, name="whoami"),
]
