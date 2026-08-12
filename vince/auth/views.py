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
"""
Authenticated-user introspection endpoint.

If the request already has an authenticated user from the configured auth
backend, the view returns user details without applying the local dev-only
bootstrap restrictions.

In ``AUTH_BACKEND_MODE=local``, unauthenticated requests may still use the
optional dev bootstrap headers ``X-Dev-User``, ``X-Dev-Email``, and
``X-Dev-Groups`` to create/sync a local user on-the-fly. That fallback path
remains restricted to ``DEBUG=True`` and localhost/test-runner requests.
"""

from django.conf import settings
from django.http import JsonResponse

from lib.vince import utils as vinceutils
from vince.auth.service import authenticate_request

# IPs that are unconditionally treated as localhost.
_LOOPBACK_IPS = {"127.0.0.1", "::1"}


def _is_localhost(request):
    """Return True when the resolved client IP is a loopback address.

    ``get_ip()`` returns ``"Unknown"`` when neither ``X-Forwarded-For`` nor
    ``REMOTE_ADDR`` is present (e.g. Django's ``RequestFactory`` in tests).
    That case is also allowed so that unit tests that don't set network
    metadata can still exercise the view.
    """
    ip = vinceutils.get_ip(request)
    # Strip port suffix if present (e.g. "127.0.0.1:52000" from some test runners).
    ip = ip.split(":")[0] if ":" in ip and not ip.startswith("::") else ip
    return ip in _LOOPBACK_IPS or ip == "Unknown"


def whoami(request):
    """
    Return JSON describing the currently authenticated user.

    Already-authenticated users are allowed through regardless of DEBUG or
    client IP so normal backend-based authentication continues to work.

    Unauthenticated requests may fall back to local dev bootstrap, but only
    when:
    * ``settings.DEBUG`` is ``True``.
    * The client IP (resolved via ``lib.vince.utils.get_ip``) is a loopback
      address (``127.0.0.1`` or ``::1``), or unresolvable
      (``"Unknown"`` — test-runner / RequestFactory context).
    """
    user = request.user
    if not getattr(user, "is_authenticated", False):
        if not getattr(settings, "DEBUG", False):
            return JsonResponse({"error": "Not available outside DEBUG mode."}, status=403)

        if not _is_localhost(request):
            return JsonResponse({"error": "Only accessible from localhost."}, status=403)

        # In local mode, attempt header-based dev bootstrap if not already authed.
        bootstrapped = authenticate_request(request)
        if bootstrapped is not None:
            user = bootstrapped

    if not getattr(user, "is_authenticated", False):
        return JsonResponse({"error": "Authentication required."}, status=401)

    return JsonResponse(
        {
            "username": user.username,
            "email": user.email,
            "groups": sorted(user.groups.values_list("name", flat=True)),
        }
    )
