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
Thin service bridge for auth operations.

Centralises call-sites so views and middleware only import from here
instead of referencing the adapters directly.  This minimises the
surface area that needs to change when swapping auth modes.

Example::

    from vince.auth.service import authenticate_request, get_roles

    user = authenticate_request(request)
    roles = get_roles(user)
"""

from .adapters import Identity, get_auth_adapter


def authenticate_request(request):
    """
    Return an authenticated User for *request* using the configured adapter,
    or ``None`` if authentication cannot be established.
    """
    return get_auth_adapter().authenticate_request(request)


def sync_user(identity: Identity):
    """
    Ensure a local User record for *identity* exists and return it.

    Delegates to the configured adapter's ``sync_user`` implementation.
    """
    return get_auth_adapter().sync_user(identity)


def get_roles(user) -> set:
    """
    Return the set of Django Group names the given *user* belongs to.
    """
    return get_auth_adapter().get_roles(user)
