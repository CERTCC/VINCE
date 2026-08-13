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
Auth adapter abstraction for VINCE.

Provides a thin interface over authentication backends so callers can
switch between Cognito (production default) and a local Django-session
mode (for development/testing) via the AUTH_BACKEND_MODE setting.

Usage::

    from vince.auth.adapters import get_auth_adapter
    adapter = get_auth_adapter()
    user = adapter.authenticate_request(request)
"""

import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

User = get_user_model()


@dataclass
class Identity:
    """Portable identity representation shared across adapters."""

    username: str
    email: Optional[str] = None
    groups: Optional[Iterable[str]] = field(default=None)


class BaseAuthAdapter:
    """Common interface that all auth adapters must implement."""

    def authenticate_request(self, request):
        """Return an authenticated User for *request*, or ``None``."""
        raise NotImplementedError

    def sync_user(self, identity: Identity):
        """Ensure a local User matching *identity* exists and return it."""
        raise NotImplementedError

    def get_roles(self, user) -> set:
        """Return the set of group names the user belongs to."""
        return set(user.groups.values_list("name", flat=True))


class LocalAuthAdapter(BaseAuthAdapter):
    """
    Local-first auth adapter for development and testing.

    Authentication priority:
    1. If ``request.user`` is already authenticated (e.g. via Django session),
       return it as-is.
    2. If ``settings.DEBUG`` is ``True``, read the optional dev bootstrap
       headers ``X-Dev-User``, ``X-Dev-Email``, and ``X-Dev-Groups`` to
       auto-create / sync a local user on-the-fly.

    The header bootstrap is **strictly** limited to ``DEBUG=True`` so it
    can never be exploited in production.
    """

    DEV_USER_HEADER = "HTTP_X_DEV_USER"
    DEV_EMAIL_HEADER = "HTTP_X_DEV_EMAIL"
    DEV_GROUPS_HEADER = "HTTP_X_DEV_GROUPS"

    def authenticate_request(self, request):
        # 1) Trust an already-authenticated Django session user.
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            return user

        # 2) Dev-header bootstrap (DEBUG-only guard).
        if not getattr(settings, "DEBUG", False):
            return None

        username = request.META.get(self.DEV_USER_HEADER)
        if not username:
            return None

        email = request.META.get(self.DEV_EMAIL_HEADER) or ""
        raw_groups = request.META.get(self.DEV_GROUPS_HEADER, "")
        groups = [g.strip() for g in raw_groups.split(",") if g.strip()]

        logger.debug("LocalAuthAdapter: bootstrapping dev user %r from request headers", username)
        identity = Identity(username=username, email=email, groups=groups)
        return self.sync_user(identity)

    def sync_user(self, identity: Identity):
        """Get-or-create a local User and sync email / groups."""
        user, created = User.objects.get_or_create(
            username=identity.username,
            defaults={"email": identity.email or ""},
        )
        if created:
            logger.debug("LocalAuthAdapter: created local user %r", identity.username)

        if identity.email and user.email != identity.email:
            user.email = identity.email
            user.save(update_fields=["email"])

        if identity.groups is not None:
            existing = set(user.groups.values_list("name", flat=True))
            for group_name in set(identity.groups) - existing:
                group, _ = Group.objects.get_or_create(name=group_name)
                user.groups.add(group)

        return user


class CognitoAuthAdapter(BaseAuthAdapter):
    """
    Thin wrapper around existing Cognito auth behaviour.

    This adapter deliberately delegates to the already-authenticated
    ``request.user`` that the ``CognitoAuthenticate`` backend populates
    via Django's ``AuthenticationMiddleware``.  All Cognito-specific logic
    remains in ``cogauth.backend`` and is untouched.
    """

    def authenticate_request(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            return user
        return None

    def sync_user(self, identity: Identity):
        user, _ = User.objects.get_or_create(
            username=identity.username,
            defaults={"email": identity.email or ""},
        )
        return user


def get_auth_adapter() -> BaseAuthAdapter:
    """
    Factory that returns the adapter matching ``settings.AUTH_BACKEND_MODE``.

    Valid values: ``"cognito"`` (default) | ``"local"``.
    Raises ``ImproperlyConfigured`` for any other value.
    """
    mode = getattr(settings, "AUTH_BACKEND_MODE", "cognito").lower()
    if mode == "local":
        return LocalAuthAdapter()
    if mode == "cognito":
        return CognitoAuthAdapter()
    raise ImproperlyConfigured(
        f"Unsupported AUTH_BACKEND_MODE={mode!r}. Valid choices are 'cognito' and 'local'."
    )
