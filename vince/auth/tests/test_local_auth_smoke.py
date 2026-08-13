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
Smoke tests for the local auth mode (AUTH_BACKEND_MODE=local).

These tests use RequestFactory so they are self-contained and do not
depend on any URL configuration or external services.
"""

import json

from django.contrib.auth.models import AnonymousUser, User
from django.test import RequestFactory, TestCase, override_settings

from vince.auth.adapters import Identity, LocalAuthAdapter, get_auth_adapter
from vince.auth.views import whoami


@override_settings(DEBUG=True, AUTH_BACKEND_MODE="local")
class LocalAuthAdapterTest(TestCase):
    """Unit tests for LocalAuthAdapter behaviour."""

    def setUp(self):
        self.factory = RequestFactory()
        self.adapter = LocalAuthAdapter()

    # ------------------------------------------------------------------
    # authenticate_request – already-authenticated user is returned as-is
    # ------------------------------------------------------------------
    def test_returns_existing_authenticated_user(self):
        request = self.factory.get("/")
        user = User.objects.create_user(username="existing")
        request.user = user
        result = self.adapter.authenticate_request(request)
        self.assertEqual(result, user)

    # ------------------------------------------------------------------
    # authenticate_request – dev headers create a new local user
    # ------------------------------------------------------------------
    def test_dev_headers_create_user(self):
        request = self.factory.get(
            "/",
            **{
                "HTTP_X_DEV_USER": "devuser",
                "HTTP_X_DEV_EMAIL": "dev@example.com",
                "HTTP_X_DEV_GROUPS": "vince_admin,analyst",
            },
        )
        request.user = AnonymousUser()
        result = self.adapter.authenticate_request(request)
        self.assertIsNotNone(result)
        self.assertEqual(result.username, "devuser")
        self.assertEqual(result.email, "dev@example.com")
        group_names = set(result.groups.values_list("name", flat=True))
        self.assertIn("vince_admin", group_names)
        self.assertIn("analyst", group_names)

    # ------------------------------------------------------------------
    # authenticate_request – missing header returns None (not anonymous)
    # ------------------------------------------------------------------
    def test_missing_dev_header_returns_none(self):
        request = self.factory.get("/")
        request.user = AnonymousUser()
        result = self.adapter.authenticate_request(request)
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # authenticate_request – headers ignored when DEBUG=False
    # ------------------------------------------------------------------
    @override_settings(DEBUG=False)
    def test_dev_headers_ignored_outside_debug(self):
        request = self.factory.get(
            "/",
            **{"HTTP_X_DEV_USER": "should_not_be_created"},
        )
        request.user = AnonymousUser()
        result = self.adapter.authenticate_request(request)
        self.assertIsNone(result)
        self.assertFalse(User.objects.filter(username="should_not_be_created").exists())

    # ------------------------------------------------------------------
    # sync_user – idempotent: calling twice must not duplicate groups
    # ------------------------------------------------------------------
    def test_sync_user_idempotent(self):
        identity = Identity(
            username="idempotent_user",
            email="u@example.com",
            groups=["g1", "g2"],
        )
        self.adapter.sync_user(identity)
        self.adapter.sync_user(identity)
        user = User.objects.get(username="idempotent_user")
        self.assertEqual(user.groups.count(), 2)

    # ------------------------------------------------------------------
    # get_roles – returns correct group names
    # ------------------------------------------------------------------
    def test_get_roles(self):
        identity = Identity(
            username="roleuser",
            email="r@example.com",
            groups=["alpha", "beta"],
        )
        user = self.adapter.sync_user(identity)
        roles = self.adapter.get_roles(user)
        self.assertEqual(roles, {"alpha", "beta"})


@override_settings(DEBUG=True, AUTH_BACKEND_MODE="local")
class LocalAuthFactoryTest(TestCase):
    """Tests for get_auth_adapter factory."""

    def test_factory_returns_local_adapter(self):
        adapter = get_auth_adapter()
        self.assertIsInstance(adapter, LocalAuthAdapter)

    @override_settings(AUTH_BACKEND_MODE="cognito")
    def test_factory_returns_cognito_adapter(self):
        from vince.auth.adapters import CognitoAuthAdapter
        adapter = get_auth_adapter()
        self.assertIsInstance(adapter, CognitoAuthAdapter)

    @override_settings(AUTH_BACKEND_MODE="invalid_value")
    def test_factory_raises_on_invalid_mode(self):
        from django.core.exceptions import ImproperlyConfigured
        with self.assertRaises(ImproperlyConfigured):
            get_auth_adapter()


@override_settings(DEBUG=True, AUTH_BACKEND_MODE="local")
class WhoamiViewTest(TestCase):
    """Smoke tests for the whoami debug endpoint."""

    def setUp(self):
        self.factory = RequestFactory()

    # ------------------------------------------------------------------
    # Returns 200 with user info when dev headers are supplied.
    # RequestFactory produces no REMOTE_ADDR → get_ip returns "Unknown"
    # which the view treats as localhost (test-runner context).
    # ------------------------------------------------------------------
    def test_whoami_with_dev_headers(self):
        request = self.factory.get(
            "/vince/auth/whoami/",
            **{
                "HTTP_X_DEV_USER": "localtester",
                "HTTP_X_DEV_EMAIL": "localtester@example.com",
                "HTTP_X_DEV_GROUPS": "vince_admin, analyst",
            },
        )
        request.user = AnonymousUser()
        response = whoami(request)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["username"], "localtester")
        self.assertEqual(data["email"], "localtester@example.com")
        self.assertIn("vince_admin", data["groups"])
        self.assertIn("analyst", data["groups"])

    # ------------------------------------------------------------------
    # Returns 200 when user is already authenticated via session.
    # No REMOTE_ADDR → "Unknown" → allowed.
    # ------------------------------------------------------------------
    def test_whoami_with_authenticated_user(self):
        user = User.objects.create_user(username="sessionuser")
        request = self.factory.get("/vince/auth/whoami/")
        request.user = user
        response = whoami(request)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["username"], "sessionuser")

    # ------------------------------------------------------------------
    # Returns 200 when REMOTE_ADDR is 127.0.0.1 explicitly.
    # ------------------------------------------------------------------
    def test_whoami_with_loopback_remote_addr(self):
        user = User.objects.create_user(username="loopbackuser")
        request = self.factory.get("/vince/auth/whoami/", REMOTE_ADDR="127.0.0.1")
        request.user = user
        response = whoami(request)
        self.assertEqual(response.status_code, 200)

    # ------------------------------------------------------------------
    # Returns 200 when REMOTE_ADDR is IPv6 loopback ::1.
    # ------------------------------------------------------------------
    def test_whoami_with_ipv6_loopback_remote_addr(self):
        user = User.objects.create_user(username="ipv6user")
        request = self.factory.get("/vince/auth/whoami/", REMOTE_ADDR="::1")
        request.user = user
        response = whoami(request)
        self.assertEqual(response.status_code, 200)

    # ------------------------------------------------------------------
    # Returns 200 when the user is already authenticated, even from a
    # non-loopback address.
    # ------------------------------------------------------------------
    def test_whoami_allows_authenticated_non_localhost(self):
        user = User.objects.create_user(username="remoteuser")
        request = self.factory.get("/vince/auth/whoami/", REMOTE_ADDR="10.0.0.1")
        request.user = user
        response = whoami(request)
        self.assertEqual(response.status_code, 200)

    # ------------------------------------------------------------------
    # Returns 200 when the user is already authenticated, even if
    # X-Forwarded-For is non-loopback.
    # ------------------------------------------------------------------
    def test_whoami_allows_authenticated_forwarded_for_remote(self):
        user = User.objects.create_user(username="proxieduser")
        request = self.factory.get(
            "/vince/auth/whoami/",
            REMOTE_ADDR="127.0.0.1",
            HTTP_X_FORWARDED_FOR="203.0.113.5",
        )
        request.user = user
        response = whoami(request)
        self.assertEqual(response.status_code, 200)

    # ------------------------------------------------------------------
    # Returns 401 when no auth is present in local+DEBUG mode.
    # ------------------------------------------------------------------
    def test_whoami_unauthenticated_returns_401(self):
        request = self.factory.get("/vince/auth/whoami/")
        request.user = AnonymousUser()
        response = whoami(request)
        self.assertEqual(response.status_code, 401)

    # ------------------------------------------------------------------
    # Returns 403 when DEBUG=False for unauthenticated requests because the
    # dev bootstrap path must be unavailable in prod.
    # ------------------------------------------------------------------
    @override_settings(DEBUG=False)
    def test_whoami_blocked_outside_debug(self):
        request = self.factory.get("/vince/auth/whoami/")
        request.user = AnonymousUser()
        response = whoami(request)
        self.assertEqual(response.status_code, 403)

    # ------------------------------------------------------------------
    # Returns 200 for an already-authenticated user even when DEBUG=False.
    # ------------------------------------------------------------------
    @override_settings(DEBUG=False)
    def test_whoami_allows_authenticated_user_outside_debug(self):
        user = User.objects.create_user(username="produser")
        request = self.factory.get("/vince/auth/whoami/", REMOTE_ADDR="203.0.113.10")
        request.user = user
        response = whoami(request)
        self.assertEqual(response.status_code, 200)
