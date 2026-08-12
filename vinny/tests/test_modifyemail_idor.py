import uuid

from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User, Group
from django.test import override_settings

from vinny.models import (
    VinceCommContact,
    VinceCommEmail,
    VinceCommGroupAdmin,
    GroupContact,
)
from unittest.mock import patch

def fake_send_ticket(*args, **kwargs):
    return True

@patch("vinny.views.contact_update.send_ticket", side_effect=fake_send_ticket)
@patch("vinny.views.contact_update.create_contact_change", side_effect=fake_send_ticket)
@override_settings(ALT_VERIFY_TOKEN=lambda user, session: True)
class ModifyEmailNotificationsIDORTest(TestCase):
    # Required because this codebase touches the vincecomm alias in auth/group checks
    databases = {"default", "vincecomm"}

    def setUp(self):
        # User
        self.password = "Passw0rd!123"
        self.attacker = User.objects.db_manager("vincecomm").create_user(
            username=f"attacker-{uuid.uuid4().hex[:6]}@example.com",
            email=f"attacker-{uuid.uuid4().hex[:6]}@example.com",
            password=self.password,
            is_active=True,
        )

        # Ensure required role/group exists without PK assumptions
        # (if fixture already has it, reuse; otherwise create)
        self.vince_group_admin_group, _ = Group.objects.db_manager("vincecomm").get_or_create(name="vince_group_admin")
        self.attacker.groups.add(self.vince_group_admin_group)

        # Vendor A (attacker is admin here)
        # Use unique vendor_id values to avoid collisions with fixtures
        self.vendor_a = VinceCommContact.objects.db_manager("vincecomm").create(
            vendor_id=10001 + int(uuid.uuid4().hex[:4], 16) % 50000,
            vendor_name=f"Vendor A {uuid.uuid4().hex[:6]}",
            vendor_type="Vendor",
            active=True,
        )
        self.group_a = Group.objects.db_manager("vincecomm").create(name=f"group-a-{uuid.uuid4().hex[:8]}")
        GroupContact.objects.db_manager("vincecomm").create(group=self.group_a, contact=self.vendor_a)

        self.admin_email_a = VinceCommEmail.objects.db_manager("vincecomm").create(
            contact=self.vendor_a,
            email=self.attacker.email,
            name="Attacker Admin",
            status=True,
            invited=False,
            email_list=False,
            email_type="Work",
            email_function="TO",
        )
        VinceCommGroupAdmin.objects.db_manager("vincecomm").create(contact=self.vendor_a, email=self.admin_email_a)

        # Vendor B (target)
        self.vendor_b = VinceCommContact.objects.db_manager("vincecomm").create(
            vendor_id=20001 + int(uuid.uuid4().hex[:4], 16) % 50000,
            vendor_name=f"Vendor B {uuid.uuid4().hex[:6]}",
            vendor_type="Vendor",
            active=True,
        )
        self.group_b = Group.objects.db_manager("vincecomm").create(name=f"group-b-{uuid.uuid4().hex[:8]}")
        GroupContact.objects.db_manager("vincecomm").create(group=self.group_b, contact=self.vendor_b)

        self.victim_email = VinceCommEmail.objects.db_manager("vincecomm").create(
            contact=self.vendor_b,
            email=f"victim-{uuid.uuid4().hex[:6]}@vendorb.example",
            name="Victim Contact",
            status=True,
            invited=False,
            email_list=False,
            email_type="Work",
            email_function="TO",
        )
        profile = self.attacker.vinceprofile
        profile.multifactor = True
        profile.pending = False
        profile.save()

        self.client.force_login(
            self.attacker,
            backend="django.contrib.auth.backends.ModelBackend",
        )
        
        #self.client.login(username=self.attacker.username, password=self.password)

    def test_idor_blocked_cannot_toggle_other_vendor_email(self, *_):
        """
        Attacker is valid admin for vendor_a, but tries to mutate vendor_b email by raw uid.
        Expected: blocked (404) and victim record unchanged.
        """
        # URL pattern expected: vinny:changeemail(vendor_id, type, uid)
        url = reverse("vinny:changeemail", args=[self.vendor_a.id, "email", self.victim_email.id])

        response = self.client.post(url, follow=False)

        self.assertEqual(response.status_code, 404)

        self.victim_email.refresh_from_db()
        self.assertEqual(self.victim_email.email_function, "TO")
        self.assertEqual(self.victim_email.name, "Victim Contact")

    def test_legitimate_same_vendor_toggle_still_works(self, *_):
        """
        Control test: admin can modify email that belongs to their own vendor.
        """

        own_vendor_email = VinceCommEmail.objects.db_manager("vincecomm").create(
            contact=self.vendor_a,
            email=f"user-{uuid.uuid4().hex[:6]}@vendora.example",
            name="Own Vendor User",
            status=True,
            invited=False,
            email_list=False,
            email_type="Work",
            email_function="TO",
        )

        url = reverse("vinny:changeemail", args=[self.vendor_a.id, "email", own_vendor_email.id])
        response = self.client.post(url, follow=False)

        # View redirects to vinny:admin on success
        self.assertIn(response.status_code, [302, 303])

        own_vendor_email.refresh_from_db()
        self.assertEqual(own_vendor_email.email_function, "EMAIL")
