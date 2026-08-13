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
import json
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from vinny.views import CommVulReportAPIView


class _MockTemplate:
    def render(self, context=None):
        return "rendered"


class _MockS3Client:
    def copy_object(self, **kwargs):
        return {"ok": True}

    def put_object(self, **kwargs):
        return {"ok": True}


class _MockSESClient:
    def send_email(self, **kwargs):
        return {"MessageId": "test-message-id"}


class _MockCaseRequest:
    def __init__(self, user_file=None):
        self.user = None
        self.user_file = user_file

    def save(self):
        return None


class CommVulReportAPIViewTests(TestCase):
    databases = {"default", "vincecomm"}
    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = CommVulReportAPIView.as_view()
        self.user = User.objects.create_user(
            username="tester@example.com",
            email="tester@example.com",
            password="password123",
        )
        self.url = "/vince/comm/api/vulreport/"
        self.csaf_payload = {
            "document": {
                "publisher": {
                    "name": "Alice",
                    "issuing_authority": "Org",
                    "namespace": "mailto:alice@example.com",
                },
                "acknowledgments": [{"name": "Alice"}],
            },
            "product_tree": {
                "branches": [
                    {
                        "category": "vendor",
                        "name": "Vendor A",
                        "branches": [
                            {
                                "category": "product_name",
                                "name": "Product A",
                                "branches": [{"category": "product_version", "name": "1.2.3"}],
                            }
                        ],
                    },
                    {
                        "category": "vendor",
                        "name": "Vendor B",
                        "branches": [
                            {
                                "category": "product_name",
                                "name": "Product B",
                                "branches": [{"category": "product_version", "name": "2.0.0"}],
                            }
                        ],
                    },
                ]
            },
            "vulnerabilities": [
                {
                    "title": "Fallback title",
                    "notes": [
                        {"category": "description", "text": "Description from note"},
                        {"title": "Vulnerability Discovery Method", "text": "Discovery text"},
                    ],
                    "threats": [
                        {"category": "impact", "details": "Impact details"},
                        {"category": "exploit_status", "details": "Exploit details"},
                    ],
                    "involvements": [
                        {
                            "status": "contact_attempted",
                            "summary": "Reached out to vendor",
                            "date": "2026-01-01T00:00:00Z",
                        },
                        {"status": "open", "party": "discoverer", "summary": "Public disclosure timeline"},
                    ],
                    "references": [
                        {"summary": "Publicly known reference", "url": "https://example.com/public"},
                        {"summary": "Actively exploited in the wild", "url": "https://example.com/exploit"},
                    ],
                    "metrics":[{"content":{"ssvc_v2":{"schemaVersion":"2.0.0","selections":[{"key":"E","name":"Exploitation","namespace":"ssvc","values":[{"key":"A","name":"Active"}],"version":"1.1.0"}]}}}],
                }
            ],
            "x_extensions": [
                {
                    "content": {
                        "ics_impact": True,
                        "ai_ml_system": True,
                        "share_contact_with_vendor": True,
                        "multiple_vendors_impacted": False,
                        "multiple_vendors": ["Vendor C"],
                        "Tracking_IDs": "VU#123456",
                        "private_comments": "Private note",
                    }
                }
            ],
        }

    def _mock_boto_client(self, name, *args, **kwargs):
        if name == "s3":
            return _MockS3Client()
        if name == "ses":
            return _MockSESClient()
        return SimpleNamespace()

    def _patched_success_dependencies(self, form_save_side_effect=None):
        stack = ExitStack()
        self.addCleanup(stack.close)

        mocks = {
            "get_template": stack.enter_context(
                patch("vinny.views.get_template", return_value=_MockTemplate())
            ),
            "send_sns_json": stack.enter_context(patch("vinny.views.send_sns_json")),
            "send_sns": stack.enter_context(patch("vinny.views.send_sns")),
            "record_access": stack.enter_context(patch("vinny.views.create_record_of_API_access")),
            "get_vrf_id": stack.enter_context(patch("vinny.views.get_vrf_id", return_value="12345")),
            "boto_client": stack.enter_context(patch("vinny.views.boto3.client")),
            # autospec=True ensures first arg is the bound form instance (self)
            "form_save": stack.enter_context(patch("vinny.views.CaseRequestForm.save", autospec=True)),
        }

        mocks["boto_client"].side_effect = self._mock_boto_client
        if form_save_side_effect is None:
            mocks["form_save"].side_effect = lambda form, *args, **kwargs: _MockCaseRequest()
        else:
            mocks["form_save"].side_effect = form_save_side_effect

        return mocks

    def test_application_json_csaf_success(self):
        mocks = self._patched_success_dependencies()

        request = self.factory.post(self.url, data=self.csaf_payload, format="json")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(payload["status"], "success")
        self.assertTrue(payload["vrf_id"].endswith("12345"))

        self.assertIsNotNone(mocks["form_save"].call_args)
        form_instance = mocks["form_save"].call_args.args[0]
        mapped_data = form_instance.cleaned_data

        self.assertEqual(mapped_data["vendor_name"], "Vendor A")
        self.assertEqual(mapped_data["other_vendors"], "Vendor B")
        self.assertEqual(mapped_data["product_name"], "Product A")
        self.assertEqual(mapped_data["product_version"], "1.2.3,2.0.0")
        self.assertEqual(mapped_data["multiplevendors"], "True")
        self.assertEqual(mapped_data["comm_attempt"], "True")
        self.assertEqual(mapped_data["vendor_communication"], "Reached out to vendor")
        self.assertEqual(mapped_data["disclosure_plans"], "Public disclosure timeline")
        self.assertEqual(mapped_data["vul_exploit"], "Exploit details")
        self.assertEqual(mapped_data["vul_impact"], "Impact details")

        submitted_payload = json.loads(mocks["send_sns_json"].call_args[0][2])
        self.assertEqual(submitted_payload["metadata"]["csaf"], self.csaf_payload)
        self.assertTrue(submitted_payload["metadata"]["ai_ml_system"])

    def test_application_json_csaf_involvements_order_independent(self):
        mocks = self._patched_success_dependencies()

        payload = json.loads(json.dumps(self.csaf_payload))
        payload["vulnerabilities"][0]["involvements"] = [
            {"status": "not_contacted", "summary": "I have not attempted to contact any vendors"},
            {"status": "open", "party": "vendor", "summary": "Vendor internal review"},
            {"status": "contact_attempted", "summary": "Reached out later", "date": "2026-02-01T00:00:00Z"},
            {"status": "open", "party": "discoverer", "summary": "Discoverer disclosure plan"},
        ]

        request = self.factory.post(self.url, data=payload, format="json")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        body = json.loads(response.content)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(body["status"], "success")

        self.assertIsNotNone(mocks["form_save"].call_args)
        form_instance = mocks["form_save"].call_args.args[0]
        mapped_data = form_instance.cleaned_data

        self.assertEqual(mapped_data["comm_attempt"], "True")
        self.assertEqual(mapped_data["vendor_communication"], "Reached out later")
        self.assertEqual(mapped_data["first_contact"], "2026-02-01")
        self.assertEqual(mapped_data["disclosure_plans"], "Discoverer disclosure plan")

    def test_contact_attempted_without_date_returns_400(self):
        payload = json.loads(json.dumps(self.csaf_payload))
        payload["vulnerabilities"][0]["involvements"] = [
            {"status": "contact_attempted", "summary": "Reached out to vendor"},
        ]
        request = self.factory.post(self.url, data=payload, format="json")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        body = json.loads(response.content)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            body["errors"]["csaf"][0],
            "first_contact date is required when involvement status is contact_attempted.",
        )

    def test_multipart_csaf_with_file_success(self):
        upload = SimpleUploadedFile("sample.txt", b"sample data", content_type="text/plain")
        mocks = self._patched_success_dependencies(
            form_save_side_effect=lambda form, *args, **kwargs: _MockCaseRequest(user_file=upload)
        )

        request = self.factory.post(
            self.url,
            data={"csaf": json.dumps(self.csaf_payload), "user_file": upload},
            format="multipart",
        )
        force_authenticate(request, user=self.user)

        response = self.view(request)
        body = json.loads(response.content)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(body["status"], "success")

        submitted_payload = json.loads(mocks["send_sns_json"].call_args[0][2])
        self.assertEqual(submitted_payload["metadata"]["csaf"], self.csaf_payload)
        self.assertTrue(submitted_payload["metadata"]["ai_ml_system"])

    def test_malformed_csaf_json_returns_400(self):
        request = self.factory.post(self.url, data={"csaf": '{"document":'}, format="multipart")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 400)
        self.assertIn("csaf", payload["errors"])

    def test_csaf_missing_product_tree_categories_returns_400(self):
        invalid_payload = {
            **self.csaf_payload,
            "product_tree": {"branches": [{"category": "vendor", "name": "Vendor A"}]},
        }
        request = self.factory.post(self.url, data=invalid_payload, format="json")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            payload["errors"]["csaf"][0],
            "At least one value for vendor, product_name, and product_version is required.",
        )

    def test_legacy_form_submission_still_works(self):
        self._patched_success_dependencies()

        legacy_data = {
            "contact_name": "Legacy User",
            "contact_email": "legacy@example.com",
            "product_name": "Legacy Product",
            "product_version": "1.0",
            "vul_description": "Description",
            "vul_exploit": "Exploit",
            "vul_impact": "Impact",
            "vul_discovery": "Discovery",
            "vul_public": "False",
            "vul_exploited": "False",
            "vul_disclose": "False",
            "share_release": "True",
            "credit_release": "True",
            "comm_attempt": "False",
            "multiplevendors": "False",
        }

        request = self.factory.post(self.url, data=legacy_data, format="multipart")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(payload["status"], "success")
