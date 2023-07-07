import json

from django.test import TestCase
from django.test.client import RequestFactory
from django.contrib.auth.models import User

from vince.models import FollowUp, Ticket
from vinceworker.views import ingest_vulreport


class TestUpdateTicketView(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_bounce_ticket_when_all_recipients_inactive(self):
        body_data = {
            "Message": json.dumps(
                {
                    "bounce": {
                        "bouncedRecipients": ["deactivated_user@example.com"],
                        "bounceType": "bouncy",
                    },
                    "notificationType": "Bounce",
                    "mail": {
                        "commonHeaders": {
                            "subject": "mock_subject",
                            "from": "mock_from",
                            "date": "mock_date",
                        }
                    },
                }
            )
        }
        request = self.factory.post(
            "/vinceworker/ingest-vulreport/", body_data, content_type="application/json"
        )
        User(username="deactivated_user@example.com", is_active=False).save()
        self.assertEqual(Ticket.objects.all().count(), 0)
        self.assertEqual(FollowUp.objects.all().count(), 0)
        response = ingest_vulreport(request)
        self.assertEqual(Ticket.objects.all().count(), 0)
        self.assertEqual(FollowUp.objects.all().count(), 0)
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertEqual(response.content, b'{"response": "success"}')
        self.assertEqual(response.status_code, 200)
