import logging
from unittest.mock import patch
from django.contrib.auth.models import User
from django.test import TestCase
from django.test.client import RequestFactory
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import override_settings

from vince.tests.helpers import *
from vince.views import TicketView, UpdateTicketView

logger = logging.getLogger(__name__)

@override_settings(ALT_VERIFY_TOKEN=lambda user, session: True)
class TestEmailNotifications(TestCase):
    fixtures = FIXTURES

    def setUp(self):
        self.factory = RequestFactory()
        # r = self.factory.get('/vince/newticket/')

    def tearDown(self):
        # Clean up run after every test method.
        pass

    def test_newticket(self):
        data = {
            'queue': '1',
            'title': 'test_newticket',
            'body': 'test_newticket',
            'submitter_email': 'newticket_submitter@example.org',
            'priority': '3'
        }

        ticket = create_ticket(data)
        emails = get_email()
        recipients = flatten_emails(emails)

        self.assertTrue(ticket.submitter_email == 'newticket_submitter@example.org')

    @patch("vince.views.is_in_group_vincetrack", return_value=True)
    def test_take_ticket(self, _):
        """
        Test take from vince.views.TicketView.get
        :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        r = self.factory.get(f"/vince/ticket/{ticket.id}", {'take': ''}, follow=True)
        r.user = User.objects.get(id=1)
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        addwatchers(ticket)
        watchers = get_watchers(ticket).all()

        data = {'pk': ticket.id}
        view = TicketView.as_view()
        response = view(r, **data)
        emails = get_email()
        recipients = flatten_emails(emails)

        # Should be redirected
        self.assertTrue(response.status_code == 302)
        self.assertTrue(response.url == f"/vince/ticket/{ticket.id}/")

    @patch("vince.views.is_in_group_vincetrack", return_value=True)
    def test_assign_ticket(self, _):
        """
        Test assign from vince.views.TicketView.get
        :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        # User 1 (vinceuser) assigning to user 2 (test1)
        r = self.factory.get(f"/vince/ticket/{ticket.id}", {'assign': '2'}, follow=True)
        r.user = User.objects.get(id=1)
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        addwatchers(ticket)
        watchers = get_watchers(ticket).all()

        data = {'pk': ticket.id}
        view = TicketView.as_view()
        response = view(r, **data)
        emails = get_email()
        recipients = flatten_emails(emails)

        # Should be redirected
        self.assertTrue(response.status_code == 302)
        self.assertTrue(response.url == f"/vince/ticket/{ticket.id}/")

    @patch("vince.views.is_in_group_vincetrack", return_value=True)
    def test_comment_ticket(self, _):
        """
        Test assign from vince.views.TicketView
        :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        # User 1 (vinceuser) assigning to user 2 (test1)
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", {'comment': 'New comment'}, follow=True)
        r.user = User.objects.get(id=1)
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        addwatchers(ticket)
        watchers = get_watchers(ticket).all()

        data = {'ticket_id': ticket.id}
        view = UpdateTicketView.as_view()
        response = view(r, **data)
        emails = get_email()
        recipients = flatten_emails(emails)

        # Should be redirected
        self.assertTrue(response.status_code == 302)
        self.assertTrue(response.url == f"/vince/ticket/{ticket.id}/")

    @patch("vince.views.is_in_group_vincetrack", return_value=True)
    def test_ticket_status_change(self, _):
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()

        status = {
            'Open': 1,
            'Reopened': 2,
            'Resolved': 3,
            'Closed': 4,
            'Duplicate': 5
        }
        status_test = ['Resolved', 'Reopened', 'Closed', 'Duplicate']
        addwatchers(ticket)
        watchers = get_watchers(ticket).all()

        for x in status_test:
            r = self.factory.post(f"/vince/ticket/{ticket.id}/update",
                                  {'comment': f"new status {status[x]}", 'new_status': status[x]}, follow=True)
            r.user = User.objects.get(id=1)
            r.user.is_superuser = True
            SessionMiddleware(lambda req: None).process_request(r)
            data = {'ticket_id': ticket.id}
            view = UpdateTicketView.as_view()
            response = view(r, **data)
            self.assertTrue(response.status_code == 302)
            self.assertTrue(response.url == f"/vince/ticket/{ticket.id}/")
