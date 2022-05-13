import logging

from django.contrib.auth.models import User
from django.test import TestCase
from django.test.client import RequestFactory

from vince.tests.helpers import *
from vince.views import TicketView, UpdateTicketView

logger = logging.getLogger(__name__)

# @override_settings(EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend')
class TestEmailNotifications(TestCase):
    fixtures = FIXTURES

    def setUp(self):
        # Setup run before every test method.
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

        # Three emails should be set.
        self.assertTrue(len(emails) == 3)
        self.assertTrue(ticket.queue.updated_ticket_cc in recipients)
        self.assertTrue(ticket.queue.new_ticket_cc in recipients)
        self.assertTrue(ticket.submitter_email in recipients)

        for email in emails:
            self.assertTrue('(Opened)' in email.subject)
            self.assertTrue(ticket.title in email.subject)

    def test_take_ticket(self):
        """
        Test take from vince.views.TicketView.get
        :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        r = self.factory.get(f"/vince/ticket/{ticket.id}", {'take': ''}, follow=True)
        r.user = User.objects.get(id=1)
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
        self.assertTrue(len(emails) == 1 + len(watchers))
        self.assertTrue(ticket.queue.updated_ticket_cc in recipients)
        self.assertTrue('(Assigned)' in emails[0].subject)
        self.assertTrue(ticket.title in emails[0].subject)

    def test_assign_ticket(self):
        """
        Test assign from vince.views.TicketView.get
        :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        # User 1 (dsbeaver) assigning to user 2 (test1)
        r = self.factory.get(f"/vince/ticket/{ticket.id}", {'assign': '2'}, follow=True)
        r.user = User.objects.get(id=1)
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

        self.assertTrue(len(emails) == 2 + len(watchers))
        self.assertTrue(ticket.queue.updated_ticket_cc in recipients)
        assigned_to = False
        for email in emails:
            if 'Assigned To You' in email.subject:
                self.assertTrue(User.objects.get(id=2).email in email.recipients())
                assigned_to = True

        self.assertTrue(assigned_to)

    def test_comment_ticket(self):
        """
        Test assign from vince.views.TicketView
        :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        # User 1 (dsbeaver) assigning to user 2 (test1)
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", {'comment': 'New comment'}, follow=True)
        r.user = User.objects.get(id=1)
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

        self.assertTrue(len(emails) == 2 + len(watchers))
        self.assertTrue(ticket.submitter_email in recipients)
        self.assertTrue(ticket.queue.updated_ticket_cc in recipients)
        for email in emails:
            self.assertTrue('(Updated)' in email.subject)

    def test_ticket_status_change(self):
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
            data = {'ticket_id': ticket.id}
            view = UpdateTicketView.as_view()
            response = view(r, **data)
            self.assertTrue(response.status_code == 302)
            self.assertTrue(response.url == f"/vince/ticket/{ticket.id}/")
            emails = get_email()

            recipients = flatten_emails(emails)
            #self.assertTrue(len(emails) == 2 + len(watchers))
            self.assertTrue(ticket.submitter_email in recipients)
            self.assertTrue(ticket.queue.updated_ticket_cc in recipients)
            for email in emails:
                if not x == 'Closed':
                    self.assertTrue(f"new status {status[x]}" in email.body)
                else:
                    self.assertTrue('Closed' in email.subject)
