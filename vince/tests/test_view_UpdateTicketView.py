import logging
import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.test.client import RequestFactory

from vince.tests.helpers import *
from vince.views import UpdateTicketView, TicketView


logger = logging.getLogger(__name__)

# @override_settings(EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend')
class TestUpdateTicketView(TestCase):
    fixtures = FIXTURES

    def setUp(self):
        # Setup run before every test method.
        self.factory = RequestFactory()
        # r = self.factory.get('/vince/newticket/')

    def tearDown(self):
        # Clean up run after every test method.
        pass

    def test_subscribe(self):
        """
            Test assign from vince.views.TicketView
            :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        # User 1 (dsbeaver) assigning to user 2 (test1)

        # Turn on ticket watching for user with id 1
        data = { 'subscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        view = UpdateTicketView.as_view()
        view(r, **data)
        watcher = get_watchers(ticket).all()[0]
        self.assertTrue(r.user == watcher.user)

        # Make sure try to subscribe twice doesn't break anything
        data = { 'subscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        view = UpdateTicketView.as_view()
        view(r, **data)
        watcher = get_watchers(ticket).all()[0]
        self.assertTrue(r.user == watcher.user)

        # Turn off ticket watching
        data = { 'unsubscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        view(r, **data)
        watchers = get_watchers(ticket).all()
        self.assertTrue(len(watchers) == 0)

        # Make sure deleting twice doesn't break anything
        data = { 'unsubscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        view(r, **data)
        watchers = get_watchers(ticket).all()
        self.assertTrue(len(watchers) == 0)


        # there should be no emails
        emails = get_email()
        self.assertTrue(len(emails) == 0)


    def test_getsubscribers(self):
        """
            Test assign from vince.views.TicketView
            :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        # User 1 (dsbeaver) assigning to user 2 (test1)

        # Turn on ticket watching for user with id 1
        data = { 'subscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        view = UpdateTicketView.as_view()
        view(r, **data)
        watcher = get_watchers(ticket).all()[0]
        self.assertTrue(r.user == watcher.user)


        data = { 'subscribed_users': True , 'pk': ticket.id}
        r = self.factory.get(f"/vince/ticket/{ticket.id}", data, follow=True)
        r.user = User.objects.get(id=1)
        view = TicketView.as_view()
        response = view(r, **data)
        print(json.loads(response.content))
