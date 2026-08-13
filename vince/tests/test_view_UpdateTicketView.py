import logging
import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.test.client import RequestFactory
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import override_settings

from vince.tests.helpers import *
from vince.views import UpdateTicketView, TicketView


logger = logging.getLogger(__name__)

@override_settings(ALT_VERIFY_TOKEN=lambda user, session: True)
class TestUpdateTicketView(TestCase):
    fixtures = FIXTURES

    def setUp(self):
        # Setup run before every test method.
        self.factory = RequestFactory()
        # r = self.factory.get('/vince/newticket/')

    def tearDown(self):
        # Clean up run after every test method.
        pass

    @patch("vince.views.is_in_group_vincetrack", return_value=True)
    def test_subscribe(self, _):
        """
            Test assign from vince.views.TicketView
            :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        # User 1 (vinceuser) assigning to user 2 (test1)

        # Turn on ticket watching for user with id 1
        data = { 'subscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        is_super = r.user.is_superuser
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        view = UpdateTicketView.as_view()
        view(r, **data)
        watcher = get_watchers(ticket).all()[0]
        r.user.is_superuser = is_super
        self.assertTrue(r.user == watcher.user)

        # Make sure try to subscribe twice doesn't break anything
        data = { 'subscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        is_super = r.user.is_superuser
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        view = UpdateTicketView.as_view()
        view(r, **data)
        watcher = get_watchers(ticket).all()[0]
        r.user.is_superuser = is_super
        self.assertTrue(r.user == watcher.user)

        # Turn off ticket watching
        data = { 'unsubscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        view(r, **data)
        watchers = get_watchers(ticket).all()
        self.assertTrue(len(watchers) == 0)

        # Make sure deleting twice doesn't break anything
        data = { 'unsubscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        view(r, **data)
        watchers = get_watchers(ticket).all()
        self.assertTrue(len(watchers) == 0)


        # there should be no emails
        emails = get_email()
        self.assertTrue(len(emails) == 0)

    @patch("vince.views.is_in_group_vincetrack", return_value=True)
    def test_getsubscribers(self, _):
        """
            Test assign from vince.views.TicketView
            :return:
        """
        ticket = create_ticket()
        # Get rid of the initial creation emails
        get_email()
        # User 1 (vinceuser) assigning to user 2 (test1)

        # Turn on ticket watching for user with id 1
        data = { 'subscribe': True, 'ticket_id': ticket.id}
        r = self.factory.post(f"/vince/ticket/{ticket.id}/update", data, follow=True)
        r.user = User.objects.get(id=1)
        is_super = r.user.is_superuser
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        view = UpdateTicketView.as_view()
        view(r, **data)
        watcher = get_watchers(ticket).all()[0]
        r.user.is_superuser = is_super
        self.assertTrue(r.user == watcher.user)


        data = { 'subscribed_users': True , 'pk': ticket.id}
        r = self.factory.get(f"/vince/ticket/{ticket.id}", data, follow=True)
        r.user = User.objects.get(id=1)
        r.user.is_superuser = True
        SessionMiddleware(lambda req: None).process_request(r)
        view = TicketView.as_view()
        response = view(r, **data)
        print(json.loads(response.content))
