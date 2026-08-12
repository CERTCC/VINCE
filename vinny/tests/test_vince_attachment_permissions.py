from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, RequestFactory
from django.http import Http404

from vinny.views import VinceAttachmentView


class DummyAttachment:
    def __init__(self, case=None, shared=False):
        self.case = case
        self.shared = shared


class DummyCase:
    def __init__(self, id=123):
        self.id = id


class VinceAttachmentViewTrackAccessTests(TestCase):
    databases = {"default", "vincecomm"}
    def setUp(self):
        self.factory = RequestFactory()

        self.normal_user = User.objects.create_user(
            username="normal",
            email="normal@example.com",
            password="x",
            is_staff=False,
            is_superuser=False,
        )
        self.staff_user = User.objects.create_user(
            username="staff",
            email="staff@example.com",
            password="x",
            is_staff=True,
            is_superuser=False,
        )
        self.super_user = User.objects.create_user(
            username="super",
            email="super@example.com",
            password="x",
            is_staff=True,
            is_superuser=True,
        )

    def _build_view(self, user):
        request = self.factory.get("/fake/track-attachment")
        request.user = user

        view = VinceAttachmentView()
        view.request = request
        view.kwargs = {"type": "track", "path": "fake-uuid"}
        return view

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views.get_object_or_404", return_value=DummyCase(id=123))
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.VinceTrackAttachment.objects.filter")
    def test_track_unshared_inaccessible_to_normal_user(
        self, mock_filter, _mock_is_my_case, _mock_get_case, _mock_pending
    ):
        mock_filter.return_value.first.return_value = DummyAttachment(
            case=DummyCase(id=123),
            shared=False,
        )
        view = self._build_view(self.normal_user)

        # With your patched logic, this should be False for normal users
        with self.assertRaises(Http404):
            view.test_func()

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views.get_object_or_404", return_value=DummyCase(id=123))
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.VinceTrackAttachment.objects.filter")
    def test_track_shared_accessible_to_normal_user(
        self, mock_filter, _mock_is_my_case, _mock_get_case, _mock_pending
    ):
        mock_filter.return_value.first.return_value = DummyAttachment(
            case=DummyCase(id=123),
            shared=True,
        )
        view = self._build_view(self.normal_user)

        self.assertTrue(view.test_func())

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views.get_object_or_404", return_value=DummyCase(id=123))
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.VinceTrackAttachment.objects.filter")
    def test_track_unshared_accessible_to_staff(
        self, mock_filter, _mock_is_my_case, _mock_get_case, _mock_pending
    ):
        mock_filter.return_value.first.return_value = DummyAttachment(
            case=DummyCase(id=123),
            shared=False,
        )
        view = self._build_view(self.staff_user)

        self.assertTrue(view.test_func())

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views.get_object_or_404", return_value=DummyCase(id=123))
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.VinceTrackAttachment.objects.filter")
    def test_track_unshared_accessible_to_superuser(
        self, mock_filter, _mock_is_my_case, _mock_get_case, _mock_pending
    ):
        mock_filter.return_value.first.return_value = DummyAttachment(
            case=DummyCase(id=123),
            shared=False,
        )
        view = self._build_view(self.super_user)

        self.assertTrue(view.test_func())

    @patch("vinny.views.VinceTrackAttachment.objects.filter")
    def test_track_missing_attachment_raises_404(self, mock_filter):
        mock_filter.return_value.first.return_value = None
        view = self._build_view(self.normal_user)

        with self.assertRaises(Http404):
            view.test_func()
