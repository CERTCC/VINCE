from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User, Group
from unittest.mock import patch, MagicMock

from vinny.views import GetStatementView


class DummyGroupQuerySet:
    """
    Minimal stand-in for the queryset returned by _my_groups_for_case().
    Supports:
      - exists()
      - filter(id=...).exists()
    """
    def __init__(self, ids):
        self.ids = set(ids)

    def exists(self):
        return len(self.ids) > 0

    def filter(self, **kwargs):
        member_id = kwargs.get("id")
        if member_id in self.ids:
            return DummyGroupQuerySet([member_id])
        return DummyGroupQuerySet([])


class GetStatementViewPermissionTests(TestCase):
    databases = {"default", "vincecomm"}
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username="user@example.com",
            email="user@example.com",
            password="pw",
        )

        # Staff/superuser bypass user for dedicated test
        self.admin = User.objects.create_user(
            username="admin@example.com",
            email="admin@example.com",
            password="pw",
            is_staff=True,
        )

        self.case = MagicMock()
        self.case.id = 101

        self.member_owned = MagicMock()
        self.member_owned.id = 201
        self.member_owned.case = self.case

        self.member_other = MagicMock()
        self.member_other.id = 202
        self.member_other.case = self.case

    def _build_view(self, user, kwargs):
        req = self.factory.get("/fake-url/")
        req.user = user
        view = GetStatementView()
        view.request = req
        view.kwargs = kwargs
        return view

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.get_object_or_404")
    @patch("vinny.views._my_groups_for_case")
    def test_member_optional_none_allows_when_user_has_any_allowed_group(
        self, mock_my_groups, mock_get_case, mock_is_my_case, mock_pending, 
    ):
        mock_get_case.return_value = self.case
        mock_my_groups.return_value = DummyGroupQuerySet([self.member_owned.id])

        view = self._build_view(self.user, {"pk": self.case.id})
        self.assertTrue(view.test_func())

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.get_object_or_404")
    @patch("vinny.views._my_groups_for_case")
    def test_member_optional_none_denies_when_user_has_no_allowed_group(
        self, mock_my_groups, mock_get_case, mock_is_my_case, mock_pending,
    ):
        mock_get_case.return_value = self.case
        mock_my_groups.return_value = DummyGroupQuerySet([])

        view = self._build_view(self.user, {"pk": self.case.id})
        self.assertFalse(view.test_func())

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.get_object_or_404")
    @patch("vinny.views._my_groups_for_case")
    @patch("vinny.views.CaseMember")
    def test_member_matches_my_group_allows(
        self, mock_case_member_cls, mock_my_groups, mock_get_case, mock_is_my_case, mock_pending
    ):
        mock_get_case.return_value = self.case
        mock_my_groups.return_value = DummyGroupQuerySet([self.member_owned.id])

        mock_case_member_cls.objects.filter.return_value.first.return_value = self.member_owned

        view = self._build_view(self.user, {"pk": self.case.id, "member": self.member_owned.id})
        self.assertTrue(view.test_func())

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.get_object_or_404")
    @patch("vinny.views._my_groups_for_case")
    @patch("vinny.views.CaseMember")
    @patch("vinny.views.CaseStatement")
    def test_member_not_mine_but_shared_statement_allows(
        self,
        mock_case_statement_cls,
        mock_case_member_cls,
        mock_my_groups,
        mock_get_case,
        mock_is_my_case,
        mock_pending,
    ):
        mock_get_case.return_value = self.case
        mock_my_groups.return_value = DummyGroupQuerySet([self.member_owned.id])  # user owns 201, requests 202

        mock_case_member_cls.objects.filter.return_value.first.return_value = self.member_other
        mock_case_statement_cls.objects.filter.return_value.exists.return_value = True

        view = self._build_view(self.user, {"pk": self.case.id, "member": self.member_other.id})
        self.assertTrue(view.test_func())

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.get_object_or_404")
    @patch("vinny.views._my_groups_for_case")
    @patch("vinny.views.CaseMember")
    @patch("vinny.views.CaseStatement")
    def test_member_not_mine_and_not_shared_denies(
        self,
        mock_case_statement_cls,
        mock_case_member_cls,
        mock_my_groups,
        mock_get_case,
        mock_is_my_case,
        mock_pending,
    ):
        mock_get_case.return_value = self.case
        mock_my_groups.return_value = DummyGroupQuerySet([self.member_owned.id])

        mock_case_member_cls.objects.filter.return_value.first.return_value = self.member_other
        mock_case_statement_cls.objects.filter.return_value.exists.return_value = False

        view = self._build_view(self.user, {"pk": self.case.id, "member": self.member_other.id})
        self.assertFalse(view.test_func())

    @patch("vinny.views.PendingTestMixin.test_func", return_value=True)
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.get_object_or_404")
    def test_staff_bypass_allows(self, mock_get_case, mock_is_my_case, mock_pending):
        mock_get_case.return_value = self.case

        view = self._build_view(self.admin, {"pk": self.case.id, "member": 99999})
        self.assertTrue(view.test_func())

    @patch("vinny.views.PendingTestMixin.test_func", return_value=False)
    @patch("vinny.views._is_my_case", return_value=True)
    @patch("vinny.views.get_object_or_404")
    def test_pending_mixin_failure_denies(self, mock_get_case, mock_is_my_case, mock_pending):
        mock_get_case.return_value = self.case

        view = self._build_view(self.user, {"pk": self.case.id, "member": self.member_owned.id})
        self.assertFalse(view.test_func())

