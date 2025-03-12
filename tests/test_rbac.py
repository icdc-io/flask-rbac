"""
Unit tests for the RBAC (Role-Based Access Control) implementation in flask_rbac_icdc.

This module contains unit tests for the RBAC class, including tests for loading
the configuration, checking permissions, and the allow decorator. The tests use
mock objects and the unittest framework to simulate various scenarios and validate
the behavior of the RBAC implementation.

Classes:
    MockAccount: A mock implementation of the RbacAccount class for testing purposes.
    TestRBAC: A unittest.TestCase subclass that contains the unit tests for the RBAC class.

Functions:
    setUp: Sets up the test environment before each test.
    tearDown: Cleans up the test environment after each test.
    test_load_config_success: Tests that the RBAC configuration is loaded correctly.
    test_load_config_failure: Tests that an exception is raised when the configuration
    file is not found.
    test_check_permission_success: Tests that abort is not called if the subject has
    permission to perform the specified action.
    test_check_permission_failure: Tests that abort is called if the subject does not
    have permission to perform the specified action.
    test_allow_decorator_success: Tests that the RBAC allow decorator correctly grants
    access to function execution.
    test_allow_decorator_failure: Tests that the RBAC allow decorator correctly denies
    access to function execution.
"""

# pylint: disable=protected-access
import unittest
from unittest.mock import patch, MagicMock
import os

mock_abort = patch("flask.abort", MagicMock()).start()
mock_request = patch("flask.request", MagicMock()).start()


from flask_rbac_icdc import RBAC, RbacAccount, PermissionException, Subject


mock_accounts_table = [
    {
        "id": 1,
        "name": "valid_account",
    },
    {
        "id": 2,
        "name": "devel",
    },
]


class MockAccount(RbacAccount):
    def __init__(self, account_id, name):
        self._id = account_id
        self._name = name

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @classmethod
    def get_by_name(cls, account_name):
        return next(
            (
                cls(account["id"], account["name"])
                for account in mock_accounts_table
                if account["name"] == account_name
            ),
            None,
        )

    def subject_role(self, x_auth_role):
        # Simulate operator group for account=devel and role=admin
        if x_auth_role == "operator":
            raise PermissionException("You are not operator")
        if self.name == "devel" and x_auth_role == "admin":
            return "operator"
        return x_auth_role


rbac_config_path = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "test_rbac.yaml"
)


class TestRBAC(unittest.TestCase):

    def setUp(self):
        mock_abort.reset_mock()
        mock_abort.side_effect = None
        self.rbac = RBAC(rbac_config_path, MockAccount)
        self.mock_account = MockAccount(1, "valid_account")

    def tearDown(self):
        patch.stopall()  # Stop all patches

    def test_load_config_success(self):
        """The RBAC configuration is loaded correctly."""
        roles = self.rbac._roles.__members__
        policy = self.rbac._policy
        self.assertIn("OPERATOR", roles)
        self.assertIn("ADMIN", roles)
        self.assertIn("MEMBER", roles)

        # check operator policy
        self.assertIn("operator", policy)
        self.assertIn("products", policy["operator"])
        self.assertIn("permissions", policy["operator"]["products"])
        self.assertEqual(
            ["list", "create", "update", "delete"],
            policy["operator"]["products"]["permissions"],
        )
        self.assertIn("permissions", policy["operator"]["accounts"])
        self.assertEqual(
            ["list", "get", "create", "delete"],
            policy["operator"]["accounts"]["permissions"],
        )

        # check admin policy
        self.assertIn("admin", policy)
        self.assertIn("permissions", policy["admin"]["products"])
        self.assertEqual(
            ["list", "create", "update"],
            policy["admin"]["products"]["permissions"],
        )
        self.assertIn("permissions", policy["admin"]["accounts"])
        self.assertEqual(
            ["list", "get"],
            policy["admin"]["accounts"]["permissions"],
        )

        # check member policy
        self.assertIn("member", policy)
        self.assertIn("products", policy["member"])
        self.assertIn("permissions", policy["member"]["products"])
        self.assertEqual(["list"], policy["member"]["products"]["permissions"])
        self.assertNotIn("accounts", policy["member"])
        mock_abort.assert_not_called()

    def test_load_config_failure(self):
        """Exception is raised when the configuration file is not found."""
        with self.assertRaises(FileNotFoundError):
            RBAC("nonexistent_file.yaml", MockAccount)

    def test_check_permission_success(self):
        """Abort is not called if subject has permission to perform the specified action."""
        test_cases = [
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "operator",
                    self.rbac._policy["operator"],
                ),
                "accounts.list",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "operator",
                    self.rbac._policy["operator"],
                ),
                "accounts.get",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "operator",
                    self.rbac._policy["operator"],
                ),
                "accounts.create",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "operator",
                    self.rbac._policy["operator"],
                ),
                "accounts.delete",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "operator",
                    self.rbac._policy["operator"],
                ),
                "products.list",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "operator",
                    self.rbac._policy["operator"],
                ),
                "products.create",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "operator",
                    self.rbac._policy["operator"],
                ),
                "products.update",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "operator",
                    self.rbac._policy["operator"],
                ),
                "products.delete",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("admin"),
                    "owner",
                    self.rbac._policy["admin"],
                ),
                "products.list",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("admin"),
                    "owner",
                    self.rbac._policy["admin"],
                ),
                "products.create",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("admin"),
                    "owner",
                    self.rbac._policy["admin"],
                ),
                "products.update",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("admin"),
                    "owner",
                    self.rbac._policy["admin"],
                ),
                "accounts.list",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("admin"),
                    "owner",
                    self.rbac._policy["admin"],
                ),
                "accounts.get",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("member"),
                    "owner",
                    self.rbac._policy["member"],
                ),
                "products.list",
            ),
        ]
        for subject, action in test_cases:
            mock_abort.reset_mock()
            with self.subTest(subject=subject, action=action):
                self.rbac._check_permission(subject, action)
                mock_abort.assert_not_called()

    def test_check_permission_failure(self):
        """Abort is called if subject does not have permission to perform the specified action."""
        test_cases = [
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("member"),
                    "owner",
                    self.rbac._policy["member"],
                ),
                "products.create",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("member"),
                    "owner",
                    self.rbac._policy["member"],
                ),
                "products.update",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("member"),
                    "owner",
                    self.rbac._policy["member"],
                ),
                "products.delete",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("member"),
                    "owner",
                    self.rbac._policy["member"],
                ),
                "products.copy",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("admin"),
                    "owner",
                    self.rbac._policy["admin"],
                ),
                "products.copy",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("admin"),
                    "owner",
                    self.rbac._policy["admin"],
                ),
                "accounts.delete",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "owner",
                    self.rbac._policy["operator"],
                ),
                "accounts.copy",
            ),
            (
                Subject(
                    MockAccount(1, "valid_account"),
                    self.rbac._roles("operator"),
                    "owner",
                    self.rbac._policy["operator"],
                ),
                "accounts.update",
            ),
        ]
        for subject, action in test_cases:
            mock_abort.reset_mock()
            with self.subTest(subject=subject, action=action):
                self.rbac._check_permission(subject, action)
                mock_abort.assert_called_once_with(
                    403, f"Access to {action} forbidden for role {subject.role.name}"
                )

    def test_allow_decorator_success(self):
        """
        @rbac.allow decorator correctly grants access to function execution
        """
        test_cases = [
            (
                "products.list",
                {
                    "x-auth-account": "devel",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
            ),
            (
                "products.create",
                {
                    "x-auth-account": "devel",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
            ),
            (
                "products.update",
                {
                    "x-auth-account": "devel",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
            ),
            (
                "products.delete",
                {
                    "x-auth-account": "devel",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
            ),
            (
                "products.list",
                {
                    "x-auth-account": "valid_account",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
            ),
            (
                "products.create",
                {
                    "x-auth-account": "valid_account",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
            ),
            (
                "products.update",
                {
                    "x-auth-account": "valid_account",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
            ),
            (
                "products.list",
                {
                    "x-auth-account": "valid_account",
                    "x-auth-role": "member",
                    "x-auth-user": "owner",
                },
            ),
        ]

        for action, headers in test_cases:
            with self.subTest(headers=headers, action=action):
                # print(f"Running subtest with\naction: {action}\nheaders: {headers}\n")

                mock_abort.reset_mock()
                mock_request.reset_mock()
                mock_abort.side_effect = PermissionError

                mock_request_headers: MagicMock = mock_request.headers.get
                mock_request_headers.side_effect = headers.get

                @self.rbac.allow(action)
                def mock_view(subject: Subject = None):
                    account_name = subject.account_name
                    return f"Access Granted for {account_name}"

                response = mock_view()
                x_auth_account = headers["x-auth-account"]
                self.assertEqual(response, f"Access Granted for {x_auth_account}")
                mock_abort.assert_not_called()
                self.assertEqual(mock_request_headers.call_count, 3)
                mock_request_headers.assert_any_call("x-auth-account")
                mock_request_headers.assert_any_call("x-auth-role")
                mock_request_headers.assert_any_call("x-auth-user")

    def test_allow_decorator_failure(self):
        """
        @rbac.allow decorator correctly denies access to function execution
        """
        test_cases = [
            (
                "products.list",
                {
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
                {
                    "code": 401,
                    "message": "Account name is required in x-auth-account header.",
                },
            ),
            (
                "products.list",
                {
                    "x-auth-account": "unknown",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
                {
                    "code": 401,
                    "message": "Invalid auth parameters. Account name is not found.",
                },
            ),
            (
                "products.list",
                {
                    "x-auth-account": "valid_account",
                    "x-auth-user": "owner",
                },
                {
                    "code": 401,
                    "message": "Role name is required in x-auth-role header.",
                },
            ),
            (
                "products.list",
                {
                    "x-auth-account": "valid_account",
                    "x-auth-role": "invalid_role",
                    "x-auth-user": "owner",
                },
                {
                    "code": 401,
                    "message": "Invalid auth parameters. Role name is not found.",
                },
            ),
            (
                "products.create",
                {
                    "x-auth-account": "valid_account",
                    "x-auth-role": "member",
                    "x-auth-user": "owner",
                },
                {
                    "code": 403,
                    "message": "Access to products.create forbidden for role MEMBER",
                },
            ),
            (
                "products.unexisted",
                {
                    "x-auth-account": "valid_account",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
                {
                    "code": 403,
                    "message": "Access to products.unexisted forbidden for role ADMIN",
                },
            ),
            (
                "products.copy",
                {
                    "x-auth-account": "devel",
                    "x-auth-role": "admin",
                    "x-auth-user": "owner",
                },
                {
                    "code": 403,
                    "message": "Access to products.copy forbidden for role OPERATOR",
                },
            ),
            (
                "products.copy",
                {
                    "x-auth-account": "devel",
                    "x-auth-role": "operator",
                    "x-auth-user": "owner",
                },
                {
                    "code": 403,
                    "message": "You are not operator",
                },
            ),
        ]

        for action, headers, expected_abort in test_cases:
            # print(f"Running subtest with\naction: {action}\nheaders: {headers}\n")
            with self.subTest(
                action=action, headers=headers, expected_abort=expected_abort
            ):

                mock_abort.reset_mock()
                mock_request.reset_mock()
                mock_abort.side_effect = PermissionError

                mock_request_headers: MagicMock = mock_request.headers.get
                mock_request_headers.side_effect = headers.get

                @self.rbac.allow(action)
                def mock_view(subject: Subject = None):
                    account_name = subject.account_name
                    return f"Access Granted for {account_name}"

                if expected_abort is not None:
                    with self.assertRaises(PermissionError):
                        response = mock_view()
                    mock_abort.assert_called_once_with(
                        expected_abort["code"], expected_abort["message"]
                    )
                else:
                    response = mock_view()
                    account_name = self.mock_account.name
                    self.assertEqual(response, f"Access Granted for {account_name}")
                    mock_abort.assert_not_called()
                    self.assertEqual(mock_request_headers.call_count, 3)
                    mock_request_headers.assert_any_call("x-auth-account")
                    mock_request_headers.assert_any_call("x-auth-role")
                    mock_request_headers.assert_any_call("x-auth-user")


class TestSubject(unittest.TestCase):
    def setUp(self):
        """Set up mock account and role for tests."""
        self.mock_account = MagicMock()
        self.mock_account.id = 123
        self.mock_account.name = "test_account"

        self.mock_role = MagicMock()
        self.mock_role.value = "admin"

    def test_subject_initialization(self):
        """Test Subject initialization with valid attributes."""
        policy = {"products": {"filters": {"account_id": "account_id"}}}
        subject = Subject(self.mock_account, self.mock_role, "owner@icdc.io", policy)

        self.assertEqual(subject.account, self.mock_account)
        self.assertEqual(subject.account_id, 123)
        self.assertEqual(subject.account_name, "test_account")
        self.assertEqual(subject.role, self.mock_role)
        self.assertEqual(subject.owner, "owner@icdc.io")
        self.assertEqual(subject.policy, policy)

    def test_filters_valid_object(self):
        """Test the filters method returns correct filter mappings."""
        policy = {
            "products": {"filters": {"account_id": "account_id", "owner": "owner"}},
            "accounts": {"filters": {"id": "account_id"}},
        }
        subject = Subject(self.mock_account, self.mock_role, "owner@icdc.io", policy)

        expected_filters = {"account_id": 123,"owner": "owner@icdc.io"}
        self.assertEqual(subject.filters("products"), expected_filters)
        expected_filters = {"id": 123}
        self.assertEqual(subject.filters("accounts"), expected_filters)

    def test_filters_missing_object_in_policy(self):
        """filters method raise KeyError when the object is not in the policy."""
        policy = {}  # Empty policy, no objects defined
        subject = Subject(self.mock_account, self.mock_role, "owner@icdc.io", policy)

        with self.assertRaises(KeyError):
            subject.filters("products")

    def test_filters_missing_filter_mapping(self):
        """filters method raise KeyError when the filters mapping is missing in policy."""
        policy = {"products": {}}  # Object defined but no filters key
        subject = Subject(self.mock_account, self.mock_role, "owner@icdc.io", policy)

        with self.assertRaises(KeyError):
            subject.filters("products")


if __name__ == "__main__":
    unittest.main(verbosity=2)
