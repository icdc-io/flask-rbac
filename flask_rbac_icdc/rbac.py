"""
This module provides authorization utilities
"""

from abc import ABC, abstractmethod
from enum import Enum
import json
import os
from functools import wraps
from typing import Callable, Dict
from flask import request, abort
import yaml


class RbacAccount(ABC):
    """
    Abstract class for RBAC account
    """

    __abstract__ = True

    @property
    @abstractmethod
    def id(self) -> int:
        """The ID of the account."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the account."""

    @abstractmethod
    def subject_role(self, x_auth_role: str, roles: Enum) -> str:
        """Determine the role of the account based on the provided role enum"""


class PermissionException(Exception):
    """
    Raised when subject trying to perform an
    operation without the access rights
    """

    def __init__(self, message):
        self.message = message
        super().__init__(message)


class Subject:
    """
    Class represents a subject in the system, combining their account, role,
    and access permissions. It facilitates role-based access control (RBAC) by
    validating whether a user can perform a specific action and defining
    scope-based access restrictions.
    """

    def __init__(self, account: RbacAccount, role: Enum, owner, action: str, policy):
        self.account = account
        self.account_id = account.id
        self.account_name = account.name
        self.role = role
        self.owner = owner
        requested_object, requested_permission = action.rsplit(".", 1)
        if not requested_object in policy[role.value]:
            raise PermissionException(
                f"Access to {action} forbidden for role {role.name}"
            )
        self.requested_object = requested_object
        permissions = policy[role.value][requested_object]["permissions"]
        if not requested_permission in permissions:
            raise PermissionException(
                f"Access to {action} forbidden for role {role.name}"
            )
        self.permissions = permissions
        self.policy = policy

    def filters(self, object_name: str):
        return {
            key: getattr(self, value)
            for key, value in self.policy[self.role.value][object_name][
                "filters"
            ].items()
        }

    def __repr__(self):
        return (
            f"Subject(\n"
            f"  role={self.role},\n"
            f"  account_id={self.account.id},\n"
            f"  account_name={self.account.name},\n"
            f"  permissions={self.permissions},\n"
            f")"
        )


class RBAC:

    def __init__(self, config_path: str, get_account: Callable[[str], RbacAccount]):
        # Get the caller's stack frame (where this instance was created)
        self.config_path = config_path
        self.get_account = get_account
        self.roles = {}
        self.load_config()

    def load_config(self):
        """Load RBAC rules from YAML file."""
        file_name = self.config_path
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"RBAC config file not found: {file_name}")
        with open(file_name, encoding="utf-8") as file_handle:
            config: Dict[str, Dict[str, str]] = yaml.load(
                file_handle, Loader=yaml.FullLoader
            )
        self.policy = config.get("roles", {})
        roles = {role.upper(): role for role in self.policy.keys()}
        self.roles = Enum("Roles", roles)

    def __repr__(self):
        policy = json.dumps(self.policy, indent=2)
        return f"RBAC(\n" f"  roles=\n{policy},\n" f")"

    def allow(self, action):
        """
        A decorator to enforce role-based access control for an endpoint.
        """

        def wrapper(func):
            @wraps(func)
            def wrap(*args, **kwargs):
                account_name = request.headers.get("x-auth-account")
                if not account_name:
                    abort(401, "Account name is required in x-auth-account header.")

                account = self.get_account(account_name)
                if not account:
                    abort(401, "Invalid auth parameters. Account name is not found.")

                owner = request.headers.get("x-auth-user")

                role_name = request.headers.get("x-auth-role")
                if not role_name:
                    abort(401, "Role name is required in x-auth-role header.")

                try:
                    # throws ValueError if role_name not in Roles
                    role = account.subject_role(role_name, self.roles)
                    subject = Subject(account, role, owner, action, self.policy)
                except ValueError:
                    abort(401, "Invalid auth parameters. Role name is not found.")
                except PermissionException as e:
                    abort(403, e.message)
                kwargs["subject"] = subject
                return func(*args, **kwargs)

            return wrap

        return wrapper
