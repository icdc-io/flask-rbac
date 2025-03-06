"""
This module provides authorization utilities
"""

from abc import abstractmethod
from enum import Enum
from functools import wraps
import json
import os
from typing import Dict
import yaml
from flask import request, abort


class RbacAccount:
    """
    Abstract base class that defines the interface for RBAC account objects.

    This class serves as a contract for implementing role-based access control (RBAC)
    account functionality. Any concrete implementation must provide properties for
    account identification and name, as well as a method to determine the subject's
    role based on authentication information.

    All subclasses must implement the abstract methods and properties defined here.
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

    @classmethod
    @abstractmethod
    def get_by_name(cls, account_name: str) -> "RbacAccount":
        """
        Retrieve an account by its name.

        Args:
            account_name (str): The name of the account to retrieve.

        Example:
        .. code-block:: python
          @classmethod
          def get_by_name(cls, account_name: str) -> Optional["Account"]:
              return cls.query.filter_by(name=account_name).first()
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @abstractmethod
    def subject_role(self, x_auth_role: str) -> str:
        """
        Determines the effective role of the account based on provided authentication
        information.

        This method validates the requested role against the available roles and
        returns the appropriate role value for the subject.

        Args:
            x_auth_role (str): The role identifier provided in authentication headers.
            roles (Enum): Enumeration of valid roles defined in the RBAC policy.

        Returns:
            str: The validated role value to be used for this subject.

        Raises:
            PermissionException: This method should raise this error,
            if the provided role is invalid or not allowed for this account.

        Note:
            This is an abstract method that must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method.")


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

    Attributes:
        account (RbacAccount): The account associated with this subject.
        account_id (int): The ID of the account.
        account_name (str): The name of the account.
        role (Enum): The role assigned to this subject.
        owner (str): The owner identifier for this subject.
        requested_object (str): The object being accessed.
        permissions (list): List of permissions available to this subject.
        policy (dict): The policy configuration applied to this subject.
    """

    def __init__(self, account: RbacAccount, role: Enum, owner, policy):
        """
        Initialize a Subject with account, role, and permission details.

        Args:
            account (RbacAccount): The account associated with this subject.
            role (Enum): The role assigned to this subject.
            owner (str): The owner identifier for this subject.
            action (str): The action being performed, in format "object.permission".
            policy (dict): The policy configuration to apply.

        Raises:
            PermissionException: If the subject doesn't have permission for the requested action.
        """
        self.account = account
        self.account_id = account.id
        self.account_name = account.name
        self.role = role
        self.owner = owner
        self.policy = policy

    def filters(self, object_name: str):
        """
        Get the filters that should be applied for this subject when 
        accessing a specific object.

        Filters are used to restrict the scope of data access based 
        on the subject's role and attributes.

        Args:
            object_name (str): The name of the object to get filters for.

        Returns:
            dict: A dictionary of filter key-value pairs to be applied 
            when accessing the object.
        """
        return {
            key: getattr(self, value)
            for key, value in self.policy[object_name]["filters"].items()
        }

    def __repr__(self):
        return (
            f"Subject(\n"
            f"  role={self.role},\n"
            f"  account_id={self.account.id},\n"
            f"  account_name={self.account.name},\n"
            f")"
        )


class RBAC:
    """
    RBAC class to handle role-based access control.

    Attributes:
        config_path (str): Path to the YAML configuration file.
        roles (Enum): Enum of roles defined in the policy.
        policy (Dict): Dictionary of RBAC policies.
    """

    def __init__(
        self,
        config_path: str,
        account_model: RbacAccount,
        use_operator_group: bool = True,
    ):
        """
        Initialize the RBAC instance.

        Args:
            config_path (str): Path to the YAML configuration file.
        """
        self._roles = self.load_config(config_path)
        self._account_model = account_model
        self._use_operator_group = use_operator_group

    def load_config(self, config_path):
        """
        Load RBAC configuration from a YAML file.

        This function reads the role-based access control configuration from a YAML file
        and returns the parsed configuration as a dictionary. The configuration defines
        roles, their permissions for different resources, and any filters that should be
        applied when accessing those resources.

        Args:
            config_file (str): Path to the YAML configuration file.

        Returns:
            dict: Parsed RBAC configuration containing roles, permissions, and filters.

        Raises:
            FileNotFoundError: If the specified configuration file does not exist.
            yaml.YAMLError: If the configuration file contains invalid YAML syntax.
        """

        if not os.path.exists(config_path):
            raise FileNotFoundError(f"RBAC config file not found: {config_path}")
        with open(config_path, encoding="utf-8") as file_handle:
            config: Dict[str, Dict[str, Dict]] = yaml.load(
                file_handle, Loader=yaml.FullLoader
            )
        self.policy = config.get("roles", {})
        roles = {role.upper(): role for role in self.policy.keys()}
        return Enum("Roles", roles)

    def _check_permission(self, subject: Subject, action: str):
        """
        Check if the subject has permission to perform the specified action.

        Args:
            subject (Subject): The subject requesting access.
            action (str): The action to check permissions for, in format "object.permission".

        Raises:
            PermissionException: If the subject doesn't have permission for the requested action.
        """
        requested_object, requested_permission = action.rsplit(".", 1)

        # Check if object exists in policy
        if requested_object not in subject.policy:
            abort(403, f"Access to {action} forbidden for role {subject.role.name}")

        # Check if permission exists for the object
        permissions = subject.policy[requested_object]["permissions"]
        if requested_permission not in permissions:
            abort(403, f"Access to {action} forbidden for role {subject.role.name}")

    def allow(self, action: str):
        """
        A decorator to enforce role-based access control for an endpoint.

        This decorator validates that the requesting user has the required permissions
        to access the endpoint by checking:
        1. Account name from x-auth-account header
        2. Role from x-auth-role header
        3. Owner from x-auth-user header
        4. Permission for the specified action based on the RBAC policy

        Args:
            action (str): The action to check permissions for, in format "object.permission"

        Returns:
            function: Decorated function that includes RBAC permission check

        Raises:
            401: If account name or role headers are missing/invalid
            403: If the user does not have permission for the requested action

        Example:
        .. code-block:: python
            @app.route('/read', methods=['GET'])
            @rbac.allow("users.read")
            def get_user(subject):
                # Function implementation
                pass
        """

        def wrapper(func):
            @wraps(func)
            def wrap(*args, **kwargs):
                account_name = request.headers.get("x-auth-account")
                if not account_name:
                    abort(401, "Account name is required in x-auth-account header.")

                account = self._account_model.get_by_name(account_name)
                if not account:
                    abort(401, "Invalid auth parameters. Account name is not found.")

                owner = request.headers.get("x-auth-user")

                role_name = request.headers.get("x-auth-role")
                if not role_name:
                    abort(401, "Role name is required in x-auth-role header.")

                try:
                    x_auth_role = role_name
                    if self._use_operator_group:
                        x_auth_role = account.subject_role(role_name)
                    # throws ValueError if role_name not in Roles enum
                    role = self._roles(x_auth_role)
                except ValueError:
                    abort(401, "Invalid auth parameters. Role name is not found.")
                except PermissionException as e:
                    abort(403, e.message)

                policy = self.policy.get(role.value, {})

                subject = Subject(account, role, owner, policy)
                self._check_permission(subject, action)
                kwargs["subject"] = subject
                return func(*args, **kwargs)

            return wrap

        return wrapper

    def __repr__(self):
        roles = json.dumps([role.name for role in self._roles])
        policy = json.dumps(self.policy, indent=2)
        return f"RBAC(\n" f"  roles={roles},\n" f"  policy=\n{policy},\n" f")"
