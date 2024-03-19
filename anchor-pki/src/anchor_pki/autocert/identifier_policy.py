"""
IdentifierPolicy is a class used to check that identifiers used in certs will be
valid.

Each IdentifierPolicy is initialized with a 'policy_description' which is used to
derive the policy check.

Current Policy Checks are:
- ForHostname - checks that the identifier matches hostname exactly
- ForWildcardHostname - checks that the identifier matches hostname with a wildcard prefix
- ForIpAddress - checks that the identifier matches an IP address or subnet
"""

from .policy_check import ForHostname, ForWildcardHostname, ForIPAddress


class PolicyCheckError(Exception):
    """PolicyCheckError is raised when a policy check cannot be built."""


class IdentifierPolicy:
    """IdentifierPolicy checks that identifiers used in certs will be valid."""

    @classmethod
    def build(cls, policy_descriptions):
        """
        Builds a sequence of IdentifierPolicy instances based upon the input
        policy_descriptions.
        """
        if isinstance(policy_descriptions, str):
            policy_descriptions = [policy_descriptions]

        return [cls(policy_description) for policy_description in policy_descriptions]

    @staticmethod
    def policy_checks():
        """
        The list of policy checks that are available, the ordering here is
        important as the first one that matches is the one that is used for the
        check. So if a policy description would be matched by multiple checks,
        the one that it should match should be first.
        """
        return [ForIPAddress, ForHostname, ForWildcardHostname]

    def __init__(self, policy_description):
        self.policy_description = policy_description

        policy_class = next(
            (
                check
                for check in IdentifierPolicy.policy_checks()
                if check.handles(policy_description)
            ),
            None,
        )

        if policy_class:
            self.policy = policy_class(policy_description)
        else:
            raise PolicyCheckError(
                f"No policy check found to handle policy description: {policy_description}"
            )

    def allow(self, identifier):
        """Returns True if the identifier is allowed by the policy."""

        return self.policy.allow(identifier)

    def deny(self, identifier):
        """Returns True if the identifier is not allowed by the policy."""

        return not self.allow(identifier)
