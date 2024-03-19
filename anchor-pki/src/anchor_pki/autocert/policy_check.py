"""
The Policy Check module containts the PolicyCheck base class / interface
and the child class implementations.

These are utility classes used by the IdentifierPolicly class to check hostname
identifiers against particular hostname policy rules.
"""

import ipaddress
import re


class PolicyCheck:
    """Base PolicyCheck class defining the interface"""

    @classmethod
    def handles(cls, description):
        """Return true if this class can handle the description"""
        raise NotImplementedError(f"{cls.__name__} must implement handles(description)")

    def __init__(self, description):
        self.policy_description = description

    def deny(self, identifier):
        """Return true if the identifier is denied by this policy"""
        return not self.allow(identifier)

    def allow(self, identifier):
        """Return true if the identifier is allowed by this policy"""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement allow(identifier)"
        )


class ForHostname(PolicyCheck):
    """
    A Hostname policy check that allows a hostname to be specified in the
    policy and it will be used to match against incoming hostnames later.
    """

    ALPHA = "[a-zA-Z]"
    ALPHA_NUMERIC = "[a-zA-Z0-9]"
    ALPHA_NUMERIC_HYPHEN = "[-a-zA-Z0-9]"
    DOMAIN_LABEL = f"{ALPHA_NUMERIC}{ALPHA_NUMERIC_HYPHEN}*{ALPHA_NUMERIC}"
    TOP_LEVEL_DOMAIN = f"{ALPHA}{ALPHA_NUMERIC_HYPHEN}*{ALPHA_NUMERIC}"

    REGEX = re.compile(f"^(?P<sub>(({DOMAIN_LABEL}\\.)+))(?P<tld>{TOP_LEVEL_DOMAIN})$")

    @classmethod
    def handles(cls, description):
        return isinstance(description, str) and cls.REGEX.match(description)

    def __init__(self, description):
        super().__init__(description)
        self.hostname = description.lower()

    def allow(self, identifier):
        return isinstance(identifier, str) and (identifier.lower() == self.hostname)


class ForWildcardHostname(PolicyCheck):
    """
    A Wildcard Hostname policy check that allows a wildcard hostname to be
    specified in the policy and it will be used to match against incoming
    hostnames later.
    """

    DOMAIN_LABEL_REGEX = re.compile(f"^{ForHostname.DOMAIN_LABEL}*$", re.IGNORECASE)
    SPLAT = "*"

    @classmethod
    def handles(cls, description):
        if not isinstance(description, str):
            return False

        parts = description.split(".")

        if (len(parts) < 2) or (parts[0] != cls.SPLAT):
            return False

        suffix = ".".join(parts[1:])

        return ForHostname.handles(suffix)

    def __init__(self, description):
        super().__init__(description)
        self.parts = description.split(".")
        self.wildcard = self.parts.pop(0)
        self.suffix = ".".join(self.parts)

    def allow(self, identifier):
        if not isinstance(identifier, str):
            return False
        parts = identifier.split(".")
        prefix = parts.pop(0)

        if (prefix != self.SPLAT) and (not self.DOMAIN_LABEL_REGEX.match(prefix)):
            return False

        domain = ".".join(parts).lower()

        return domain == self.suffix


class ForIPAddress(PolicyCheck):
    """
    An IP Address policy check that allows an IP Address, or network
    to be specified in the policy and it will be used to match against
    incoming IP Addresses later.
    """

    @classmethod
    def handles(cls, description):
        try:
            ipaddress.ip_network(description)
            return True
        except ValueError:
            return False

    def __init__(self, description):
        super().__init__(description)
        self.ip_network = ipaddress.ip_network(description)

    def allow(self, identifier):
        try:
            network = ipaddress.ip_network(identifier)
            return self.ip_network.overlaps(network)
        except ValueError:
            return False
