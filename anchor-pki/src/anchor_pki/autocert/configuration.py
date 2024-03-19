"""
Configuration holds the configuration paramters for a Mananager.

It is configured from, initialization paramaters, defaults and
enviroment variables.

Attributes:
    name (str): The name of the configuration
    allow_identifiers (list): The list of identifiers to allow
    cache_dir (str): The directory to use for caching ACME data
    check_every_seconds (int): How often to check for certificate renewal
    contact (str): The ACME account contact email
    directory_url (str): The ACME directory URL
    external_account_binding (dict): The external account binding, this contains
        the ACME_KID and ACME_MAC_KEY
    renew_before_fraction (float): The fraction of the certificate lifetime at
        which to attempt renewal. This is from the end of the certificate lifetime.
    renew_before_seconds (int): The number of seconds before the end of the
        certificate lifetime at which to attempt renewal.
    tos_acceptors (list of obj): The Acceptor instances that will be used to
        compare against the termos of service url returned by the ACME server.
    work_dir (str): The directory to use for working files. The PEM formats of
        the certificate and the private keys will be stored here on occassion.
"""

import os
import pathlib
from .terms_of_service import Acceptor


class ConfigurationError(Exception):
    """Error raised when there is a configuration issue."""


# pylint: disable=too-many-instance-attributes,too-few-public-methods
class Configuration:
    """Configuration object for a Manager"""

    # 30 days in seconds
    DEFAULT_RENEW_BEFORE_SECONDS = 2_592_000

    # 50% o the cert's validity window
    DEFAULT_RENEW_BEFORE_FRACTION = 0.5

    # How often to check for certificate renewal, every hour by default
    DEFAULT_CHECK_EVERY_SECONDS = 3_600

    # pylint: disable=too-many-arguments,dangerous-default-value
    def __init__(
        self,
        name,
        allow_identifiers=None,
        cache_dir=None,
        check_every_seconds=None,
        contact=None,
        directory_url=None,
        external_account_binding=None,
        renew_before_fraction=None,
        renew_before_seconds=None,
        tos_acceptors=None,
        work_dir=None,
        env=os.environ,
    ):
        self.name = name
        if self.name is None:
            raise ConfigurationError(
                "The Configuration instance has a misconfigured 'name' value. It is required"
            )

        self._env = env.copy()

        self.allow_identifiers = self._prepare_allow_identifiers(allow_identifiers)
        self.cache_dir = cache_dir
        self.check_every_seconds = self._prepare_check_every_seconds(
            check_every_seconds
        )
        self.contact = contact
        self.directory_url = self._prepare_directory_url(directory_url)
        self.external_account_binding = self._prepare_external_account_binding(
            external_account_binding
        )
        self.renew_before_fraction = self._prepare_renew_before_fraction(
            renew_before_fraction
        )
        self.renew_before_seconds = self._prepare_renew_before_seconds(
            renew_before_seconds
        )

        self.tos_acceptors = self._prepare_tos_acceptors(tos_acceptors)

        self.work_dir = work_dir

        self._ensure_directory(self.cache_dir, "cache_dir")
        self._ensure_directory(self.work_dir, "work_dir")

    @property
    def account(self):
        """Return the account information"""
        return {
            "contact": self.contact,
            "external_account_binding": self.external_account_binding,
        }

    @property
    def acme_kid(self):
        """Return the ACME account kid"""
        return self.external_account_binding["kid"]

    @property
    def acme_hmac_key(self):
        """Return the ACME account hmac_key"""
        return self.external_account_binding["hmac_key"]

    @property
    def fallback_identifier(self):
        """
        Return the fallback identifer for this configuration

        look at all the identifiers, strip a leading wildcard off of all of
        them and then pick the one that has the fewest '.' in it, if there are
        ties for fewest, pick the first one in the list of ties. A minimum of
        2 '.' is required.
        """

        de_wildcarded = [i.removeprefix("*.") for i in self.allow_identifiers]
        not_tld = [ident for ident in de_wildcarded if ident.count(".") >= 2]
        ordered = sorted(not_tld, key=lambda x: x.count("."))
        return ordered[0]

    def _prepare_allow_identifiers(self, allow_identifiers):
        """Prepares the allow_identifiers configuration parameter."""

        if isinstance(allow_identifiers, list):
            prepared = allow_identifiers
        elif isinstance(allow_identifiers, str):
            prepared = allow_identifiers.split(",")
        elif allow_identifiers is None:
            env_allow = self._env.get("ACME_ALLOW_IDENTIFIERS")
            prepared = env_allow.split(",") if env_allow else None
        else:
            raise ConfigurationError("Invalid input type for allow_identifiers")

        if prepared is None or len(prepared) == 0:
            raise ConfigurationError(
                f"The '{self.name}' Configuration instance has a misconfigured"
                "`allow_identifiers` value. Set it to a string, or an array of "
                "strings, or set the ACME_ALLOW_IDENTIFIERS environment "
                "variable to a comma-separated list of identifiers."
            )

        return [ident.strip() for ident in prepared]

    def _prepare_directory_url(self, directory_url):
        """Prepares the directory_url configuration parameter."""

        prepared = directory_url or self._env.get("ACME_DIRECTORY_URL")

        if prepared is None:
            raise ConfigurationError(
                f"The '{self.name}' Configuration instance has a misconfigured"
                " `directory_url` value. It must be set to a string, or set "
                "the ACME_DIRECTORY_URL environment variable."
            )

        return prepared

    def _prepare_external_account_binding(self, external_account_binding):
        """Prepares the external_account_binding configuration parameter."""
        kid = self._env.get("ACME_KID")
        hmac_key = self._env.get("ACME_HMAC_KEY")

        if (
            external_account_binding
            and ("kid" in external_account_binding)
            and ("hmac_key" in external_account_binding)
        ):
            return external_account_binding

        return {"kid": kid, "hmac_key": hmac_key}

    def _prepare_renew_before_fraction(self, renew_before_fraction):
        """Prepares the renew_before_fraction configuration parameter."""

        message = (
            f"The '{self.name}' Configuration instance has a misconfigured "
            "`renew_before_fraction` value. It must be set to a float > 0 and "
            "< 1, or set the ACME_RENEW_BEFORE_FRACTION environment variable."
        )

        candidates = [
            renew_before_fraction,
            self._env.get("ACME_RENEW_BEFORE_FRACTION"),
            self.DEFAULT_RENEW_BEFORE_FRACTION,
        ]

        for candidate in candidates:
            try:
                prepared = float(candidate)
                if 0 < prepared < 1:
                    return prepared
            except TypeError:
                pass

        # probably can never happen unless self.DEFAULT_RENEW_BEFORE_ACTION is changed
        raise ConfigurationError(message)

    def _prepare_renew_before_seconds(self, renew_before_seconds):
        """Prepares the renew_before_seconds configuration parameter."""

        message = (
            f"The '{self.name}' Configuration instance has a misconfigured "
            "`renew_before_seconds` value. It must be set to an integer > 0, "
            "or set the ACME_RENEW_BEFORE_SECONDS environment variable."
        )

        candidates = [
            renew_before_seconds,
            self._env.get("ACME_RENEW_BEFORE_SECONDS"),
            self.DEFAULT_RENEW_BEFORE_SECONDS,
        ]
        return self._ensure_positive_integer(candidates, message)

    def _prepare_tos_acceptors(self, tos_acceptors):
        """Prepares the tos_acceptors configuration parameter."""

        message = (
            f"The '{self.name}' Configuration instance has a misconfigured "
            "`tos_acceptors` value. It must be set to an instance or list of "
            "instances that inherit from Acceptor."
        )

        if isinstance(tos_acceptors, list):
            prepared = tos_acceptors
        elif isinstance(tos_acceptors, Acceptor):
            prepared = [tos_acceptors]
        else:
            raise ConfigurationError(message)

        for acceptor in prepared:
            if not isinstance(acceptor, Acceptor):
                raise ConfigurationError(message)

        return prepared

    def _prepare_check_every_seconds(self, check_every_seconds):
        """Prepares the check_every_seconds configuration parameter."""

        message = (
            f"The '{self.name}' Configuration instance has a misconfigured "
            "`check_every_seconds` value. It must be set to an integer > 0, or "
            "set the AUTO_CERT_CHECK_EVERY environment variable."
        )

        candidates = [
            check_every_seconds,
            self._env.get("AUTO_CERT_CHECK_EVERY"),
            self.DEFAULT_CHECK_EVERY_SECONDS,
        ]
        return self._ensure_positive_integer(candidates, message)

    def _ensure_positive_integer(self, candidates, message):
        """
        Return the first positive integer-like candidate. If none are,
        raise the message as a ConfigurationError
        """

        for candidate in candidates:
            try:
                prepared = int(candidate)
                if prepared > 0:
                    return prepared
            except ValueError:
                pass
            except TypeError:
                pass

        raise ConfigurationError(message)

    def _ensure_directory(self, directory, directory_property):
        """Ensure that the directory exists and is a directory"""

        if directory is None:
            return None

        path = pathlib.Path(directory).absolute()

        message = (
            f"The '${self.name}' Configuration instance has a misconfigured "
            f"`{directory_property}` value, it resolves to ({path}). "
            "It must be set to a directory, or a path that can be created."
        )

        try:
            path.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise ConfigurationError(message) from exc

        return True
