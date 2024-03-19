"""
Manages the ACME client and the certificates it generates.
"""

import datetime
import json
import math
import tempfile
import importlib.metadata
from pathlib import Path
from urllib.parse import urlparse

import diskcache as dc

import josepy as jose
from josepy import jwa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import OpenSSL
from acme.client import ClientV2, ClientNetwork
from acme import messages, crypto_util


from .identifier_policy import IdentifierPolicy
from .managed_certificate import ManagedCertificate


class IdentifierNotAllowedError(Exception):
    """Raised when an identifier is not allowed by the policy"""


# pylint: disable=too-many-public-methods
class Manager:
    """
    Manages the ACME client and the certificates it generates.
    """

    # 1 day in seconds
    FALLBACK_RENEW_BEFORE_SECONDS = 86_400

    VERSION = importlib.metadata.version("anchor-pki")
    USER_AGENT = f"anchor-pki autocert python client v{VERSION}"

    # Certificate private key size
    CERT_PRIVATE_KEY_BITS = 2048

    def __init__(self, configuration):
        self.configuration = configuration
        self.identifier_policies = IdentifierPolicy.build(
            self.configuration.allow_identifiers
        )
        self.work_dir = Path(self.configuration.work_dir or tempfile.mkdtemp())
        self.enabled = True
        self.managed_certificates = {}

    @property
    def contact(self):
        """return the Manager's contact"""
        return self.configuration.contact

    @property
    def acme_kid(self):
        """return the Manager's acme_kid"""
        return self.configuration.acme_kid

    @property
    def acme_hmac_key(self):
        """return the Manager's acme_hmac_key"""
        return self.configuration.acme_hmac_key

    @property
    def directory_url(self):
        """return the Manager's directory_url"""
        return self.configuration.directory_url

    @property
    def tos_acceptors(self):
        """return the Manager's tos_acceptors"""
        return self.configuration.tos_acceptors

    @property
    def account(self):
        """return the Manager's account"""
        return self.configuration.account

    @property
    def fallback_identifier(self):
        """return the Manager's fallback_identifier"""
        return self.configuration.fallback_identifier

    @property
    def check_every_seconds(self):
        """return the Manager's check_every_seconds parameter"""
        return self.configuration.check_every_seconds

    @property
    def renew_before_seconds(self):
        """return the Manager's renew_before_seconds parameter"""
        return (
            self.configuration.renew_before_seconds
            or self.FALLBACK_RENEW_BEFORE_SECONDS
        )

    @property
    def renew_before_fraction(self):
        """return the Manager's renew_before_fraction parameter"""
        return self.configuration.renew_before_fraction

    @property
    def cache_dir(self):
        """return the Manager's cache_dir"""
        return self.configuration.cache_dir

    def cache_store(self, key, value):
        """store the item in the cache"""
        stored = False

        if self.cache_dir:
            with dc.Cache(self.cache_dir) as cache:
                stored = cache.set(key, value)

        return stored

    def cache_fetch(self, key):
        """fetch the item from the cache"""
        value = None

        if self.cache_dir:
            with dc.Cache(self.cache_dir) as cache:
                value = cache.get(key)

        return value

    def cache_clear(self):
        """clear the cache"""
        if self.cache_dir:
            with dc.Cache(self.cache_dir) as cache:
                cache.clear()

    def account_key(self):
        """return the account key, generating it if necessary"""
        host = urlparse(self.directory_url).hostname
        cache_key = "+".join([self.contact or "default", host, "key"])
        serialized_account_key = self.cache_fetch(cache_key)

        if not serialized_account_key:
            private_key = self._create_account_key()
            serialized_account_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            self.cache_store(cache_key, serialized_account_key)

        private_key = serialization.load_pem_private_key(
            serialized_account_key, password=None
        )
        account_key = jose.JWKEC(key=private_key)
        return account_key

    def managed_certificate(self, common_name, identifiers=None, now=None):
        """
        return the managed certificate for the given common_name, generating
        it if necessary.
        """
        if now is None:
            now = datetime.datetime.now(datetime.timezone.utc)

        full_identifiers = self.consolidate_identifiers(common_name, identifiers)
        denied_ids = self.denied_identifiers(full_identifiers)

        # Fallback to a configured identifier if the requested one(s) are denied
        if denied_ids and len(denied_ids) > 0:
            common_name = self.fallback_identifier
            identifiers = None

        managed_certificate = self.managed_certificates.get(common_name)

        if managed_certificate and not self.needs_renewal(managed_certificate, now):
            return managed_certificate

        # check the cache and see if there is a cert there and if it is still
        # valid
        cert_data = self.cache_fetch(common_name)
        parsed_data = None

        if cert_data:
            parsed_data = json.loads(cert_data)
            managed_certificate = ManagedCertificate(
                persist_dir=self.work_dir, **parsed_data
            )
            if managed_certificate and self.needs_renewal(managed_certificate, now):
                managed_certificate = None
            else:
                print(
                    f"Certificate for {common_name} returned from disk cache ({self.cache_dir})"
                )
                return managed_certificate

        cert_data = self.provision_or_fallback(common_name, identifiers)

        parsed_data = json.loads(cert_data)
        managed_certificate = ManagedCertificate(
            persist_dir=self.work_dir, **parsed_data
        )
        self.managed_certificates[common_name] = managed_certificate

        was_cached = self.cache_store(common_name, cert_data)
        if was_cached:
            print(f"Certificate for {common_name} cached in ({self.cache_dir}).")

        return managed_certificate

    def provision_or_fallback(self, common_name, identifiers=None):
        """Provision the cert, but on error, use the fallback"""
        try:
            return self.provision(common_name, identifiers)
        except Exception:  # pylint: disable=broad-exception-caught
            return self.provision(self.fallback_identifier, None)

    def provision(self, common_name, identifiers=None):
        """
        provision a new certificate for the given common_name and identifiers
        returns the full certificate pem chain and the private key pem, in a
        JSON structure:

        { "cert_pem": "....", "key_pem": "...." }

        """

        # Prepare the client
        client = self._create_acme_client()
        reg_message = self._create_registration_message(client)
        client.new_account(reg_message)

        # make the CSR
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, self.CERT_PRIVATE_KEY_BITS)
        pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
        all_identifiers = self.consolidate_identifiers(common_name, identifiers)
        csr_pem = crypto_util.make_csr(pkey_pem, all_identifiers)

        # Submit the order
        order = client.new_order(csr_pem)

        # Fetch the certs
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)
        finalized_order = client.finalize_order(order, deadline)
        fullchain_pem = finalized_order.fullchain_pem

        # serialize the results
        cert_data = json.dumps(
            {
                "cert_pem": fullchain_pem,
                "key_pem": pkey_pem.decode("utf-8"),  # convert bytes to string
            }
        )

        return cert_data

    def denied_identifiers(self, identifiers):
        """return the identifiers that are denied by the policy"""
        if identifiers is None:
            return []

        if not isinstance(identifiers, list):
            identifiers = [identifiers]

        # An identifier is denied if any of the policies deny it
        denied = []
        for identifier in identifiers:
            if all(policy.deny(identifier) for policy in self.identifier_policies):
                denied.append(identifier)

        return denied

    def needs_renewal(self, managed_certificate, now=None):
        """return True if the certificate needs renewal"""
        if now is None:
            now = datetime.datetime.now(datetime.timezone.utc)

        posibilities = [
            self._renew_after_from_seconds(managed_certificate),
            self._renew_after_from_fraction(managed_certificate),
            self._renew_after_fallback(managed_certificate),
            managed_certificate.not_after,
        ]
        renew_after = min(filter(None, posibilities))

        return now > renew_after

    def _renew_after_from_seconds(self, managed_certificate, before_seconds=None):
        if before_seconds is None:
            before_seconds = self.renew_before_seconds

        renew_after = managed_certificate.not_after - datetime.timedelta(
            seconds=before_seconds
        )

        if (
            managed_certificate.not_before
            <= renew_after
            <= managed_certificate.not_after
        ):
            return renew_after

        return None

    def _renew_after_from_fraction(self, managed_certificate, before_fraction=None):
        if before_fraction is None:
            before_fraction = self.renew_before_fraction

        if not 0 <= before_fraction <= 1:
            return None

        valid_span = (
            managed_certificate.not_after - managed_certificate.not_before
        ).total_seconds()
        before_seconds = math.floor(valid_span * before_fraction)

        return self._renew_after_from_seconds(managed_certificate, before_seconds)

    def _renew_after_fallback(self, managed_certificate):
        return self._renew_after_from_seconds(
            managed_certificate, self.FALLBACK_RENEW_BEFORE_SECONDS
        )

    def terms_of_service_agreed(self, client, terms_of_service_url=None):
        """Check the terms of service agreement url terms of service acceptor"""

        if terms_of_service_url is None:
            terms_of_service_url = client.directory.meta.terms_of_service

        if terms_of_service_url is None:
            return True

        agreed = any(
            acceptor.accept(terms_of_service_url) for acceptor in self.tos_acceptors
        )

        return agreed

    def _create_account_key(self):
        return ec.generate_private_key(ec.SECP256R1)

    def _create_acme_client(self):
        """return a new ACME client"""
        net = ClientNetwork(
            self.account_key(), user_agent=self.USER_AGENT, alg=jwa.ES256
        )
        directory = ClientV2.get_directory(self.directory_url, net)
        client_acme = ClientV2(directory, net=net)
        return client_acme

    def _create_eab_message(self, client):
        account_public_key = client.net.key.public_key()
        directory = client.directory

        return messages.ExternalAccountBinding.from_data(
            account_public_key=account_public_key,
            kid=self.acme_kid,
            hmac_key=self.acme_hmac_key,
            directory=directory,
        )

    def _create_registration_message(self, client):
        eab_message = self._create_eab_message(client)
        reg_message = messages.NewRegistration.from_data(
            email=self.contact,
            terms_of_service_agreed=self.terms_of_service_agreed(client),
            external_account_binding=eab_message,
        )
        return reg_message

    def consolidate_identifiers(self, common_name, identifiers=None):
        """
        return a list of identifiers with duplicates removed
        preserving order with the common_name first
        """

        identifiers = identifiers or []
        domains = dict.fromkeys([common_name, *identifiers])
        return list(domains.keys())
