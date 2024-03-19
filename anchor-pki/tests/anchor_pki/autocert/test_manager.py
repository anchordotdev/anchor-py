import pytest
import json
import shutil
import diskcache as dc
import os
import datetime
from acme import messages
from freezegun import freeze_time

from anchor_pki.autocert.manager import Manager, IdentifierNotAllowedError
from anchor_pki.autocert.managed_certificate import ManagedCertificate
from anchor_pki.autocert.configuration import Configuration
from anchor_pki.autocert.terms_of_service import AnyAcceptor

vcr_recorded_at = datetime.datetime(2023, 10, 24, tzinfo=datetime.timezone.utc)


class TestManager:
    DEFAULT_URL = "https://anchor.dev/autocert-cab3bc/development/x509/ca/acme"

    DEFAULT_CONFIG_PARAMETERS = {
        "name": "valid",
        "allow_identifiers": "test.lcl.host",
        "contact": "developer@anchor.dev",
        "external_account_binding": {"kid": "kid", "hmac_key": "hmac_key"},
        "tos_acceptors": AnyAcceptor(),
    }

    @pytest.fixture
    def default_params(self):
        return TestManager.DEFAULT_CONFIG_PARAMETERS | {
            "directory_url": TestManager.DEFAULT_URL
        }

    @pytest.fixture
    def manager_params(self, default_params):
        return default_params | {
            "name": "test_manager",
            "allow_identifiers": "manager.lcl.host",
        }

    @pytest.fixture
    def manager_configuration(self, manager_params):
        return Configuration(**manager_params)

    @pytest.fixture
    def manager(self, manager_params):
        config = Configuration(**manager_params)
        manager = Manager(config)
        yield manager

        if manager.cache_dir:
            manager.cache_clear()
            shutil.rmtree(manager.cache_dir)


class TestManagerDelegation(TestManager):
    @pytest.fixture
    def manager_params(self, default_params):
        return default_params | {
            "name": "test_manager_delegation",
            "allow_identifiers": "manager-delegation.lcl.host",
            "cache_dir": "tmp/anchor-pki-test-cache-for-delegation",
            "renew_before_seconds": 42,
            "renew_before_fraction": 0.42,
            "check_every_seconds": 42,
        }

    def test_directory_url(self, manager):
        assert manager.directory_url == TestManager.DEFAULT_URL

    def test_contact(self, manager):
        assert manager.contact == "developer@anchor.dev"

    def test_cache_dir(self, manager):
        assert manager.cache_dir == "tmp/anchor-pki-test-cache-for-delegation"

    def test_renew_before_seconds(self, manager):
        assert manager.renew_before_seconds == 42

    def test_renew_before_fraction(self, manager):
        assert manager.renew_before_fraction == 0.42

    def test_check_every_seconds(self, manager):
        assert manager.check_every_seconds == 42

    def test_tos_acceptors(self, manager):
        assert type(manager.tos_acceptors[0]) == AnyAcceptor

    def test_account_key(self, manager):
        expected = {
            "contact": "developer@anchor.dev",
            "external_account_binding": {"kid": "kid", "hmac_key": "hmac_key"},
        }
        assert manager.account == expected

    def test_acme_kid(self, manager):
        assert manager.acme_kid == "kid"

    def test_acme_hmac_key(self, manager):
        assert manager.acme_hmac_key == "hmac_key"


class TestManagerCache(TestManager):
    @pytest.fixture
    def manager_params(self, default_params):
        return default_params | {
            "name": "test_manager_cache",
            "cache_dir": "tmp/anchor-pki-test-cache-manager-cache",
        }

    def test_cache_dir(self, manager):
        assert (
            manager.configuration.cache_dir == "tmp/anchor-pki-test-cache-manager-cache"
        )

    def test_cache_item(self, manager):
        manager.cache_store("test", "value")
        val = manager.cache_fetch("test")
        assert val == "value"

    def test_cache_clear(self, manager):
        cache = dc.Cache(manager.cache_dir)
        key_count = len(list(cache.iterkeys()))
        assert key_count == 0

        manager.cache_store("test", "value")
        key_count = len(list(cache.iterkeys()))
        assert key_count == 1

        manager.cache_clear()
        key_count = len(list(cache.iterkeys()))
        assert key_count == 0

    def test_account_key_cached(self, manager):
        cache = dc.Cache(manager.cache_dir)
        key_count = len(list(cache.iterkeys()))
        assert key_count == 0

        account_key = manager.account_key()
        key_count = len(list(cache.iterkeys()))
        assert key_count == 1


class TestManagerWithLiveAuth(TestManager):
    # These values need to be kept in sync with the authorization used to
    # generate the vcr cassettes.
    # https://anchor.dev/autocert-cab3bc/services/anchor-pki-py-testing
    ACME_KID = "aae_uWOqncjTdF_1YNrAfFxN01VEG_V-GHKcZyN874y5smvf"
    ACME_HMAC_KEY = "L8LGTnrmyvdPzr4xhvF8sRkCLDgwFiwQ_H0Rw9tvfMEVDV9phUgfONuoxnT-yyye"

    HOST = "anchor-pki-py-testing.lcl.host"

    @pytest.fixture
    def manager_params(self, default_params):
        """Manager that uses dotenv provided credentials"""

        params = default_params | {
            "name": "test_manager_cert",
            "allow_identifiers": [
                self.HOST,
                f"*.{self.HOST}",
            ],
            "cache_dir": "tmp/anchor-pki-test-cache-manager-cert",
            "external_account_binding": {
                "kid": os.environ.get("ACME_KID", self.ACME_KID),
                "hmac_key": os.environ.get("ACME_HMAC_KEY", self.ACME_HMAC_KEY),
            },
            "renew_before_seconds": 24 * 60 * 60 * 14,  # 14 days for testing
        }

        return params


class TestManagerCert(TestManagerWithLiveAuth):
    @pytest.mark.vcr
    def test_provisions_certificate(self, manager):
        cert_data = manager.provision(self.HOST)
        parsed_data = json.loads(cert_data)

        assert "key_pem" in parsed_data
        assert "cert_pem" in parsed_data

        assert "BEGIN PRIVATE KEY" in parsed_data["key_pem"]
        assert "BEGIN CERTIFICATE" in parsed_data["cert_pem"]

    @pytest.mark.vcr
    def test_provision_raises_error_if_identifier_not_allowed(self, manager):
        with pytest.raises(messages.Error):
            manager.provision("invalid.bad.host")

    @pytest.mark.vcr
    def test_managed_certificate(self, manager):
        cert = manager.managed_certificate(self.HOST)
        assert type(cert) == ManagedCertificate
        assert cert.common_name == self.HOST

    @pytest.mark.vcr
    def test_managed_subdomain_certificate(self, manager):
        subdomain = f"sub.{self.HOST}"
        cert = manager.managed_certificate(subdomain)
        assert type(cert) == ManagedCertificate
        assert cert.common_name == subdomain

    @pytest.mark.vcr
    def test_return_fallback_cert_if_all_ids_are_denied(self, manager):
        cert = manager.managed_certificate("invalid.bad.host")
        assert cert.common_name == self.HOST

    def really_long_sub_domain(self):
        chars = "abcdefghijklmnopqrstuvwxyz"
        parts = ["".join([a, b]) for a in chars for b in chars]
        return ".".join(parts)

    @pytest.mark.vcr
    @pytest.mark.skip(reason="backend returns 500 for the moment")
    def test_domain_name_too_long(self, manager):
        sub = self.really_long_sub_domain()
        with pytest.raises(messages.Error):
            manager.provision(f"{sub}.{self.HOST}")

    @pytest.mark.vcr
    @pytest.mark.skip(reason="backend errors 500 for the moment")
    def test_provision_or_fallback(self, manager):
        sub = self.really_long_sub_domain()

        cert_data = manager.provision_or_fallback(f"{sub}.{self.HOST}")

        parsed_data = json.loads(cert_data)
        managed_certificate = ManagedCertificate(manager=self, **parsed_data)

        assert managed_certificate.common_name == self.HOST

    @pytest.mark.vcr
    @pytest.mark.skip(reason="backend errors 500 for the moment")
    def test_returns_fallback_cert_if_acme_raises_error(self, manager_params):
        funky_params = manager_params | {
            "allow_identifiers": [
                self.HOST,
                f"*.sub1.{self.HOST}",
            ]
        }
        config = Configuration(**funky_params)
        manager = Manager(config)

        sub = self.really_long_sub_domain()
        cert = manager.managed_certificate(f"{sub}.{self.HOST}")
        assert cert.common_name == self.HOST

        if manager.cache_dir:
            manager.cache_clear()
            shutil.rmtree(manager.cache_dir)

    @pytest.mark.vcr
    def test_has_all_names_requested(self, manager):
        common_name = self.HOST
        extra_names = [f"auth.{self.HOST}", f"admin.{self.HOST}"]
        all_names = sorted([common_name, *extra_names])
        cert = manager.managed_certificate(common_name, extra_names)

        assert cert.common_name == common_name
        assert cert.identifiers == all_names
        assert cert.all_names == [common_name, *sorted(extra_names)]

    @pytest.mark.vcr
    @freeze_time(vcr_recorded_at)
    def test_returns_the_memory_cached_certificate(self, manager):
        cert = manager.managed_certificate(self.HOST)
        assert type(cert) == ManagedCertificate
        assert cert.common_name == self.HOST

        cert2 = manager.managed_certificate(self.HOST)
        assert cert2.serial == cert.serial

    @pytest.mark.vcr
    @freeze_time(vcr_recorded_at)
    def test_returns_the_same_cert_from_disk_cache(self, manager):
        cert = manager.managed_certificate(self.HOST)
        assert type(cert) == ManagedCertificate
        assert cert.common_name == self.HOST
        assert len(manager.managed_certificates) == 1

        cache = dc.Cache(manager.cache_dir)
        key_count = len(list(cache.iterkeys()))
        assert key_count >= 1

        # clear out the memeory so it has to load from disk cache
        manager.managed_certificates.clear()
        assert len(manager.managed_certificates) == 0

        cert2 = manager.managed_certificate(self.HOST)
        assert cert2.serial == cert.serial

    @pytest.mark.vcr
    @pytest.mark.skip(reason="this test may not be applicable")
    def test_returns_the_same_cert_for_a_set_of_identifiers(self, manager):
        cert_x = manager.managed_certificate(f"x.{self.HOST}")
        cert_y = manager.managed_certificate(f"y.{self.HOST}")

        assert cert_x.serial == cert_y.serial

    def test_denied_identifiers_returns_empty_array(self, manager):
        assert manager.denied_identifiers(None) == []

    def test_denied_identifiers_returns_array(self, manager):
        assert manager.denied_identifiers("bad.host.name") == ["bad.host.name"]


class TestManagerRewalLogic(TestManagerWithLiveAuth):
    @pytest.fixture
    def managed_certificate(self, manager):
        return manager.managed_certificate(self.HOST)

    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestManagerRenwalLogic.renewal_logic_common.yaml")
    def test_renew_after_from_seconds_returns_none_if_before_cert_is_valid(
        self, managed_certificate, manager
    ):
        renewal_period = managed_certificate.not_after - managed_certificate.not_before
        before_seconds = renewal_period.total_seconds() + 1000

        assert (
            manager._renew_after_from_seconds(managed_certificate, before_seconds)
            is None
        )

    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestManagerRenwalLogic.renewal_logic_common.yaml")
    def test_renew_after_from_seconds_returns_datetime_in_valid_range_of_cert(
        self, managed_certificate, manager
    ):
        renew_after = manager._renew_after_from_seconds(managed_certificate)
        assert type(renew_after) == datetime.datetime
        assert renew_after >= managed_certificate.not_before
        assert renew_after <= managed_certificate.not_after

    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestManagerRenwalLogic.renewal_logic_common.yaml")
    def test_renew_after_from_fraction_returns_none_if_before_fraction_is_lt_zero(
        self, managed_certificate, manager
    ):
        assert manager._renew_after_from_fraction(managed_certificate, -0.42) is None

    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestManagerRenwalLogic.renewal_logic_common.yaml")
    def test_renew_after_from_fraction_returns_a_datetime_in_valid_range_of_cert(
        self, managed_certificate, manager
    ):
        renew_after = manager._renew_after_from_fraction(managed_certificate)
        assert type(renew_after) == datetime.datetime
        assert renew_after >= managed_certificate.not_before
        assert renew_after <= managed_certificate.not_after

    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestManagerRenwalLogic.renewal_logic_common.yaml")
    def test_needs_renewal_if_cert_is_not_expiring(self, managed_certificate, manager):
        now_before_renewal_period = managed_certificate.not_before + datetime.timedelta(
            days=2
        )
        assert not manager.needs_renewal(managed_certificate, now_before_renewal_period)

    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestManagerRenwalLogic.renewal_logic_common.yaml")
    def test_needs_renewal_if_cert_is_in_expiration_window(
        self, managed_certificate, manager
    ):
        now_in_window = managed_certificate.not_after - datetime.timedelta(days=10)
        assert manager.needs_renewal(managed_certificate, now_in_window)

    @pytest.mark.vcr
    def test_returns_a_new_cert_upon_expiration(self, managed_certificate, manager):
        first_serial = managed_certificate.serial
        now_in_window = managed_certificate.not_after - datetime.timedelta(days=10)
        new_cert = manager.managed_certificate(self.HOST, now=now_in_window)

        assert new_cert.serial != first_serial
