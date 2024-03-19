import pytest
import os
import pathlib
from anchor_pki.autocert.configuration import (
    Configuration,
    ConfigurationError,
)

from anchor_pki.autocert.terms_of_service import AnyAcceptor, RegexAcceptor


class TestConfiguration:
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
        return TestConfiguration.DEFAULT_CONFIG_PARAMETERS | {
            "directory_url": TestConfiguration.DEFAULT_URL
        }

    @pytest.fixture
    def blank_configuration(self, default_params):
        blank_params = default_params | {
            "name": "blank",
            "allow_identifiers": "blank.lcl.host",
        }

        return Configuration(**blank_params)

    @pytest.fixture
    def minimal_params(self, default_params):
        return default_params | {
            "name": "minimal",
            "allow_identifiers": "minimal.lcl.host",
        }

    @pytest.fixture
    def minimal_configuration(self, minimal_params):
        return Configuration(**minimal_params)

    ## Default class level items
    def test_default_before_seconds(self, blank_configuration):
        assert blank_configuration.DEFAULT_RENEW_BEFORE_SECONDS == 60 * 60 * 24 * 30

    def test_default_before_fraction(self, blank_configuration):
        assert blank_configuration.DEFAULT_RENEW_BEFORE_FRACTION == 0.5

    def test_default_check_every_seconds(self, blank_configuration):
        assert blank_configuration.DEFAULT_CHECK_EVERY_SECONDS == 60 * 60

    ## name attribute
    ##
    def test_name(self, minimal_configuration):
        assert minimal_configuration.name == "minimal"

    def test_name_can_change(self, minimal_configuration):
        minimal_configuration.name = "new_name"
        assert minimal_configuration.name == "new_name"

    def test_missing_name(self, default_params):
        default_params["name"] = None

        with pytest.raises(ConfigurationError):
            Configuration(**default_params)

    ## allow_identifiers attribute
    ##
    def test_allow_identifiers(self, minimal_configuration):
        assert minimal_configuration.allow_identifiers == ["minimal.lcl.host"]

    def test_multiple_allow_identifiers(self, minimal_params):
        minimal_params["allow_identifiers"] = [
            "minimal.lcl.host",
            "minimal2.lcl.host",
        ]
        configuration = Configuration(**minimal_params)

        assert configuration.allow_identifiers == [
            "minimal.lcl.host",
            "minimal2.lcl.host",
        ]

    def test_load_allow_identifiers_from_env(self, minimal_params):
        del minimal_params["allow_identifiers"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_ALLOW_IDENTIFIERS": "env.lcl.host",
        }
        configuration = Configuration(**minimal_params)
        assert configuration.allow_identifiers == ["env.lcl.host"]

    def test_load_multiple_allow_identifiers_from_env(self, minimal_params):
        del minimal_params["allow_identifiers"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_ALLOW_IDENTIFIERS": "env.lcl.host,env2.lcl.host",
        }
        configuration = Configuration(**minimal_params)
        assert configuration.allow_identifiers == ["env.lcl.host", "env2.lcl.host"]

    def test_multiple_allow_identifiers_from_env_with_spaces(self, minimal_params):
        del minimal_params["allow_identifiers"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_ALLOW_IDENTIFIERS": "env.lcl.host, env2.lcl.host",
        }
        configuration = Configuration(**minimal_params)
        assert configuration.allow_identifiers == ["env.lcl.host", "env2.lcl.host"]

    def test_raises_error_if_no_allow_identifiers(self, minimal_params):
        del minimal_params["allow_identifiers"]
        with pytest.raises(ConfigurationError):
            Configuration(**minimal_params)

    def test_raises_error_if_allow_identifiers_is_unparsable(self, minimal_params):
        minimal_params["allow_identifiers"] = 42
        with pytest.raises(ConfigurationError):
            Configuration(**minimal_params)

    def test_fallback_identifier_with_one_allow(self, minimal_params):
        del minimal_params["allow_identifiers"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_ALLOW_IDENTIFIERS": "fallback.lcl.host"
        }
        configuration = Configuration(**minimal_params)
        assert configuration.fallback_identifier == "fallback.lcl.host"

    def test_fallback_identifier_with_wildcard_result(self, minimal_params):
        del minimal_params["allow_identifiers"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_ALLOW_IDENTIFIERS": "auth.fallback.lcl.host, *.fallback.lcl.host"
        }
        configuration = Configuration(**minimal_params)
        assert configuration.fallback_identifier == "fallback.lcl.host"

    def test_fallback_identifier_with_invalid_wildard_fallback(self, minimal_params):
        del minimal_params["allow_identifiers"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_ALLOW_IDENTIFIERS": "auth.fallback.lcl.host, *.lcl.host"
        }
        configuration = Configuration(**minimal_params)
        assert configuration.fallback_identifier == "auth.fallback.lcl.host"

    def test_fallback_identifier_use_minimal_dots_match(self, minimal_params):
        del minimal_params["allow_identifiers"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_ALLOW_IDENTIFIERS": "x.auth.fallback.lcl.host, fallback.lcl.host"
        }
        configuration = Configuration(**minimal_params)
        assert configuration.fallback_identifier == "fallback.lcl.host"

    def test_fallback_identifier_first_minimum(self, minimal_params):
        del minimal_params["allow_identifiers"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_ALLOW_IDENTIFIERS": "auth.fallback.lcl.host, admin.fallback.lcl.host"
        }
        configuration = Configuration(**minimal_params)
        assert configuration.fallback_identifier == "auth.fallback.lcl.host"

    ## Account
    def test_account(self, minimal_params):
        configuration = Configuration(**minimal_params)
        assert configuration.account == {
            "contact": minimal_params["contact"],
            "external_account_binding": minimal_params["external_account_binding"],
        }

    ## Contact
    def test_contact(self, minimal_configuration):
        assert minimal_configuration.contact == "developer@anchor.dev"

    ## check every seconds
    def test_check_every_seconds(self, minimal_configuration):
        assert minimal_configuration.check_every_seconds == 60 * 60

    def test_loads_check_every_seconds_from_env(self, minimal_params):
        minimal_params["check_every_seconds"] = None
        minimal_params["env"] = os.environ.copy() | {
            "AUTO_CERT_CHECK_EVERY": "42",
        }
        configuration = Configuration(**minimal_params)
        assert configuration.check_every_seconds == 42

    ## directory url
    def test_directory_url(self, minimal_configuration):
        assert minimal_configuration.directory_url == TestConfiguration.DEFAULT_URL

    def test_loads_directory_url_from_env(self, minimal_params):
        del minimal_params["directory_url"]
        minimal_params["env"] = os.environ.copy() | {
            "ACME_DIRECTORY_URL": "env_directory_url"
        }
        configuration = Configuration(**minimal_params)
        assert configuration.directory_url == "env_directory_url"

    def test_raises_error_if_no_directory_url(self, minimal_params):
        del minimal_params["directory_url"]
        with pytest.raises(ConfigurationError):
            Configuration(**minimal_params)

    ## external_account_binding
    def test_external_account_binding(self, minimal_configuration):
        assert minimal_configuration.external_account_binding == {
            "kid": "kid",
            "hmac_key": "hmac_key",
        }

    def test_loads_external_account_binding_from_env(self, minimal_params):
        minimal_params["env"] = os.environ.copy() | {
            "ACME_KID": "env_kid",
            "ACME_HMAC_KEY": "env_hmac_key",
        }
        del minimal_params["external_account_binding"]

        configuration = Configuration(**minimal_params)
        assert configuration.external_account_binding == {
            "kid": "env_kid",
            "hmac_key": "env_hmac_key",
        }

    def test_acme_kid(self, minimal_configuration):
        assert minimal_configuration.acme_kid == "kid"

    def test_acme_hma_key(self, minimal_configuration):
        assert minimal_configuration.acme_hmac_key == "hmac_key"

    ## renew before fraction
    def test_renew_before_fraction(self, minimal_configuration):
        assert minimal_configuration.renew_before_fraction == 0.5

    def test_can_set_renew_before_fraction_explicitly(self, minimal_params):
        minimal_params["renew_before_fraction"] = 0.42
        configuration = Configuration(**minimal_params)
        assert configuration.renew_before_fraction == 0.42

    def test_loads_renew_before_fraction_from_env(self, minimal_params):
        minimal_params["env"] = os.environ.copy() | {
            "ACME_RENEW_BEFORE_FRACTION": "0.75",
        }
        configuration = Configuration(**minimal_params)
        assert configuration.renew_before_fraction == 0.75

    def test_falls_back_to_default_if_unparsable(self, minimal_params):
        minimal_params["env"] = os.environ.copy() | {
            "ACME_RENEW_BEFORE_FRACTION": "not a float",
        }
        configuration = Configuration(**minimal_params)
        assert (
            configuration.renew_before_fraction
            == Configuration.DEFAULT_RENEW_BEFORE_FRACTION
        )

    ## renew before seconds
    def test_renew_before_seconds(self, minimal_configuration):
        assert minimal_configuration.renew_before_seconds == 60 * 60 * 24 * 30

    def test_can_set_renew_before_seconds_explicitly(self, minimal_params):
        minimal_params["renew_before_seconds"] = 42_000
        configuration = Configuration(**minimal_params)
        assert configuration.renew_before_seconds == 42_000

    def test_loads_renew_before_seconds_from_env(self, minimal_params):
        minimal_params["env"] = os.environ.copy() | {
            "ACME_RENEW_BEFORE_SECONDS": "30000",
        }
        configuration = Configuration(**minimal_params)
        assert configuration.renew_before_seconds == 30_000

    def test_falls_back_to_default_if_unparsable(self, minimal_params):
        minimal_params["env"] = os.environ.copy() | {
            "ACME_RENEW_BEFORE_SECONDS": "not_a_number",
        }
        configuration = Configuration(**minimal_params)
        assert (
            configuration.renew_before_seconds
            == Configuration.DEFAULT_RENEW_BEFORE_SECONDS
        )

    ## tos_acceptors
    def test_tos_acceptors(self, minimal_configuration):
        assert len(minimal_configuration.tos_acceptors) == 1
        assert isinstance(minimal_configuration.tos_acceptors[0], AnyAcceptor)

    def test_raises_an_error_if_tos_acceptors_is_missing(self, minimal_params):
        del minimal_params["tos_acceptors"]
        with pytest.raises(ConfigurationError):
            Configuration(**minimal_params)

    def test_multiple_tos_acceptors(self, minimal_params):
        minimal_params["tos_acceptors"] = [
            AnyAcceptor(),
            RegexAcceptor(".*"),
        ]
        configuration = Configuration(**minimal_params)
        assert len(configuration.tos_acceptors) == 2

    def test_raises_an_error_if_non_acceptor_in_tos_acceptors(self, minimal_params):
        minimal_params["tos_acceptors"] = [AnyAcceptor(), "not an acceptor"]
        with pytest.raises(ConfigurationError):
            Configuration(**minimal_params)

    ## _ensure_positive_integer
    def test_ensure_positive_integer_can_raise(self, minimal_configuration):
        with pytest.raises(ConfigurationError):
            minimal_configuration._ensure_positive_integer(["name"], "Bad Number")

    ## working_directory
    def test_work_dir_is_settable(self, minimal_params, tmp_path_factory):
        work_dir = tmp_path_factory.mktemp("working")
        minimal_params["work_dir"] = str(work_dir)
        configuration = Configuration(**minimal_params)
        assert configuration.work_dir == str(work_dir)

    def test_raises_error_if_work_dir_is_not_writable(self, minimal_params):
        work_dir = "/sys/work-dir-not-writeable"  # /sys is a read only filesystem
        minimal_params["work_dir"] = work_dir
        with pytest.raises(ConfigurationError):
            Configuration(**minimal_params)

    def test_creates_work_dir_if_it_does_not_exist(
        self, minimal_params, tmp_path_factory
    ):
        work_dir = tmp_path_factory.mktemp("autocert") / "working"
        minimal_params["work_dir"] = str(work_dir)
        assert not work_dir.exists()

        configuration = Configuration(**minimal_params)
        assert work_dir.exists()

    def test_is_ok_if_work_dir_exists(self, minimal_params, tmp_path_factory):
        work_dir = tmp_path_factory.mktemp("working")
        minimal_params["work_dir"] = str(work_dir)

        assert work_dir.exists()

        configuration = Configuration(**minimal_params)
        assert pathlib.Path(configuration.work_dir).exists()

    ## cache directory
    def test_cache_dir_is_settable(self, minimal_params, tmp_path_factory):
        cache_dir = tmp_path_factory.mktemp("cache")
        minimal_params["cache_dir"] = str(cache_dir)
        configuration = Configuration(**minimal_params)
        assert configuration.cache_dir == str(cache_dir)

    def test_raises_error_if_cache_dir_is_not_writable(self, minimal_params):
        cache_dir = "/sys/cache-dir-not-writeable"  # /sys is a read only filesystem
        minimal_params["cache_dir"] = cache_dir
        with pytest.raises(ConfigurationError):
            Configuration(**minimal_params)

    def test_creates_cache_dir_if_it_does_not_exist(
        self, minimal_params, tmp_path_factory
    ):
        cache_dir = tmp_path_factory.mktemp("autocert") / "cache"
        minimal_params["cache_dir"] = str(cache_dir)
        assert not cache_dir.exists()

        configuration = Configuration(**minimal_params)
        assert cache_dir.exists()

    def test_is_ok_if_cache_dir_exists(self, minimal_params, tmp_path_factory):
        cache_dir = tmp_path_factory.mktemp("cache_dir")
        minimal_params["cache_dir"] = str(cache_dir)

        assert cache_dir.exists()

        configuration = Configuration(**minimal_params)
        assert pathlib.Path(configuration.cache_dir).exists()
