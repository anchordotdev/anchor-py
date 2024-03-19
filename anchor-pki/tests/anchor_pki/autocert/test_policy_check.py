import pytest
from anchor_pki.autocert.policy_check import (
    PolicyCheck,
    ForHostname,
    ForWildcardHostname,
    ForIPAddress,
)


class TestPolicyCheck:
    @pytest.fixture
    def policy_check(self):
        return PolicyCheck("illegal instatiation")

    def test_handles_raises_not_implemented_error(self, policy_check):
        with pytest.raises(NotImplementedError):
            PolicyCheck.handles("bad-idea")

    def test_deny_raises_not_implemented_error(self, policy_check):
        with pytest.raises(NotImplementedError):
            policy_check.deny("bad-idea")

    def test_allow_raises_not_implemented_error(self, policy_check):
        with pytest.raises(NotImplementedError):
            policy_check.allow("bad-idea")


class TestForHostname:
    @pytest.fixture
    def for_hostname(self):
        return ForHostname("test.example.com")

    def test_handles_hostname(self):
        assert ForHostname.handles("test.example.com")

    def test_does_not_handle_wildcard_hostname(self):
        assert not ForHostname.handles("*.test.example.com")

    def test_does_not_handle_non_string(self):
        assert not ForHostname.handles(None)

    def test_denies_non_hostname(self):
        assert not ForHostname.handles("domain-name")

    def test_creates_a_for_hostname_policy_check(self, for_hostname):
        assert isinstance(for_hostname, ForHostname)

    def test_allows_exact_hostname_match(self, for_hostname):
        assert for_hostname.allow("test.example.com")

    def test_allows_case_insensitive_match(self, for_hostname):
        assert for_hostname.allow("TEST.example.com")

    def test_denies_hostname_mismatch(self, for_hostname):
        assert for_hostname.deny("testing.example.com")


class TestWildcardHostname:
    @pytest.fixture
    def for_wildcard_hostname(self):
        return ForWildcardHostname("*.test.example.com")

    def test_handles_wildcard_hostname(self):
        assert ForWildcardHostname.handles("*.test.example.com")

    def test_does_not_handle_non_string(self):
        assert not ForWildcardHostname.handles(None)

    def test_does_not_handle_malformed_hostname(self):
        assert not ForWildcardHostname.handles("domain-name")

    def test_creates_a_for_wildcard_hostname_policy_check(self, for_wildcard_hostname):
        assert isinstance(for_wildcard_hostname, ForWildcardHostname)

    def test_allows_wildcard_match(self, for_wildcard_hostname):
        assert for_wildcard_hostname.allow("api.test.example.com")

    def test_allows_wildcard_match(self, for_wildcard_hostname):
        assert for_wildcard_hostname.allow("x.test.example.com")

    def test_allows_explicit_splat_match(self, for_wildcard_hostname):
        assert for_wildcard_hostname.allow("*.test.example.com")

    def test_denies_non_string(self, for_wildcard_hostname):
        assert for_wildcard_hostname.deny(None)

    def test_denies_middle_wildcard_non_match(self, for_wildcard_hostname):
        assert for_wildcard_hostname.deny("api.*.test.example.com")

    def test_denies_after_wildcard_exact_match(self, for_wildcard_hostname):
        assert for_wildcard_hostname.deny("test.example.com")

    def test_denies_dot_replacment_not_wildcard_non_match(self, for_wildcard_hostname):
        assert for_wildcard_hostname.deny("api.testDexample.com")

    def test_denies_multilevel_wildcard_non_matches(self, for_wildcard_hostname):
        assert for_wildcard_hostname.deny("1.api.test.example.com")

    def test_denies_invalid_hostname_prefix(self, for_wildcard_hostname):
        assert for_wildcard_hostname.deny("-invalid.test.example.com")


class TestForIPAddress:
    @pytest.fixture
    def for_ipaddr(self):
        return ForIPAddress("192.168.1.1")

    @pytest.fixture
    def for_ipaddr_network(self):
        return ForIPAddress("192.168.1.0/24")

    def test_does_not_handle_non_parsable(self, for_ipaddr):
        assert not ForIPAddress.handles("not-an-ipaddr")

    def test_does_not_handle_non_string(self, for_ipaddr):
        assert not ForIPAddress.handles(None)

    def test_does_handle_ipaddress(self, for_ipaddr):
        assert ForIPAddress.handles("192.168.1.1")

    def test_does_handle_ipnetwork(self, for_ipaddr):
        assert ForIPAddress.handles("192.168.1.0/24")

    def test_creates_a_for_ipaddr_policy_check(self, for_ipaddr):
        assert isinstance(for_ipaddr, ForIPAddress)

    def test_allows_exact_ipaddr_match(self, for_ipaddr):
        assert for_ipaddr.allow("192.168.1.1")

    def test_denies_ipv4_out_of_range_value(self, for_ipaddr):
        assert for_ipaddr.deny("192.168.1.256")

    def test_creates_a_for_ipaddr_network_policy_check(self, for_ipaddr_network):
        assert isinstance(for_ipaddr_network, ForIPAddress)

    def test_allows_ipv4_in_range_value(self, for_ipaddr_network):
        assert for_ipaddr_network.allow("192.168.1.42")

    def test_denies_ipv4_out_of_range_for_network_value(self, for_ipaddr_network):
        assert for_ipaddr_network.deny("192.168.2.42")

    def test_creates_a_for_ipaddr_policy_check(self, for_ipaddr):
        assert isinstance(for_ipaddr, ForIPAddress)

    def test_allows_exact_ipaddr_match(self, for_ipaddr):
        assert for_ipaddr.allow("192.168.1.1")

    def test_denies_ipv4_out_of_range_value(self, for_ipaddr):
        assert for_ipaddr.deny("192.168.1.256")

    def test_creates_a_for_ipaddr_network_policy_check(self, for_ipaddr_network):
        assert isinstance(for_ipaddr_network, ForIPAddress)

    def test_allows_ipv4_in_range_value(self, for_ipaddr_network):
        assert for_ipaddr_network.allow("192.168.1.42")

    def test_denies_ipv4_out_of_range_for_network_value(self, for_ipaddr_network):
        assert for_ipaddr_network.deny("192.168.2.42")
