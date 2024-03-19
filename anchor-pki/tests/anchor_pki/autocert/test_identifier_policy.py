import pytest
from anchor_pki.autocert.identifier_policy import IdentifierPolicy, PolicyCheckError
from anchor_pki.autocert.policy_check import (
    ForHostname,
    ForWildcardHostname,
    ForIPAddress,
)


class TestIdentifierPolicy:
    def test_builds_an_identifer_policy_checking_hostname(self):
        policy = IdentifierPolicy("test.example.com")
        assert isinstance(policy.policy, ForHostname)

    def test_builds_an_identifer_policy_checking_wildcard_hostname(self):
        policy = IdentifierPolicy("*.test.example.com")
        assert isinstance(policy.policy, ForWildcardHostname)

    def test_builds_an_identifer_policy_checking_ip_network(self):
        policy = IdentifierPolicy("192.168.1.0/24")
        assert isinstance(policy.policy, ForIPAddress)

    def test_builds_an_identifer_policy_checking_ip_address(self):
        policy = IdentifierPolicy("192.168.1.1")
        assert isinstance(policy.policy, ForIPAddress)

    def test_builds_a_list_of_policies(self):
        descriptions = ["test.example.com", "*.test.example.com", "192.168.1.1"]
        policies = IdentifierPolicy.build(descriptions)

        assert len(policies) == len(descriptions)
        assert isinstance(policies[0].policy, ForHostname)
        assert isinstance(policies[1].policy, ForWildcardHostname)
        assert isinstance(policies[2].policy, ForIPAddress)

    def test_builds_a_list_of_policies_from_one_description(self):
        policies = IdentifierPolicy.build("test.example.com")

        assert len(policies) == 1
        assert isinstance(policies[0].policy, ForHostname)

    def test_raises_policy_check_error_for_invalid_description(self):
        with pytest.raises(PolicyCheckError):
            IdentifierPolicy("not-a-valid-description")

    def test_allows_valid_hostname(self):
        policy = IdentifierPolicy("test.example.com")
        assert policy.allow("test.example.com")

    def test_allows_valid_wildcard_hostname(self):
        policy = IdentifierPolicy("*.test.example.com")
        assert policy.allow("x.test.example.com")

    def test_allows_explicit_splat_wildcard_hostname(self):
        policy = IdentifierPolicy("*.test.example.com")
        assert policy.allow("*.test.example.com")

    def test_deny_non_matching_wildcard_hostname(self):
        policy = IdentifierPolicy("*.test.example.com")
        assert policy.deny("x.test.example.net")

    def test_allows_matching_ip_for_network(self):
        policy = IdentifierPolicy("192.168.1.0/24")
        assert policy.allow("192.168.1.42")

    def test_deny_non_matching_ip_for_network(self):
        policy = IdentifierPolicy("192.168.1.0/24")
        assert policy.deny("192.168.2.42")
