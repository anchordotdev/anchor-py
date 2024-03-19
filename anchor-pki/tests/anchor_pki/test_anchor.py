import pytest
import os

from anchor_pki import anchor


class TestRootBundle:
    def test_anchor_root_bundle_is_not(self):
        with pytest.raises(AttributeError):
            anchor.__ROOT_BUNDLE

    def test_add_cert_adds_pem_to_bundle(self):
        pem = "pem"
        anchor.add_cert(pem)
        assert pem in anchor.ca_pems()

    def test_fetching_pems_returns_copy(self):
        pem = "pem"
        anchor.add_cert(pem)

        pem2 = "pem2"
        pems = anchor.ca_pems()
        pems.append(pem2)

        assert pem in anchor.ca_pems()
        assert pem2 not in anchor.ca_pems()


class TestPEMBundle:
    def test_anchor_root_bundle_is_not(self):
        with pytest.raises(AttributeError):
            anchor.__ROOT_BUNDLE

    @pytest.fixture
    def bundle(self):
        return anchor.PEMBundle()

    def test_add_cert_adds_pem_to_bundle(self, bundle):
        pem = "pem"
        bundle.add_cert(pem)
        assert pem in bundle.pems()

    def test_fetching_pems_returns_copy(self, bundle):
        pem = "pem"
        bundle.add_cert(pem)

        pem2 = "pem2"
        pems = bundle.pems()
        pems.append(pem2)

        assert pem in bundle.pems()
        assert pem2 not in bundle.pems()
