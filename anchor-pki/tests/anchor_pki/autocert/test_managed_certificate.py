import pytest
import pathlib
import json
import datetime
from anchor_pki.autocert.managed_certificate import ManagedCertificate


class TestManagedCertificate:
    @pytest.fixture
    def data_dir(self):
        return pathlib.Path(__file__).with_suffix("")

    @pytest.fixture
    def cert_data(self, data_dir):
        print(f"data_dir: {data_dir}")
        json_dir = pathlib.Path(data_dir)
        json_path = json_dir.joinpath("cert-data-1.json")
        json_data = None

        with json_path.open() as json_file:
            json_data = json_file.read()

        return json.loads(json_data)

    @pytest.fixture
    def managed_certificate(self, cert_data):
        cert_pem = cert_data["cert_pem"]
        key_pem = cert_data["key_pem"]
        return ManagedCertificate(None, cert_pem, key_pem)

    def test_serial(self, managed_certificate):
        assert type(managed_certificate.serial) == int
        assert managed_certificate.serial == 66097454161859316724930776650

    def test_not_before(self, managed_certificate):
        expected = datetime.datetime(
            2023, 9, 6, 22, 59, 3, tzinfo=datetime.timezone.utc
        )
        not_before = managed_certificate.not_before
        assert not_before.tzinfo is not None
        assert not_before.tzinfo.utcoffset(not_before) == datetime.timedelta(0)

        assert type(not_before) == datetime.datetime
        assert not_before == expected

    def test_not_after(self, managed_certificate):
        expected = datetime.datetime(
            2023, 10, 4, 22, 59, 2, tzinfo=datetime.timezone.utc
        )
        not_after = managed_certificate.not_after

        assert not_after.tzinfo is not None
        assert not_after.tzinfo.utcoffset(not_after) == datetime.timedelta(0)

        assert type(not_after) == datetime.datetime
        assert not_after == expected

    def test_common_name(self, managed_certificate):
        expected = "anchor-pki-py-testing.lcl.host"
        assert managed_certificate.common_name == expected

    def test_identifiers(self, managed_certificate):
        expected = ["anchor-pki-py-testing.lcl.host"]
        assert managed_certificate.identifiers == expected

    def test_all_names(self, managed_certificate):
        expected = ["anchor-pki-py-testing.lcl.host"]
        assert managed_certificate.all_names == expected
