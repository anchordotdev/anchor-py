import pytest
from anchor_pki.autocert.terms_of_service import Acceptor, AnyAcceptor, RegexAcceptor


class TestAcceptor:
    @pytest.fixture
    def base_acceptor(self):
        return Acceptor()

    @pytest.fixture
    def any_acceptor(self):
        return AnyAcceptor()

    @pytest.fixture
    def regex_acceptor(self):
        return RegexAcceptor(r"^https://example.com/tos")

    def test_base_class_raises_exception(self, base_acceptor):
        with pytest.raises(NotImplementedError):
            base_acceptor.accept("https://example.com/tos")

    def test_any_acceptor_accepts_all(self, any_acceptor):
        assert any_acceptor.accept("https://example.com/tos")

    def test_any_acceptor_accepts_none(self, any_acceptor):
        assert any_acceptor.accept(None)

    def test_regex_acceptor_accepts_matching(self, regex_acceptor):
        assert regex_acceptor.accept("https://example.com/tos")

    def test_regex_acceptor_rejects_non_matching(self, regex_acceptor):
        assert not regex_acceptor.accept("foo")
