# -*- coding: utf-8 -*-

"""
Module providing an Anchor client API for adding PEM encoded certificates and
building CA bundles.
"""
import tempfile
import os


class PEMBundle:
    """
    A PEMBundle is a collection of PEM encoded CA certificates stored in both
    memory and a temporary file on disk.
    """

    def __init__(self):
        self._pems = []
        self._path = None

    def add_cert(self, pem):
        """Insert a PEM encoded CA certificate into the CA bundle."""

        self._pems.append(pem)
        self.remove_path()

    def remove_path(self):
        """Remove the CA bundle file."""

        if self._path and os.path.exists(self._path):
            os.remove(self._path)
            self._path = None

    def write_to_path(self):
        """Write the CA bundle contents to a temporary file, but do not deleted it."""
        self.remove_path()

        with tempfile.NamedTemporaryFile(
            prefix="ca-certs-", suffix=".pem", mode="w+t", delete=False
        ) as file:
            self._path = file.name
            for pem in self._pems:
                file.write(pem)

    def clear_certs(self):
        """Remove all PEM encoded CA certificates from the CA bundle."""

        self._pems.clear()
        self.remove_path()

    def pems(self):
        """Fetch a copy of the list of PEM encoded CA certificates."""

        return self._pems.copy()

    def path(self):
        """
        Fetch the file path of the CA bundle file containing all the added CA certs.
        This will write the ca_bundle to a file if it does not already exist.
        """

        if not self._path:
            self.write_to_path()

        return self._path


__ROOT_BUNDLE = PEMBundle()


def add_cert(pem):
    """Insert a PEM encoded CA certificate into the root CA bundle."""

    __ROOT_BUNDLE.add_cert(pem)


def ca_bundle_path():
    """Fetch the file path of the root CA bundle file containing all the added CA certs."""

    return __ROOT_BUNDLE.path()


def ca_pems():
    """Fetch a copy of the list of PEM encoded CA certificates."""

    return __ROOT_BUNDLE.pems()
