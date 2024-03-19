"""Module to encapulate the auto-renewal of SSL certificates."""

import ssl
from .manager import Manager


class SniCallback:  # pylint: disable=too-few-public-methods
    """SniCallback class"""

    def __init__(self, configuration):
        self.configuration = configuration
        self.manager = Manager(configuration)
        self.sni_callback = self._create_sni_callback()

    def _create_sni_callback(self):
        """
        creat the callback to set the SSL context for the given server name.
        This is used to support the gunicorn sni_callback configuration variable
        """

        def sni_callback(
            ssl_socket, server_name, ssl_context
        ):  # pylint: disable=unused-argument
            if server_name is None:
                return None

            managed_certificate = self.manager.managed_certificate(server_name)

            # need to write to files so that the ssl context can load the files
            cert_filename = managed_certificate.certificate_path
            key_filename = managed_certificate.private_key_path

            new_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            new_context.load_cert_chain(cert_filename, key_filename)

            ssl_socket.context = new_context

            return None

        return sni_callback
