"""
Manages the ACME client and the certificates it generates.
"""

import ssl

from anchor_pki.autocert import configuration, manager, terms_of_service


class Manager:
    """
    Manages the ACME client and the certificates it generates.
    """

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        cache_dir="tmp/acme",
        contact=None,
        directory_url=None,
        eab_hmac_key=None,
        eab_kid=None,
        renew_in=None,
        server_names=None,
        tos_agreed=None,
    ):
        eab = {
            "kid": eab_kid,
            "hmac_key": eab_hmac_key,
        }

        renew_before_seconds = None
        if renew_in is not None:
            renew_before_seconds = renew_in.total_seconds()

        cfg = configuration.Configuration(
            name="acme",
            allow_identifiers=server_names,
            cache_dir=cache_dir,
            contact=contact,
            directory_url=directory_url,
            external_account_binding=eab,
            renew_before_seconds=renew_before_seconds,
            tos_acceptors=TosAcceptor(tos_agreed),
            work_dir=cache_dir,
        )

        self.mgr = manager.Manager(cfg)
        self.server_names = server_names

    def ssl_context(self):
        """
        return an SSLContext with an SNI callback configured to provision certs
        & keys via this Manager.
        """

        def ssl_context(_config, _default_ssl_context_factory):
            def sni_callback(ssl_socket, server_name, _ssl_context):
                if server_name is None:
                    return None

                cert = self.get_cert([server_name])
                if cert is None:
                    return None

                ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(cert.certificate_path, cert.private_key_path)

                ssl_socket.context = ctx

                return None

            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.sni_callback = sni_callback

            return ctx

        return ssl_context

    def get_cert(self, server_names):
        """return a managed certificate"""
        return self.mgr.managed_certificate(server_names[0], identifiers=server_names)

    def certfile(self):
        """return the path to a certificate file"""
        cert = self.get_cert(self.server_names)
        return str(cert.certificate_path)

    def keyfile(self):
        """return the path to a private key file"""
        cert = self.get_cert(self.server_names)
        return str(cert.private_key_path)


# pylint: disable=too-few-public-methods
class TosAcceptor(terms_of_service.Acceptor):
    """Simple terms-of-service acceptor based on a boolean value or TOS URL"""

    def __init__(self, tos_agreed):
        self.tos_agreed = tos_agreed

    def accept(self, tos_uri):
        if self.tos_agreed is True:
            return True

        if self.tos_agreed == tos_uri:
            return True

        return False
