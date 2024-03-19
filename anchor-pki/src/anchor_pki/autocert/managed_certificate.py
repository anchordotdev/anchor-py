"""
Managed certificate class
"""

import datetime

from cryptography import x509


class ManagedCertificate:
    """A managed certificate"""

    def __init__(self, persist_dir, cert_pem, key_pem):
        self.persist_dir = persist_dir
        self.cert_pem = str.encode(cert_pem)
        self.key_pem = str.encode(key_pem)
        self.cert_chain = x509.load_pem_x509_certificates(self.cert_pem)
        self.persist_pems()

    @property
    def cert(self):
        """Return the primary certificate"""
        return self.cert_chain[0]

    @property
    def serial(self):
        """Return the certificate serial number"""
        return self.cert.serial_number

    @property
    def not_before(self):
        """Return the certificate not_before date"""
        return self.cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

    @property
    def not_after(self):
        """Return the certificate not_after date"""
        return self.cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    @property
    def common_name(self):
        """Return the certificate common name"""
        attributes = self.cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attributes[0].value

    @property
    def identifiers(self):
        """Return the certificate identifiers"""
        ext = self.cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        return sorted(ext.value.get_values_for_type(x509.DNSName))

    @property
    def all_names(self):
        """Return all unique names with the common name at the front"""
        non_common_identifiers = [i for i in self.identifiers if i != self.common_name]
        all_names = [self.common_name, *sorted(non_common_identifiers)]
        return all_names

    def persist_pems(self):
        """Persist the certificate and key to disk"""
        if self.persist_dir is None:
            return

        self.certificate_path = self.persist_dir / f"{self.serial}.crt"
        with open(self.certificate_path, "wb") as cert_file:
            cert_file.write(self.cert_pem)

        self.private_key_path = self.persist_dir / f"{self.serial}.key"
        with open(self.private_key_path, "wb") as key_file:
            key_file.write(self.key_pem)
