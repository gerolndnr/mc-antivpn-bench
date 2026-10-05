"""Throwaway certificate authority for the egress interposer.

The CA exists only inside one benchmark container. Its certificate is imported
into that container's JDK trust store so every product's HTTPS client trusts the
interposer equally; nothing on the host trusts it.
"""
import datetime
import ipaddress
import os
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _write_key(path, key):
    with open(path, 'wb') as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    os.chmod(path, 0o600)


class Authority:
    def __init__(self, directory):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.cert_path = os.path.join(directory, 'ca.pem')
        key_path = os.path.join(directory, 'ca.key')
        if os.path.exists(self.cert_path):
            with open(key_path, 'rb') as handle:
                self.key = serialization.load_pem_private_key(handle.read(), None)
            with open(self.cert_path, 'rb') as handle:
                self.cert = x509.load_pem_x509_certificate(handle.read())
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mc-antivpn-bench throwaway CA')])
            self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                         .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                         .not_valid_before(_now() - datetime.timedelta(days=1))
                         .not_valid_after(_now() + datetime.timedelta(days=30))
                         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                                      content_commitment=False, key_encipherment=False,
                                                      data_encipherment=False, key_agreement=False,
                                                      encipher_only=False, decipher_only=False), critical=True)
                         .sign(self.key, hashes.SHA256()))
            _write_key(key_path, self.key)
            with open(self.cert_path, 'wb') as handle:
                handle.write(self.cert.public_bytes(serialization.Encoding.PEM))
        self._contexts = {}
        self._lock = threading.Lock()

    def context_for(self, name):
        """Server-side TLS context presenting a leaf certificate for a host name or IP literal."""
        name = (name or 'unknown.invalid').lower().rstrip('.')
        with self._lock:
            if name in self._contexts:
                return self._contexts[name]
            key = ec.generate_private_key(ec.SECP256R1())
            try:
                alt = x509.IPAddress(ipaddress.ip_address(name))
            except ValueError:
                alt = x509.DNSName(name)
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])]))
                    .issuer_name(self.cert.subject).public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(_now() - datetime.timedelta(days=1))
                    .not_valid_after(_now() + datetime.timedelta(days=7))
                    .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
                    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .sign(self.key, hashes.SHA256()))
            safe = ''.join(c if c.isalnum() or c in '.-' else '_' for c in name)
            cert_path = os.path.join(self.directory, f'leaf-{safe}.pem')
            key_path = os.path.join(self.directory, f'leaf-{safe}.key')
            with open(cert_path, 'wb') as handle:
                handle.write(cert.public_bytes(serialization.Encoding.PEM))
                handle.write(self.cert.public_bytes(serialization.Encoding.PEM))
            _write_key(key_path, key)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(['h2', 'http/1.1'])
            context.load_cert_chain(cert_path, key_path)
            self._contexts[name] = context
            return context
