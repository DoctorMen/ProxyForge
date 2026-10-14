"""The proxy's own certificate authority.

To read HTTPS traffic the proxy pretends to be each site: it signs a fresh
certificate for the site's hostname with its own CA. Your browser accepts it
only because you installed that CA as trusted. Never install it on a machine
you don't control, and keep ca.key private.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_NAME = "proxyforge CA (local testing only)"


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


class CertAuthority:
    def __init__(self, directory: str | os.PathLike):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cert_path = self.dir / "ca.pem"
        self.key_path = self.dir / "ca.key"
        if self.cert_path.exists() and self.key_path.exists():
            self.cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
            self.key = serialization.load_pem_private_key(self.key_path.read_bytes(), None)
        else:
            self._create()
        # One key pair is shared by every site certificate; generating an RSA
        # key per host would add a noticeable pause to each new site.
        self.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._leaf_dir = self.dir / "certs"
        self._leaf_dir.mkdir(exist_ok=True)
        self._contexts: dict[str, ssl.SSLContext] = {}

    def _create(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
        now = dt.datetime.now(dt.timezone.utc)
        public = self.key.public_key()
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        _write_private(self.key_path, _key_pem(self.key))
        self.cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def sign_leaf(self, host: str) -> x509.Certificate:
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = dt.datetime.now(dt.timezone.utc)
        public = self.leaf_key.public_key()
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self.cert.subject)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            # Browsers reject site certificates valid for more than 398 days.
            .not_valid_after(now + dt.timedelta(days=397))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )

    def server_context(self, host: str) -> ssl.SSLContext:
        """A TLS server context presenting a certificate for host."""
        host = host.lower()
        ctx = self._contexts.get(host)
        if ctx is not None:
            return ctx
        cert = self.sign_leaf(host)
        name = hashlib.sha256(host.encode()).hexdigest()[:24]
        pem_path = self._leaf_dir / f"{name}.pem"
        _write_private(
            pem_path,
            cert.public_bytes(serialization.Encoding.PEM)
            + self.cert_pem
            + _key_pem(self.leaf_key),
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(pem_path)
        ctx.set_alpn_protocols(["http/1.1"])
        self._contexts[host] = ctx
        return ctx
