"""Certificate generation and management operations."""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Tuple
import ipaddress


class CertificateManager:
    """Handles certificate generation, signing, and management operations."""

    DEFAULT_KEY_SIZE = 4096
    DEFAULT_VALIDITY_DAYS = 3650  # 10 years for CA
    DEFAULT_CERT_VALIDITY_DAYS = 825  # ~2 years for certificates

    @staticmethod
    def generate_private_key(key_size: int = DEFAULT_KEY_SIZE) -> rsa.RSAPrivateKey:
        """Generate an RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    @staticmethod
    def create_ca_certificate(
        common_name: str,
        organization: Optional[str] = None,
        country: Optional[str] = None,
        validity_days: int = DEFAULT_VALIDITY_DAYS,
        key_size: int = DEFAULT_KEY_SIZE,
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Create a self-signed CA certificate.

        Args:
            common_name: Common name for the CA
            organization: Organization name
            country: Two-letter country code
            validity_days: Number of days the certificate is valid
            key_size: RSA key size in bits

        Returns:
            Tuple of (certificate, private_key)
        """
        private_key = CertificateManager.generate_private_key(key_size)

        # Build subject name
        subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        if organization:
            subject_attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)
            )
        if country:
            subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

        subject = issuer = x509.Name(subject_attrs)

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        return cert, private_key

    @staticmethod
    def create_certificate(
        common_name: str,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        san_dns: Optional[List[str]] = None,
        san_ip: Optional[List[str]] = None,
        organization: Optional[str] = None,
        country: Optional[str] = None,
        validity_days: int = DEFAULT_CERT_VALIDITY_DAYS,
        key_size: int = DEFAULT_KEY_SIZE,
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Create and sign a certificate with the CA.

        Args:
            common_name: Common name for the certificate
            ca_cert: CA certificate for signing
            ca_key: CA private key for signing
            san_dns: List of DNS names for Subject Alternative Name
            san_ip: List of IP addresses for Subject Alternative Name
            organization: Organization name
            country: Two-letter country code
            validity_days: Number of days the certificate is valid
            key_size: RSA key size in bits

        Returns:
            Tuple of (certificate, private_key)
        """
        private_key = CertificateManager.generate_private_key(key_size)

        # Build subject name
        subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        if organization:
            subject_attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)
            )
        if country:
            subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

        subject = x509.Name(subject_attrs)

        # Build SAN extension
        san_list = []
        if san_dns:
            san_list.extend([x509.DNSName(name) for name in san_dns])
        if san_ip:
            san_list.extend([x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ip])

        # Always include the common name in SAN
        if common_name not in (san_dns or []):
            san_list.insert(0, x509.DNSName(common_name))

        # Build certificate
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
        )

        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        cert = builder.sign(ca_key, hashes.SHA256())

        return cert, private_key

    @staticmethod
    def save_certificate(cert: x509.Certificate, path: Path) -> None:
        """Save certificate to PEM file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def save_private_key(key: rsa.RSAPrivateKey, path: Path) -> None:
        """Save private key to PEM file without encryption."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    @staticmethod
    def load_certificate(path: Path) -> x509.Certificate:
        """Load certificate from PEM file."""
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    @staticmethod
    def load_private_key(path: Path) -> rsa.RSAPrivateKey:
        """Load private key from PEM file."""
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    @staticmethod
    def certificate_to_pem(cert: x509.Certificate) -> bytes:
        """Serialize certificate to PEM bytes."""
        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def private_key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
        """Serialize private key to PEM bytes."""
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def load_certificate_from_pem(pem_data: bytes) -> x509.Certificate:
        """Load certificate from PEM bytes."""
        return x509.load_pem_x509_certificate(pem_data)

    @staticmethod
    def load_private_key_from_pem(pem_data: bytes) -> rsa.RSAPrivateKey:
        """Load private key from PEM bytes."""
        return serialization.load_pem_private_key(pem_data, password=None)
