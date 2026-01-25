"""Tests for certificate operations."""

import tempfile
from pathlib import Path
from cryptography import x509

from cert_manager.certificates import CertificateManager


def test_generate_private_key():
    """Test private key generation."""
    key = CertificateManager.generate_private_key()
    assert key.key_size == 4096


def test_generate_private_key_custom_size():
    """Test private key generation with custom size."""
    key = CertificateManager.generate_private_key(key_size=2048)
    assert key.key_size == 2048


def test_create_ca_certificate_minimal():
    """Test CA certificate creation with minimal parameters."""
    cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")

    # Verify certificate properties
    assert cert is not None
    assert key is not None
    assert cert.subject.rfc4514_string() == "CN=Test CA"

    # Verify CA extensions
    basic_constraints = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.value.ca is True


def test_create_ca_certificate_full():
    """Test CA certificate creation with all parameters."""
    cert, key = CertificateManager.create_ca_certificate(
        common_name="Test CA", organization="Test Org", country="US", validity_days=365
    )

    # Verify subject fields
    assert "CN=Test CA" in cert.subject.rfc4514_string()
    assert "O=Test Org" in cert.subject.rfc4514_string()
    assert "C=US" in cert.subject.rfc4514_string()

    # Verify validity period
    validity = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert validity.days >= 364  # Account for time precision


def test_create_certificate_minimal():
    """Test certificate creation with minimal parameters."""
    # First create a CA
    ca_cert, ca_key = CertificateManager.create_ca_certificate(common_name="Test CA")

    # Create certificate
    cert, key = CertificateManager.create_certificate(
        common_name="server.local", ca_cert=ca_cert, ca_key=ca_key
    )

    assert cert is not None
    assert key is not None
    assert "CN=server.local" in cert.subject.rfc4514_string()

    # Verify it's not a CA
    basic_constraints = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.value.ca is False


def test_create_certificate_with_san():
    """Test certificate creation with SAN."""
    ca_cert, ca_key = CertificateManager.create_ca_certificate(common_name="Test CA")

    cert, key = CertificateManager.create_certificate(
        common_name="server.local",
        ca_cert=ca_cert,
        ca_key=ca_key,
        san_dns=["server.local", "server", "*.server.local"],
        san_ip=["192.168.1.100", "10.0.0.1"],
    )

    # Verify SAN extension
    san_ext = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )

    dns_names = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
    assert "server.local" in dns_names
    assert "server" in dns_names
    assert "*.server.local" in dns_names

    ip_addresses = [
        str(ip.value) for ip in san_ext.value if isinstance(ip, x509.IPAddress)
    ]
    assert "192.168.1.100" in ip_addresses
    assert "10.0.0.1" in ip_addresses


def test_save_and_load_certificate():
    """Test saving and loading certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "test.crt"

        # Create and save
        cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")
        CertificateManager.save_certificate(cert, cert_path)

        # Load and verify
        loaded_cert = CertificateManager.load_certificate(cert_path)
        assert loaded_cert.subject.rfc4514_string() == cert.subject.rfc4514_string()


def test_save_and_load_private_key():
    """Test saving and loading private keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "test.key"

        # Create and save
        cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")
        CertificateManager.save_private_key(key, key_path)

        # Load and verify
        loaded_key = CertificateManager.load_private_key(key_path)
        assert loaded_key.key_size == key.key_size


def test_certificate_chain():
    """Test that certificates are properly signed by CA."""
    ca_cert, ca_key = CertificateManager.create_ca_certificate(common_name="Test CA")

    cert, key = CertificateManager.create_certificate(
        common_name="server.local", ca_cert=ca_cert, ca_key=ca_key
    )

    # Verify issuer matches CA subject
    assert cert.issuer.rfc4514_string() == ca_cert.subject.rfc4514_string()


def test_certificate_validity_period():
    """Test custom validity periods."""
    ca_cert, ca_key = CertificateManager.create_ca_certificate(
        common_name="Test CA", validity_days=180
    )

    cert, key = CertificateManager.create_certificate(
        common_name="server.local", ca_cert=ca_cert, ca_key=ca_key, validity_days=90
    )

    ca_validity = ca_cert.not_valid_after_utc - ca_cert.not_valid_before_utc
    cert_validity = cert.not_valid_after_utc - cert.not_valid_before_utc

    assert ca_validity.days >= 179
    assert cert_validity.days >= 89
