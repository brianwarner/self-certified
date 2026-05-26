"""Tests for encrypted storage."""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

from cert_manager.storage import CertificateStorage


@pytest.fixture
def storage():
    """Create a temporary storage instance."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        storage = CertificateStorage(db_path, "test_password")
        yield storage


def test_storage_initialization(storage):
    """Test storage initialization creates tables."""
    # If initialization succeeded, we should be able to list CAs
    cas = storage.list_cas()
    assert isinstance(cas, list)
    assert len(cas) == 0


def test_add_and_get_ca(storage):
    """Test adding and retrieving a CA."""
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = (
        b"-----BEGIN CERTIFICATE-----\ntest_cert_data\n-----END CERTIFICATE-----"
    )
    key_data = (
        b"-----BEGIN RSA PRIVATE KEY-----\ntest_key_data\n-----END RSA PRIVATE KEY-----"
    )

    ca_id = storage.add_ca(
        name="test_ca",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="Test CA",
        organization="Test Org",
        country="US",
    )

    assert ca_id > 0

    ca = storage.get_ca("test_ca")
    assert ca is not None
    assert ca["name"] == "test_ca"
    assert ca["common_name"] == "Test CA"
    assert ca["organization"] == "Test Org"
    assert ca["country"] == "US"
    assert ca["cert_data"] == cert_data
    assert ca["key_data"] == key_data


def test_add_duplicate_ca(storage):
    """Test that duplicate CA names are rejected."""
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key_data = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    storage.add_ca(
        name="test_ca",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="Test CA",
    )

    # Attempting to add duplicate should raise error
    with pytest.raises(Exception):
        storage.add_ca(
            name="test_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test CA 2",
        )


def test_list_cas(storage):
    """Test listing all CAs."""
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key_data = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    storage.add_ca(
        name="ca1",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="CA 1",
    )

    storage.add_ca(
        name="ca2",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="CA 2",
    )

    cas = storage.list_cas()
    assert len(cas) == 2
    names = [ca["name"] for ca in cas]
    assert "ca1" in names
    assert "ca2" in names


def test_add_and_get_certificate(storage):
    """Test adding and retrieving a certificate."""
    # First add a CA
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key_data = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    ca_id = storage.add_ca(
        name="test_ca",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="Test CA",
    )

    # Add certificate
    cert_valid_until = datetime.now() + timedelta(days=825)
    cert_id = storage.add_certificate(
        name="server_cert",
        common_name="server.local",
        cert_path=Path("/path/to/server.crt"),
        key_path=Path("/path/to/server.key"),
        ca_id=ca_id,
        valid_until=cert_valid_until,
        san_dns=["server.local", "server"],
        san_ip=["192.168.1.100"],
        organization="Test Org",
        country="US",
    )

    assert cert_id > 0

    cert = storage.get_certificate("server_cert")
    assert cert is not None
    assert cert["name"] == "server_cert"
    assert cert["common_name"] == "server.local"
    assert cert["ca_id"] == ca_id
    assert cert["san_dns"] == ["server.local", "server"]
    assert cert["san_ip"] == ["192.168.1.100"]


def test_certificate_without_san(storage):
    """Test adding certificate without SAN."""
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key_data = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    ca_id = storage.add_ca(
        name="test_ca",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="Test CA",
    )

    cert_valid_until = datetime.now() + timedelta(days=825)
    storage.add_certificate(
        name="server_cert",
        common_name="server.local",
        cert_path=Path("/path/to/server.crt"),
        key_path=Path("/path/to/server.key"),
        ca_id=ca_id,
        valid_until=cert_valid_until,
    )

    cert = storage.get_certificate("server_cert")
    assert cert["san_dns"] == []
    assert cert["san_ip"] == []


def test_list_certificates(storage):
    """Test listing all certificates."""
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key_data = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    ca_id = storage.add_ca(
        name="test_ca",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="Test CA",
    )

    cert_valid_until = datetime.now() + timedelta(days=825)

    storage.add_certificate(
        name="cert1",
        common_name="server1.local",
        cert_path=Path("/path/to/server1.crt"),
        key_path=Path("/path/to/server1.key"),
        ca_id=ca_id,
        valid_until=cert_valid_until,
    )

    storage.add_certificate(
        name="cert2",
        common_name="server2.local",
        cert_path=Path("/path/to/server2.crt"),
        key_path=Path("/path/to/server2.key"),
        ca_id=ca_id,
        valid_until=cert_valid_until,
    )

    certs = storage.list_certificates()
    assert len(certs) == 2
    names = [cert["name"] for cert in certs]
    assert "cert1" in names
    assert "cert2" in names


def test_delete_certificate(storage):
    """Test deleting a certificate."""
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key_data = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    ca_id = storage.add_ca(
        name="test_ca",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="Test CA",
    )

    cert_valid_until = datetime.now() + timedelta(days=825)
    storage.add_certificate(
        name="server_cert",
        common_name="server.local",
        cert_path=Path("/path/to/server.crt"),
        key_path=Path("/path/to/server.key"),
        ca_id=ca_id,
        valid_until=cert_valid_until,
    )

    # Delete certificate
    result = storage.delete_certificate("server_cert")
    assert result is True

    # Verify it's gone
    cert = storage.get_certificate("server_cert")
    assert cert is None


def test_delete_nonexistent_certificate(storage):
    """Test deleting a certificate that doesn't exist."""
    result = storage.delete_certificate("nonexistent")
    assert result is False


def test_delete_ca_with_certificates(storage):
    """Test that CA with dependent certificates cannot be deleted."""
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key_data = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    ca_id = storage.add_ca(
        name="test_ca",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="Test CA",
    )

    cert_valid_until = datetime.now() + timedelta(days=825)
    storage.add_certificate(
        name="server_cert",
        common_name="server.local",
        cert_path=Path("/path/to/server.crt"),
        key_path=Path("/path/to/server.key"),
        ca_id=ca_id,
        valid_until=cert_valid_until,
    )

    # Attempt to delete CA should raise error
    with pytest.raises(ValueError, match="Cannot delete CA"):
        storage.delete_ca("test_ca")


def test_delete_ca_without_certificates(storage):
    """Test deleting a CA with no dependent certificates."""
    valid_until = datetime.now() + timedelta(days=3650)
    cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key_data = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    storage.add_ca(
        name="test_ca",
        cert_data=cert_data,
        key_data=key_data,
        valid_until=valid_until,
        common_name="Test CA",
    )

    result = storage.delete_ca("test_ca")
    assert result is True

    ca = storage.get_ca("test_ca")
    assert ca is None


def test_encrypted_database():
    """Test that database encryption works."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "encrypted.db"
        cert_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        key_data = (
            b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        )

        # Create storage with password
        storage1 = CertificateStorage(db_path, "secret_password")
        valid_until = datetime.now() + timedelta(days=3650)
        storage1.add_ca(
            name="test_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test CA",
        )

        # Try to open with different password - should fail at initialization
        with pytest.raises(ValueError, match="Incorrect password"):
            CertificateStorage(db_path, "wrong_password")

        # Open with correct password - should work
        storage3 = CertificateStorage(db_path, "secret_password")
        cas = storage3.list_cas()
        assert len(cas) == 1
