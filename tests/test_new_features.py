"""Tests for new security features: PEM serialization and CA export."""

import tempfile
import pytest
from pathlib import Path
from datetime import datetime, timedelta

from cert_manager.certificates import CertificateManager
from cert_manager.storage import CertificateStorage


def test_certificate_to_pem():
    """Test converting certificate to PEM bytes."""
    cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")

    # Convert to PEM
    pem_data = CertificateManager.certificate_to_pem(cert)

    # Verify it's bytes and contains PEM markers
    assert isinstance(pem_data, bytes)
    assert b"-----BEGIN CERTIFICATE-----" in pem_data
    assert b"-----END CERTIFICATE-----" in pem_data


def test_private_key_to_pem():
    """Test converting private key to PEM bytes."""
    key = CertificateManager.generate_private_key()

    # Convert to PEM
    pem_data = CertificateManager.private_key_to_pem(key)

    # Verify it's bytes and contains PEM markers
    assert isinstance(pem_data, bytes)
    assert b"-----BEGIN RSA PRIVATE KEY-----" in pem_data
    assert b"-----END RSA PRIVATE KEY-----" in pem_data


def test_load_certificate_from_pem():
    """Test loading certificate from PEM bytes."""
    # Create original certificate
    cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")

    # Convert to PEM and back
    pem_data = CertificateManager.certificate_to_pem(cert)
    loaded_cert = CertificateManager.load_certificate_from_pem(pem_data)

    # Verify they're the same
    assert loaded_cert.subject.rfc4514_string() == cert.subject.rfc4514_string()
    assert loaded_cert.serial_number == cert.serial_number


def test_load_private_key_from_pem():
    """Test loading private key from PEM bytes."""
    # Create original key
    key = CertificateManager.generate_private_key(key_size=2048)

    # Convert to PEM and back
    pem_data = CertificateManager.private_key_to_pem(key)
    loaded_key = CertificateManager.load_private_key_from_pem(pem_data)

    # Verify key size matches
    assert loaded_key.key_size == key.key_size


def test_pem_roundtrip_with_signing():
    """Test that PEM serialization works with certificate signing."""
    # Create CA
    ca_cert, ca_key = CertificateManager.create_ca_certificate(common_name="Test CA")

    # Convert to PEM and back
    ca_cert_pem = CertificateManager.certificate_to_pem(ca_cert)
    ca_key_pem = CertificateManager.private_key_to_pem(ca_key)

    loaded_ca_cert = CertificateManager.load_certificate_from_pem(ca_cert_pem)
    loaded_ca_key = CertificateManager.load_private_key_from_pem(ca_key_pem)

    # Create a certificate with the loaded CA
    cert, key = CertificateManager.create_certificate(
        common_name="server.local", ca_cert=loaded_ca_cert, ca_key=loaded_ca_key
    )

    # Verify the certificate was signed correctly
    assert cert.issuer.rfc4514_string() == loaded_ca_cert.subject.rfc4514_string()


def test_export_ca():
    """Test exporting CA certificate and key to files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        # Create storage and add CA
        storage = CertificateStorage(db_path, "test_password")

        cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")
        cert_data = CertificateManager.certificate_to_pem(cert)
        key_data = CertificateManager.private_key_to_pem(key)

        valid_until = datetime.now() + timedelta(days=3650)
        storage.add_ca(
            name="test_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test CA",
        )

        # Export CA
        export_cert_path = tmppath / "exported_ca.crt"
        export_key_path = tmppath / "exported_ca.key"

        result = storage.export_ca("test_ca", export_cert_path, export_key_path)

        # Verify export succeeded
        assert result is True
        assert export_cert_path.exists()
        assert export_key_path.exists()

        # Verify exported files contain correct data
        with open(export_cert_path, "rb") as f:
            exported_cert_data = f.read()
        with open(export_key_path, "rb") as f:
            exported_key_data = f.read()

        assert exported_cert_data == cert_data
        assert exported_key_data == key_data

        # Verify we can load the exported files
        loaded_cert = CertificateManager.load_certificate(export_cert_path)
        loaded_key = CertificateManager.load_private_key(export_key_path)

        assert loaded_cert.subject.rfc4514_string() == cert.subject.rfc4514_string()
        assert loaded_key.key_size == key.key_size


def test_export_ca_nonexistent():
    """Test exporting a CA that doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        export_cert_path = tmppath / "exported_ca.crt"
        export_key_path = tmppath / "exported_ca.key"

        result = storage.export_ca("nonexistent", export_cert_path, export_key_path)

        # Should return False for nonexistent CA
        assert result is False
        assert not export_cert_path.exists()
        assert not export_key_path.exists()


def test_export_ca_creates_directories():
    """Test that export_ca creates parent directories if needed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        # Create storage and add CA
        storage = CertificateStorage(db_path, "test_password")

        cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")
        cert_data = CertificateManager.certificate_to_pem(cert)
        key_data = CertificateManager.private_key_to_pem(key)

        valid_until = datetime.now() + timedelta(days=3650)
        storage.add_ca(
            name="test_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test CA",
        )

        # Export to nested directory that doesn't exist
        export_cert_path = tmppath / "nested" / "dir" / "ca.crt"
        export_key_path = tmppath / "nested" / "dir" / "ca.key"

        result = storage.export_ca("test_ca", export_cert_path, export_key_path)

        # Verify export succeeded and directories were created
        assert result is True
        assert export_cert_path.exists()
        assert export_key_path.exists()


def test_ca_storage_with_cert_data():
    """Test that CA storage with cert_data maintains data integrity."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        # Create CA
        cert, key = CertificateManager.create_ca_certificate(
            common_name="Test CA", organization="Test Org", country="US"
        )

        cert_data = CertificateManager.certificate_to_pem(cert)
        key_data = CertificateManager.private_key_to_pem(key)

        valid_until = datetime.now() + timedelta(days=3650)

        # Store in database
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

        # Retrieve and verify
        ca_record = storage.get_ca("test_ca")
        assert ca_record is not None
        assert ca_record["cert_data"] == cert_data
        assert ca_record["key_data"] == key_data
        assert ca_record["common_name"] == "Test CA"
        assert ca_record["organization"] == "Test Org"
        assert ca_record["country"] == "US"

        # Verify we can use the stored data to load certificates
        loaded_cert = CertificateManager.load_certificate_from_pem(
            ca_record["cert_data"]
        )
        loaded_key = CertificateManager.load_private_key_from_pem(ca_record["key_data"])

        # Verify loaded certificates match original
        assert loaded_cert.subject.rfc4514_string() == cert.subject.rfc4514_string()
        assert loaded_key.key_size == key.key_size

        # Verify we can use loaded CA to sign certificates
        server_cert, server_key = CertificateManager.create_certificate(
            common_name="server.local", ca_cert=loaded_cert, ca_key=loaded_key
        )

        assert (
            server_cert.issuer.rfc4514_string() == loaded_cert.subject.rfc4514_string()
        )


def test_forget_ca_without_dependent_certs():
    """Test forgetting a CA that has no dependent certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        # Create and store CA
        cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")
        cert_data = CertificateManager.certificate_to_pem(cert)
        key_data = CertificateManager.private_key_to_pem(key)

        valid_until = datetime.now() + timedelta(days=3650)
        storage.add_ca(
            name="test_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test CA",
        )

        # Verify CA exists
        ca = storage.get_ca("test_ca")
        assert ca is not None

        # Delete CA
        result = storage.delete_ca("test_ca")
        assert result is True

        # Verify CA is gone
        ca = storage.get_ca("test_ca")
        assert ca is None


def test_forget_ca_with_dependent_certs():
    """Test that forgetting a CA with dependent certificates fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        # Create and store CA
        cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")
        cert_data = CertificateManager.certificate_to_pem(cert)
        key_data = CertificateManager.private_key_to_pem(key)

        valid_until = datetime.now() + timedelta(days=3650)
        ca_id = storage.add_ca(
            name="test_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test CA",
        )

        # Add a certificate signed by this CA
        cert_valid_until = datetime.now() + timedelta(days=825)
        storage.add_certificate(
            name="server_cert",
            common_name="server.local",
            cert_path=Path("/path/to/server.crt"),
            key_path=Path("/path/to/server.key"),
            ca_id=ca_id,
            valid_until=cert_valid_until,
        )

        # Attempt to delete CA should fail
        with pytest.raises(ValueError, match="Cannot delete CA"):
            storage.delete_ca("test_ca")

        # Verify CA still exists
        ca = storage.get_ca("test_ca")
        assert ca is not None


def test_forget_ca_then_delete_dependent_certs():
    """Test forgetting CA after deleting dependent certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        # Create and store CA
        cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")
        cert_data = CertificateManager.certificate_to_pem(cert)
        key_data = CertificateManager.private_key_to_pem(key)

        valid_until = datetime.now() + timedelta(days=3650)
        ca_id = storage.add_ca(
            name="test_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test CA",
        )

        # Add a certificate
        cert_valid_until = datetime.now() + timedelta(days=825)
        storage.add_certificate(
            name="server_cert",
            common_name="server.local",
            cert_path=Path("/path/to/server.crt"),
            key_path=Path("/path/to/server.key"),
            ca_id=ca_id,
            valid_until=cert_valid_until,
        )

        # Delete the certificate first
        storage.delete_certificate("server_cert")

        # Now deleting CA should succeed
        result = storage.delete_ca("test_ca")
        assert result is True

        # Verify CA is gone
        ca = storage.get_ca("test_ca")
        assert ca is None


def test_forget_ca_nonexistent():
    """Test forgetting a CA that doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        # Attempt to delete nonexistent CA
        result = storage.delete_ca("nonexistent_ca")
        assert result is False


def test_forget_multiple_cas():
    """Test forgetting multiple CAs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        # Create multiple CAs
        for i in range(3):
            cert, key = CertificateManager.create_ca_certificate(
                common_name=f"Test CA {i}"
            )
            cert_data = CertificateManager.certificate_to_pem(cert)
            key_data = CertificateManager.private_key_to_pem(key)

            valid_until = datetime.now() + timedelta(days=3650)
            storage.add_ca(
                name=f"test_ca_{i}",
                cert_data=cert_data,
                key_data=key_data,
                valid_until=valid_until,
                common_name=f"Test CA {i}",
            )

        # Verify all exist
        cas = storage.list_cas()
        assert len(cas) == 3

        # Delete each one
        for i in range(3):
            result = storage.delete_ca(f"test_ca_{i}")
            assert result is True

        # Verify all are gone
        cas = storage.list_cas()
        assert len(cas) == 0


def test_ca_deletion_integrity():
    """Test that CA deletion maintains database integrity."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        # Create two CAs with certificates
        ca_ids = []
        for i in range(2):
            cert, key = CertificateManager.create_ca_certificate(
                common_name=f"Test CA {i}"
            )
            cert_data = CertificateManager.certificate_to_pem(cert)
            key_data = CertificateManager.private_key_to_pem(key)

            valid_until = datetime.now() + timedelta(days=3650)
            ca_id = storage.add_ca(
                name=f"test_ca_{i}",
                cert_data=cert_data,
                key_data=key_data,
                valid_until=valid_until,
                common_name=f"Test CA {i}",
            )
            ca_ids.append(ca_id)

            # Add certificate for each CA
            cert_valid_until = datetime.now() + timedelta(days=825)
            storage.add_certificate(
                name=f"server_cert_{i}",
                common_name=f"server{i}.local",
                cert_path=Path(f"/path/to/server{i}.crt"),
                key_path=Path(f"/path/to/server{i}.key"),
                ca_id=ca_id,
                valid_until=cert_valid_until,
            )

        # Delete first CA's certificate, then CA
        storage.delete_certificate("server_cert_0")
        result = storage.delete_ca("test_ca_0")
        assert result is True

        # Verify first CA is gone but second CA and its cert remain
        ca0 = storage.get_ca("test_ca_0")
        assert ca0 is None

        ca1 = storage.get_ca("test_ca_1")
        assert ca1 is not None

        cert1 = storage.get_certificate("server_cert_1")
        assert cert1 is not None

        # Verify lists are correct
        cas = storage.list_cas()
        assert len(cas) == 1
        assert cas[0]["name"] == "test_ca_1"

        certs = storage.list_certificates()
        assert len(certs) == 1
        assert certs[0]["name"] == "server_cert_1"


def test_export_ca_client_package_from_storage():
    """Test exporting CA as client package from storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        # Create storage and add CA
        storage = CertificateStorage(db_path, "test_password")

        cert, key = CertificateManager.create_ca_certificate(
            common_name="Test Internal CA", organization="Test Org", country="US"
        )
        cert_data = CertificateManager.certificate_to_pem(cert)
        key_data = CertificateManager.private_key_to_pem(key)

        valid_until = datetime.now() + timedelta(days=3650)
        storage.add_ca(
            name="test_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test Internal CA",
            organization="Test Org",
            country="US",
        )

        # Get CA record (simulating what CLI does)
        ca_record = storage.get_ca("test_ca")
        assert ca_record is not None

        # Test that we can create client package from database-stored CA
        output_dir = tmppath / "output"
        ca_cert_path = ca_record.get("cert_path")

        # Verify cert_path is None (stored in database)
        assert ca_cert_path is None

        # Create temp file from cert_data (simulating CLI behavior)
        import tempfile as tmp

        temp_ca_file = tmp.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False)
        temp_ca_file.write(ca_record["cert_data"])
        temp_ca_file.close()

        try:
            from cert_manager.utils import create_client_package
            from cert_manager.cli import sanitize_name

            zip_path = create_client_package(
                ca_cert_path=Path(temp_ca_file.name),
                output_dir=output_dir,
                ca_name=sanitize_name(ca_record["name"]),
                ca_common_name=ca_record["common_name"],
                ca_created_at=ca_record["created_at"],
                ca_valid_until=ca_record["valid_until"],
            )

            # Verify package was created
            assert zip_path.exists()
            assert zip_path.name == "test_ca_client.zip"

            # Verify package contents
            import zipfile

            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                # Should contain CA cert but NOT private key
                assert "test_ca_CA.crt" in names
                assert "README.txt" in names
                assert len(names) == 2  # Only cert and README

                # Verify CA cert can be read
                ca_cert_content = zf.read("test_ca_CA.crt")
                assert b"-----BEGIN CERTIFICATE-----" in ca_cert_content
                assert b"-----END CERTIFICATE-----" in ca_cert_content

                # Verify README content
                readme = zf.read("README.txt").decode("utf-8")
                assert "Test Internal CA" in readme
                assert "Client Certificate Installation" in readme
                assert "Windows" in readme
                assert "macOS" in readme
                assert "Linux" in readme

        finally:
            # Clean up temp file
            import os

            try:
                os.unlink(temp_ca_file.name)
            except Exception:
                pass


def test_export_ca_client_package_no_private_key():
    """Test that client package does NOT contain private key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        # Create storage and add CA
        storage = CertificateStorage(db_path, "test_password")

        cert, key = CertificateManager.create_ca_certificate(common_name="Test CA")
        cert_data = CertificateManager.certificate_to_pem(cert)
        key_data = CertificateManager.private_key_to_pem(key)

        valid_until = datetime.now() + timedelta(days=3650)
        storage.add_ca(
            name="secure_ca",
            cert_data=cert_data,
            key_data=key_data,
            valid_until=valid_until,
            common_name="Test CA",
        )

        # Get CA and create client package
        ca_record = storage.get_ca("secure_ca")
        output_dir = tmppath / "output"

        # Create temp file
        import tempfile as tmp

        temp_ca_file = tmp.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False)
        temp_ca_file.write(ca_record["cert_data"])
        temp_ca_file.close()

        try:
            from cert_manager.utils import create_client_package
            from cert_manager.cli import sanitize_name

            zip_path = create_client_package(
                ca_cert_path=Path(temp_ca_file.name),
                output_dir=output_dir,
                ca_name=sanitize_name(ca_record["name"]),
                ca_common_name=ca_record["common_name"],
                ca_created_at=ca_record["created_at"],
                ca_valid_until=ca_record["valid_until"],
            )

            # Verify no private key in package
            import zipfile

            with zipfile.ZipFile(zip_path, "r") as zf:
                for name in zf.namelist():
                    # Should not have any .key files
                    assert not name.endswith(".key")
                    # Read all files to ensure no private key content
                    content = zf.read(name)
                    assert b"-----BEGIN RSA PRIVATE KEY-----" not in content
                    assert (
                        b"PRIVATE KEY" not in content
                        or b"private key" in content.lower()
                    )

        finally:
            import os

            try:
                os.unlink(temp_ca_file.name)
            except Exception:
                pass


def test_export_ca_client_package_multiple_cas():
    """Test exporting client packages for multiple CAs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        db_path = tmppath / "test.db"

        storage = CertificateStorage(db_path, "test_password")

        # Create multiple CAs
        output_dir = tmppath / "output"
        created_packages = []

        for i in range(3):
            cert, key = CertificateManager.create_ca_certificate(
                common_name=f"Test CA {i}"
            )
            cert_data = CertificateManager.certificate_to_pem(cert)
            key_data = CertificateManager.private_key_to_pem(key)

            valid_until = datetime.now() + timedelta(days=3650)
            storage.add_ca(
                name=f"test_ca_{i}",
                cert_data=cert_data,
                key_data=key_data,
                valid_until=valid_until,
                common_name=f"Test CA {i}",
            )

            # Export client package for each
            ca_record = storage.get_ca(f"test_ca_{i}")
            import tempfile as tmp

            temp_ca_file = tmp.NamedTemporaryFile(
                mode="wb", suffix=".pem", delete=False
            )
            temp_ca_file.write(ca_record["cert_data"])
            temp_ca_file.close()

            try:
                from cert_manager.utils import create_client_package
                from cert_manager.cli import sanitize_name

                zip_path = create_client_package(
                    ca_cert_path=Path(temp_ca_file.name),
                    output_dir=output_dir,
                    ca_name=sanitize_name(ca_record["name"]),
                    ca_common_name=ca_record["common_name"],
                    ca_created_at=ca_record["created_at"],
                    ca_valid_until=ca_record["valid_until"],
                )
                created_packages.append(zip_path)
            finally:
                import os

                try:
                    os.unlink(temp_ca_file.name)
                except Exception:
                    pass

        # Verify all packages exist and are unique
        assert len(created_packages) == 3
        assert len(set(created_packages)) == 3  # All unique
        for pkg in created_packages:
            assert pkg.exists()
            assert pkg.name.endswith("_client.zip")
