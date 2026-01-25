"""Tests for utility functions."""

import pytest
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime

from cert_manager.utils import (
    create_server_package,
    create_client_package,
    create_combined_package,
)
from cert_manager.certificates import CertificateManager


@pytest.fixture
def test_certificates():
    """Create test certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Create CA
        ca_cert, ca_key = CertificateManager.create_ca_certificate(
            common_name="Test CA"
        )
        ca_cert_path = tmppath / "ca.crt"
        ca_key_path = tmppath / "ca.key"
        CertificateManager.save_certificate(ca_cert, ca_cert_path)
        CertificateManager.save_private_key(ca_key, ca_key_path)

        # Create server certificate
        cert, key = CertificateManager.create_certificate(
            common_name="server.local", ca_cert=ca_cert, ca_key=ca_key
        )
        cert_path = tmppath / "server.crt"
        key_path = tmppath / "server.key"
        CertificateManager.save_certificate(cert, cert_path)
        CertificateManager.save_private_key(key, key_path)

        yield {
            "cert_path": cert_path,
            "key_path": key_path,
            "ca_cert_path": ca_cert_path,
            "ca_key_path": ca_key_path,
            "tmppath": tmppath,
        }


def test_create_server_package(test_certificates):
    """Test server package creation."""
    output_dir = test_certificates["tmppath"] / "output"
    now = datetime.now()

    zip_path = create_server_package(
        cert_path=test_certificates["cert_path"],
        key_path=test_certificates["key_path"],
        ca_cert_path=test_certificates["ca_cert_path"],
        output_dir=output_dir,
        cert_name="test_server",
        common_name="server.local",
        created_at=now,
        valid_until=now,
    )

    # Verify zip was created
    assert zip_path.exists()
    assert zip_path.name == "test_server_server.zip"

    # Verify zip contents
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        assert "test_server.crt" in names
        assert "test_server.key" in names
        assert "ca.crt" in names
        assert "README.txt" in names

        # Verify README content
        readme = zf.read("README.txt").decode("utf-8")
        assert "test_server" in readme
        assert "Server Certificate Package" in readme


def test_create_client_package(test_certificates):
    """Test client package creation."""
    output_dir = test_certificates["tmppath"] / "output"
    now = datetime.now()

    zip_path = create_client_package(
        ca_cert_path=test_certificates["ca_cert_path"],
        output_dir=output_dir,
        ca_name="test_ca",
        ca_common_name="Test CA",
        ca_created_at=now,
        ca_valid_until=now,
    )

    # Verify zip was created
    assert zip_path.exists()
    assert zip_path.name == "test_ca_client.zip"

    # Verify zip contents
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        assert "test_ca_CA.crt" in names
        assert "README.txt" in names

        # Verify README content
        readme = zf.read("README.txt").decode("utf-8")
        assert "Client Certificate Installation" in readme
        assert "Windows" in readme
        assert "macOS" in readme
        assert "Linux" in readme


def test_create_combined_package(test_certificates):
    """Test creating both server and client packages."""
    output_dir = test_certificates["tmppath"] / "output"
    now = datetime.now()

    server_zip, client_zip = create_combined_package(
        cert_path=test_certificates["cert_path"],
        key_path=test_certificates["key_path"],
        ca_cert_path=test_certificates["ca_cert_path"],
        output_dir=output_dir,
        cert_name="test_server",
        ca_name="test_ca",
        common_name="server.local",
        created_at=now,
        valid_until=now,
        ca_common_name="Test CA",
        ca_created_at=now,
        ca_valid_until=now,
    )

    # Verify both zips were created
    assert server_zip.exists()
    assert client_zip.exists()

    # Verify server zip
    with zipfile.ZipFile(server_zip, "r") as zf:
        assert "test_server.crt" in zf.namelist()
        assert "test_server.key" in zf.namelist()

    # Verify client zip
    with zipfile.ZipFile(client_zip, "r") as zf:
        assert "test_ca_CA.crt" in zf.namelist()


def test_server_package_readme_content(test_certificates):
    """Test that server package README has appropriate content."""
    output_dir = test_certificates["tmppath"] / "output"
    now = datetime.now()

    zip_path = create_server_package(
        cert_path=test_certificates["cert_path"],
        key_path=test_certificates["key_path"],
        ca_cert_path=test_certificates["ca_cert_path"],
        output_dir=output_dir,
        cert_name="myserver",
        common_name="server.local",
        created_at=now,
        valid_until=now,
    )

    with zipfile.ZipFile(zip_path, "r") as zf:
        readme = zf.read("README.txt").decode("utf-8")

        # Check for key content
        assert "myserver.crt" in readme
        assert "myserver.key" in readme
        assert "Private key" in readme
        assert "Security Notes" in readme
        assert "Apache" in readme or "Nginx" in readme


def test_client_package_readme_content(test_certificates):
    """Test that client package README has installation instructions."""
    output_dir = test_certificates["tmppath"] / "output"
    now = datetime.now()

    zip_path = create_client_package(
        ca_cert_path=test_certificates["ca_cert_path"],
        output_dir=output_dir,
        ca_name="myca",
        ca_common_name="Test CA",
        ca_created_at=now,
        ca_valid_until=now,
    )

    with zipfile.ZipFile(zip_path, "r") as zf:
        readme = zf.read("README.txt").decode("utf-8")

        # Check for platform instructions
        assert "Windows" in readme
        assert "macOS" in readme
        assert "Linux" in readme
        assert "iOS" in readme
        assert "Android" in readme
        assert "Firefox" in readme
        assert "Trusted Root" in readme or "Trust" in readme


def test_output_directory_creation(test_certificates):
    """Test that output directory is created if it doesn't exist."""
    output_dir = test_certificates["tmppath"] / "nested" / "output" / "dir"
    now = datetime.now()

    zip_path = create_server_package(
        cert_path=test_certificates["cert_path"],
        key_path=test_certificates["key_path"],
        ca_cert_path=test_certificates["ca_cert_path"],
        output_dir=output_dir,
        cert_name="test",
        common_name="server.local",
        created_at=now,
        valid_until=now,
    )

    # Verify directory was created
    assert output_dir.exists()
    assert zip_path.exists()
