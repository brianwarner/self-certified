"""Tests for configuration management."""

import tempfile
from pathlib import Path

from cert_manager.config import Config


def test_config_default_initialization():
    """Test default configuration initialization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = Config(Path(tmpdir))

        assert config.storage_dir == Path(tmpdir) / "cert_storage"
        assert config.metadata_db == Path(tmpdir) / "cert_storage" / "metadata.db"
        assert config.ca_dir == Path(tmpdir) / "cert_storage" / "ca"
        assert config.certs_dir == Path(tmpdir) / "cert_storage" / "certificates"
        assert config.output_dir == Path(tmpdir) / "cert_storage" / "output"


def test_config_ensure_directories():
    """Test directory creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = Config(Path(tmpdir))
        config.ensure_directories()

        assert config.storage_dir.exists()
        assert config.ca_dir.exists()
        assert config.certs_dir.exists()
        assert config.output_dir.exists()


def test_config_always_uses_cert_storage():
    """Test that storage directory is always cert_storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = Config(Path(tmpdir))

        # Storage dir should always be cert_storage
        assert config.storage_dir.name == "cert_storage"

        # All paths should be under cert_storage
        assert config.metadata_db.parent.name == "cert_storage"
        assert config.ca_dir.parent.name == "cert_storage"
        assert config.certs_dir.parent.name == "cert_storage"
        assert config.output_dir.parent.name == "cert_storage"
