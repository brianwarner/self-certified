"""Configuration management for certificate storage and application settings."""

from pathlib import Path
from typing import Optional


class Config:
    """Manages application configuration and storage paths."""

    DEFAULT_STORAGE_DIR = "cert_storage"

    def __init__(self, workspace_root: Optional[Path] = None):
        """Initialize configuration.

        Args:
            workspace_root: Root directory for the workspace. If None, uses current directory.
        """
        self.workspace_root = workspace_root or Path.cwd()
        self._storage_dir = self.workspace_root / self.DEFAULT_STORAGE_DIR

    @property
    def storage_dir(self) -> Path:
        """Get storage directory path (always cert_storage)."""
        return self._storage_dir

    @property
    def metadata_db(self) -> Path:
        """Get metadata database path."""
        return self._storage_dir / "metadata.db"

    @property
    def ca_dir(self) -> Path:
        """Get CA directory path."""
        return self._storage_dir / "ca"

    @property
    def certs_dir(self) -> Path:
        """Get certificates directory path."""
        return self._storage_dir / "certificates"

    @property
    def output_dir(self) -> Path:
        """Get output directory path."""
        return self._storage_dir / "output"

    def ensure_directories(self) -> None:
        """Create all necessary directories if they don't exist."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
