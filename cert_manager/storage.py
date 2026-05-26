"""Encrypted storage for certificate metadata and sensitive data."""

import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from contextlib import contextmanager
import base64
import hashlib
from cryptography.fernet import Fernet

_SENTINEL_KEY = "__password_verify__"
_SENTINEL_VALUE = "self-certified-valid"


class CertificateStorage:
    """Manages encrypted storage of certificate metadata."""

    def __init__(self, db_path: Path, encryption_key: str):
        """Initialize encrypted storage.

        Args:
            db_path: Path to the database file
            encryption_key: Encryption key for securing the database
        """
        self.db_path = db_path
        is_new_db = not db_path.exists()
        # Derive a Fernet key from the password
        key_bytes = hashlib.sha256(encryption_key.encode()).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
        self._init_db()
        self._verify_encryption(is_new_db)

    def _verify_encryption(self, is_new_db: bool) -> None:
        """Verify the password is correct using an encrypted sentinel value.

        On a new database, stores the encrypted sentinel.
        On an existing database, decrypts the sentinel to confirm the password.
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?", (_SENTINEL_KEY,)
            ).fetchone()

        if row is None:
            # New database or upgraded DB without sentinel — store it now
            encrypted = self._encrypt(_SENTINEL_VALUE)
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                    (_SENTINEL_KEY, encrypted),
                )
        else:
            # Existing database — verify the password by decrypting the sentinel
            try:
                decrypted = self._decrypt(row["value"])
                if decrypted != _SENTINEL_VALUE:
                    raise ValueError("Incorrect password")
            except ValueError:
                raise
            except Exception as e:
                raise ValueError("Incorrect password") from e

    @contextmanager
    def _get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _encrypt(self, data: str) -> str:
        """Encrypt sensitive data."""
        if data is None:
            return None
        return self.fernet.encrypt(data.encode()).decode()

    def _decrypt(self, data: str) -> str:
        """Decrypt sensitive data."""
        if data is None:
            return None
        return self.fernet.decrypt(data.encode()).decode()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ca_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    cert_path TEXT,
                    key_path TEXT,
                    cert_data TEXT,
                    key_data TEXT,
                    created_at TEXT NOT NULL,
                    valid_until TEXT NOT NULL,
                    common_name TEXT NOT NULL,
                    organization TEXT,
                    country TEXT
                )
            """)

            # Migrate existing table if needed
            try:
                conn.execute("ALTER TABLE ca_certificates ADD COLUMN cert_data TEXT")
            except sqlite3.OperationalError:
                pass  # Column already exists
            try:
                conn.execute("ALTER TABLE ca_certificates ADD COLUMN key_data TEXT")
            except sqlite3.OperationalError:
                pass  # Column already exists

            conn.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    common_name TEXT NOT NULL,
                    cert_path TEXT NOT NULL,
                    key_path TEXT NOT NULL,
                    ca_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    valid_until TEXT NOT NULL,
                    san_dns TEXT,
                    san_ip TEXT,
                    organization TEXT,
                    country TEXT,
                    FOREIGN KEY (ca_id) REFERENCES ca_certificates(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                )
            """)

    def add_ca(
        self,
        name: str,
        cert_data: bytes,
        key_data: bytes,
        valid_until: datetime,
        common_name: str,
        organization: Optional[str] = None,
        country: Optional[str] = None,
        created_at: Optional[datetime] = None,
    ) -> int:
        """Add a CA certificate record with encrypted cert/key data.

        Args:
            name: CA name
            cert_data: PEM-encoded certificate bytes
            key_data: PEM-encoded private key bytes
            valid_until: Expiration date
            common_name: Certificate common name
            organization: Optional organization
            country: Optional country code
            created_at: Optional creation date (defaults to now if not provided)

        Returns:
            The ID of the newly created record
        """
        if created_at is None:
            created_at = datetime.now()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO ca_certificates
                (name, cert_data, key_data, created_at, valid_until,
                 common_name, organization, country)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    name,
                    self._encrypt(cert_data.decode("utf-8")),
                    self._encrypt(key_data.decode("utf-8")),
                    created_at.isoformat(),
                    valid_until.isoformat(),
                    common_name,
                    organization,
                    country,
                ),
            )
            return cursor.lastrowid

    def get_ca(self, name: str) -> Optional[Dict[str, Any]]:
        """Get CA certificate record by name with decrypted cert/key data."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM ca_certificates WHERE name = ?", (name,)
            ).fetchone()
            if row:
                ca = dict(row)
                # Decrypt sensitive fields
                if ca.get("cert_data"):
                    ca["cert_data"] = self._decrypt(ca["cert_data"]).encode("utf-8")
                if ca.get("key_data"):
                    ca["key_data"] = self._decrypt(ca["key_data"]).encode("utf-8")
                # Legacy support for file-based storage
                if ca.get("cert_path"):
                    ca["cert_path"] = self._decrypt(ca["cert_path"])
                if ca.get("key_path"):
                    ca["key_path"] = self._decrypt(ca["key_path"])
                return ca
            return None

    def list_cas(self) -> List[Dict[str, Any]]:
        """List all CA certificates."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM ca_certificates ORDER BY created_at DESC"
            ).fetchall()
            cas = []
            for row in rows:
                ca = dict(row)
                # Decrypt cert/key data but don't include in list view
                # Legacy support for file-based storage
                if ca.get("cert_path"):
                    ca["cert_path"] = self._decrypt(ca["cert_path"])
                if ca.get("key_path"):
                    ca["key_path"] = self._decrypt(ca["key_path"])
                # Don't decrypt full cert/key data for list view (performance)
                ca.pop("cert_data", None)
                ca.pop("key_data", None)
                cas.append(ca)
            return cas

    def add_certificate(
        self,
        name: str,
        common_name: str,
        cert_path: Path,
        key_path: Path,
        ca_id: int,
        valid_until: datetime,
        san_dns: Optional[List[str]] = None,
        san_ip: Optional[List[str]] = None,
        organization: Optional[str] = None,
        country: Optional[str] = None,
    ) -> int:
        """Add a certificate record.

        Returns:
            The ID of the newly created record
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO certificates
                (name, common_name, cert_path, key_path, ca_id, created_at,
                 valid_until, san_dns, san_ip, organization, country)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    name,
                    common_name,
                    self._encrypt(str(cert_path)),
                    self._encrypt(str(key_path)),
                    ca_id,
                    datetime.now().isoformat(),
                    valid_until.isoformat(),
                    ",".join(san_dns) if san_dns else None,
                    ",".join(san_ip) if san_ip else None,
                    organization,
                    country,
                ),
            )
            return cursor.lastrowid

    def get_certificate(self, name: str) -> Optional[Dict[str, Any]]:
        """Get certificate record by name."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE name = ?", (name,)
            ).fetchone()
            if row:
                cert = dict(row)
                # Decrypt sensitive fields
                cert["cert_path"] = self._decrypt(cert["cert_path"])
                cert["key_path"] = self._decrypt(cert["key_path"])
                # Parse SAN fields back to lists
                cert["san_dns"] = cert["san_dns"].split(",") if cert["san_dns"] else []
                cert["san_ip"] = cert["san_ip"].split(",") if cert["san_ip"] else []
                return cert
            return None

    def list_certificates(self) -> List[Dict[str, Any]]:
        """List all certificates."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT c.*, ca.name as ca_name
                FROM certificates c
                LEFT JOIN ca_certificates ca ON c.ca_id = ca.id
                ORDER BY c.created_at DESC
                """).fetchall()
            certs = []
            for row in rows:
                cert = dict(row)
                cert["cert_path"] = self._decrypt(cert["cert_path"])
                cert["key_path"] = self._decrypt(cert["key_path"])
                cert["san_dns"] = cert["san_dns"].split(",") if cert["san_dns"] else []
                cert["san_ip"] = cert["san_ip"].split(",") if cert["san_ip"] else []
                certs.append(cert)
            return certs

    def delete_certificate(self, name: str) -> bool:
        """Delete a certificate record by name.

        Returns:
            True if deleted, False if not found
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM certificates WHERE name = ?", (name,))
            return cursor.rowcount > 0

    def export_ca(self, name: str, cert_path: Path, key_path: Path) -> bool:
        """Export CA certificate and key to files.

        Args:
            name: CA name
            cert_path: Path to save certificate
            key_path: Path to save private key

        Returns:
            True if successful, False if CA not found
        """
        ca = self.get_ca(name)
        if not ca or not ca.get("cert_data") or not ca.get("key_data"):
            return False

        cert_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.parent.mkdir(parents=True, exist_ok=True)

        with open(cert_path, "wb") as f:
            f.write(ca["cert_data"])
        with open(key_path, "wb") as f:
            f.write(ca["key_data"])

        return True

    def delete_ca(self, name: str) -> bool:
        """Delete a CA certificate record by name.

        Note: This will fail if there are certificates signed by this CA.

        Returns:
            True if deleted, False if not found or has dependent certificates
        """
        with self._get_connection() as conn:
            # Check for dependent certificates
            ca = self.get_ca(name)
            if not ca:
                return False

            dependent = conn.execute(
                "SELECT COUNT(*) as count FROM certificates WHERE ca_id = ?",
                (ca["id"],),
            ).fetchone()

            if dependent["count"] > 0:
                raise ValueError(
                    f"Cannot delete CA '{name}': {dependent['count']} "
                    f"certificate(s) depend on it"
                )

            cursor = conn.execute("DELETE FROM ca_certificates WHERE name = ?", (name,))
            return cursor.rowcount > 0
