"""Interactive CLI interface using prompt_toolkit."""

from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import (
    radiolist_dialog,
    button_dialog,
)
from prompt_toolkit.validation import Validator, ValidationError
from pathlib import Path
from typing import Optional
import getpass
import sys
from cryptography import x509

from cert_manager.config import Config
from cert_manager.storage import CertificateStorage
from cert_manager.certificates import CertificateManager
from cert_manager.utils import create_combined_package


class IPAddressValidator(Validator):
    """Validates IP address format."""

    def validate(self, document):
        text = document.text.strip()
        if not text:
            return  # Empty is OK for optional fields

        import ipaddress

        try:
            ipaddress.ip_address(text)
        except ValueError:
            raise ValidationError(message="Invalid IP address format")


class CountryCodeValidator(Validator):
    """Validates two-letter country code."""

    def validate(self, document):
        text = document.text.strip()
        if not text:
            return  # Empty is OK for optional fields

        if len(text) != 2 or not text.isalpha():
            raise ValidationError(message="Country code must be exactly 2 letters")


def sanitize_name(name: str) -> str:
    """Sanitize name for use in filenames.

    Converts to snake_case and replaces non-alphanumeric characters with underscores.

    Args:
        name: The name to sanitize

    Returns:
        Sanitized name safe for filenames
    """
    import re

    # Replace any non-alphanumeric character with underscore
    sanitized = re.sub(r"[^a-zA-Z0-9]+", "_", name)
    # Remove leading/trailing underscores
    sanitized = sanitized.strip("_")
    # Convert to lowercase (snake_case)
    sanitized = sanitized.lower()
    return sanitized


class CertManagerCLI:
    """Interactive CLI for certificate management."""

    def __init__(self):
        """Initialize CLI."""
        self.config = Config()
        self.storage = None
        self.running = True

    def _init_storage(self) -> bool:
        """Initialize encrypted storage with user password."""
        if self.storage is not None:
            return True

        self.config.ensure_directories()

        # Check if database exists
        db_exists = self.config.metadata_db.exists()

        if db_exists:
            password = getpass.getpass("Enter database password: ")
        else:
            print(
                "\nFirst-time setup: Create a password for encrypted certificate storage."
            )
            print("This password will be required each time you run this tool.")
            password = getpass.getpass("Create database password: ")
            password_confirm = getpass.getpass("Confirm password: ")

            if password != password_confirm:
                print("Passwords do not match!")
                return False

        try:
            self.storage = CertificateStorage(self.config.metadata_db, password)
            return True
        except Exception as e:
            print(f"Failed to access database: {e}")
            print("If this is an existing database, the password may be incorrect.")
            return False

    def run(self):
        """Main CLI loop."""
        print("Internal Certificate Manager")
        print("=" * 50)

        if not self._init_storage():
            return

        while self.running:
            action = self._main_menu()
            if action:
                action()

    def _main_menu(self) -> Optional[callable]:
        """Display main menu and return selected action."""
        result = radiolist_dialog(
            title="Main Menu",
            text=f"Output directory: {self.config.output_dir}\n\nSelect an action:",
            values=[
                ("list_cas", "List root certificates"),
                ("create_ca", "Create new root certificate"),
                ("use_existing_ca", "Import existing root certificate"),
                ("export_ca", "Export root certificate"),
                ("export_ca_client", "Export root certificate client package"),
                ("forget_ca", "Forget root certificate"),
                ("list_certs", "List certificates"),
                ("create_cert", "Create and sign certificate"),
                ("forget_cert", "Forget certificate"),
            ],
            cancel_text="Exit",
        ).run()

        if not result:
            self.running = False
            return None

        if result == "create_ca":
            return self._create_ca
        elif result == "use_existing_ca":
            return self._use_existing_ca
        elif result == "export_ca":
            return self._export_ca
        elif result == "export_ca_client":
            return self._export_ca_client_package
        elif result == "create_cert":
            return self._create_certificate
        elif result == "list_certs":
            return self._list_certificates
        elif result == "list_cas":
            return self._list_cas
        elif result == "forget_cert":
            return self._forget_certificate
        elif result == "forget_ca":
            return self._forget_ca
        elif result == "exit":
            self.running = False
            return None

        return None

    def _create_ca(self):
        """Create a new root certificate."""
        print("\nCreate Root Certificate")
        print("-" * 50)

        name = prompt("Root certificate name (used for file naming): ").strip()
        if not name:
            print("Root certificate name is required!")
            return

        # Check if root certificate already exists
        if self.storage.get_ca(name):
            print(f"Root certificate '{name}' already exists!")
            return

        common_name = prompt("Common Name (e.g., 'My Internal CA'): ").strip()
        if not common_name:
            print("Common Name is required!")
            return

        organization = prompt("Organization (optional): ").strip() or None
        country = (
            prompt(
                "Country code (2 letters, optional): ", validator=CountryCodeValidator()
            )
            .strip()
            .upper()
            or None
        )

        validity_input = prompt("Validity in days (default: 3650): ").strip()
        validity_days = int(validity_input) if validity_input else 3650

        print("\nGenerating root certificate...")
        try:
            cert, key = CertificateManager.create_ca_certificate(
                common_name=common_name,
                organization=organization,
                country=country,
                validity_days=validity_days,
            )

            # Convert to PEM bytes
            cert_data = CertificateManager.certificate_to_pem(cert)
            key_data = CertificateManager.private_key_to_pem(key)

            # Store in encrypted database
            self.storage.add_ca(
                name=name,
                cert_data=cert_data,
                key_data=key_data,
                valid_until=cert.not_valid_after,
                common_name=common_name,
                organization=organization,
                country=country,
            )

            # Create client package
            file_name = sanitize_name(name)
            temp_cert_path = self.config.ca_dir / f"{file_name}_temp.crt"
            temp_cert_path.parent.mkdir(parents=True, exist_ok=True)

            # Temporarily save cert for package creation
            with open(temp_cert_path, "wb") as f:
                f.write(cert_data)

            from cert_manager.utils import create_client_package

            client_zip = create_client_package(
                ca_cert_path=temp_cert_path,
                output_dir=self.config.output_dir,
                ca_name=file_name,
                ca_common_name=common_name,
                ca_created_at=cert.not_valid_before,
                ca_valid_until=cert.not_valid_after,
            )

            # Clean up temp file
            temp_cert_path.unlink()

            print("\n✓ Root certificate created successfully!")
            print("  Stored in encrypted database")
            print(f"  Valid until: {cert.not_valid_after}")
            print(f"  Client package: {client_zip}")

        except Exception as e:
            print(f"\n✗ Failed to create root certificate: {e}")

    def _use_existing_ca(self):
        """Import an existing root certificate."""
        print("\nImport Root Certificate")
        print("-" * 50)

        name = prompt("Root certificate name (used for tracking): ").strip()
        if not name:
            print("Root certificate name is required!")
            return

        if self.storage.get_ca(name):
            print(f"CA '{name}' already exists in database!")
            return

        cert_path_str = prompt("Path to CA certificate (.crt): ").strip()
        key_path_str = prompt("Path to CA private key (.key): ").strip()

        cert_path = Path(cert_path_str).expanduser()
        key_path = Path(key_path_str).expanduser()

        if not cert_path.exists():
            print(f"Certificate file not found: {cert_path}")
            return

        if not key_path.exists():
            print(f"Key file not found: {key_path}")
            return

        try:
            # Load and verify certificate and key
            cert = CertificateManager.load_certificate(cert_path)
            key = CertificateManager.load_private_key(key_path)

            # Convert to PEM bytes
            cert_data = CertificateManager.certificate_to_pem(cert)
            key_data = CertificateManager.private_key_to_pem(key)

            # Extract certificate info
            common_name = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value

            org_attrs = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.ORGANIZATION_NAME
            )
            organization = org_attrs[0].value if org_attrs else None

            country_attrs = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COUNTRY_NAME
            )
            country = country_attrs[0].value if country_attrs else None

            # Store in encrypted database
            self.storage.add_ca(
                name=name,
                cert_data=cert_data,
                key_data=key_data,
                valid_until=cert.not_valid_after,
                common_name=common_name,
                organization=organization,
                country=country,
            )

            # Create client package
            file_name = sanitize_name(name)
            temp_cert_path = self.config.ca_dir / f"{file_name}_temp.crt"
            temp_cert_path.parent.mkdir(parents=True, exist_ok=True)

            with open(temp_cert_path, "wb") as f:
                f.write(cert_data)

            from cert_manager.utils import create_client_package

            client_zip = create_client_package(
                ca_cert_path=temp_cert_path,
                output_dir=self.config.output_dir,
                ca_name=file_name,
                ca_common_name=common_name,
                ca_created_at=cert.not_valid_before,
                ca_valid_until=cert.not_valid_after,
            )

            temp_cert_path.unlink()

            print("\n✓ Root certificate imported successfully!")
            print("  Stored in encrypted database")
            print(f"  Common Name: {common_name}")
            print(f"  Valid until: {cert.not_valid_after}")
            print(f"  Client package: {client_zip}")

        except Exception as e:
            print(f"\n✗ Failed to import root certificate: {e}")

    def _export_ca(self):
        """Export root certificate and key to files."""
        print("\nExport Root Certificate")
        print("-" * 50)

        cas = self.storage.list_cas()
        if not cas:
            print("No root certificates available!")
            return

        if len(cas) == 1:
            ca_name = cas[0]["name"]
            print(f"Exporting root certificate: {ca_name}")
        else:
            ca_choice = radiolist_dialog(
                title="Select Root Certificate",
                text="Choose a root certificate to export:",
                values=[(ca["name"], ca["common_name"]) for ca in cas],
            ).run()

            if not ca_choice:
                return

            ca_name = ca_choice

        # Get export paths
        cert_path_str = prompt(
            "Path for root certificate (default: ca.crt): ", default="ca.crt"
        ).strip()
        key_path_str = prompt(
            "Path for root certificate private key (default: ca.key): ",
            default="ca.key",
        ).strip()

        cert_path = Path(cert_path_str).expanduser()
        key_path = Path(key_path_str).expanduser()

        # Confirm if files exist
        if cert_path.exists() or key_path.exists():
            confirm = button_dialog(
                title="Confirm Overwrite",
                text="One or more files already exist. Overwrite?",
                buttons=[("Yes", True), ("No", False)],
            ).run()

            if not confirm:
                return

        try:
            if self.storage.export_ca(ca_name, cert_path, key_path):
                print("\n✓ Root certificate exported successfully!")
                print(f"  Certificate: {cert_path}")
                print(f"  Private Key: {key_path}")
                print("\n  WARNING: Private key is now stored unencrypted on disk!")
                print("  Remember to secure or delete these files when done.")
            else:
                print("\n✗ Failed to export root certificate.")
        except Exception as e:
            print(f"\n✗ Export failed: {e}")

    def _export_ca_client_package(self):
        """Export root certificate as client package (cert only, no private key)."""
        print("\nExport Root Certificate Client Package")
        print("-" * 50)

        cas = self.storage.list_cas()
        if not cas:
            print("No root certificates available!")
            return

        if len(cas) == 1:
            ca_name = cas[0]["name"]
            print(f"Exporting root certificate: {ca_name}")
        else:
            ca_choice = radiolist_dialog(
                title="Select Root Certificate",
                text="Choose a root certificate for client package:",
                values=[(ca["name"], ca["common_name"]) for ca in cas],
            ).run()

            if not ca_choice:
                return

            ca_name = ca_choice

        # Get root certificate details
        ca_record = self.storage.get_ca(ca_name)
        if not ca_record:
            print("\n✗ Failed to load root certificate.")
            return

        # Get output directory
        output_dir_str = prompt(
            f"Output directory (default: {self.config.output_dir}): ",
            default=str(self.config.output_dir),
        ).strip()

        output_dir = Path(output_dir_str).expanduser()
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Create temporary file for CA cert if stored in database
            ca_cert_path = ca_record.get("cert_path")
            temp_ca_file = None

            if not ca_cert_path:
                # CA is stored in database, export to temp file
                import tempfile

                temp_ca_file = tempfile.NamedTemporaryFile(
                    mode="wb", suffix=".pem", delete=False
                )
                temp_ca_file.write(ca_record["cert_data"])
                temp_ca_file.close()
                ca_cert_path = temp_ca_file.name

            try:
                from cert_manager.utils import create_client_package

                zip_path = create_client_package(
                    ca_cert_path=Path(ca_cert_path),
                    output_dir=output_dir,
                    ca_name=sanitize_name(ca_record["name"]),
                    ca_common_name=ca_record["common_name"],
                    ca_created_at=ca_record["created_at"],
                    ca_valid_until=ca_record["valid_until"],
                )

                print("\n✓ Client package created successfully!")
                print(f"  Package: {zip_path}")
                print("\n  This package contains the root certificate and installation")
                print(
                    "  instructions for end users. It does NOT contain the private key."
                )
            finally:
                # Clean up temp file if we created one
                if temp_ca_file:
                    import os

                    try:
                        os.unlink(temp_ca_file.name)
                    except Exception:
                        pass

        except Exception as e:
            print(f"\n✗ Failed to create client package: {e}")

    def _create_certificate(self):
        """Create and sign a new certificate."""
        print("\nCreate and Sign Certificate")
        print("-" * 50)

        # Select root certificate
        cas = self.storage.list_cas()
        if not cas:
            print("No root certificates available. Create one first!")
            return

        if len(cas) == 1:
            ca_name = cas[0]["name"]
            print(f"Using root certificate: {ca_name}")
        else:
            ca_name = radiolist_dialog(
                title="Select Root Certificate",
                text="Choose a root certificate to sign this certificate:",
                values=[(ca["name"], ca["common_name"]) for ca in cas],
            ).run()

            if not ca_name:
                return

        # Get full root certificate record with cert/key data
        ca_record = self.storage.get_ca(ca_name)
        if not ca_record:
            print("Failed to load root certificate!")
            return

        # Load CA from database
        try:
            if ca_record.get("cert_data") and ca_record.get("key_data"):
                # Load from encrypted database
                ca_cert = CertificateManager.load_certificate_from_pem(
                    ca_record["cert_data"]
                )
                ca_key = CertificateManager.load_private_key_from_pem(
                    ca_record["key_data"]
                )
            else:
                # Legacy: load from files
                ca_cert = CertificateManager.load_certificate(
                    Path(ca_record["cert_path"])
                )
                ca_key = CertificateManager.load_private_key(
                    Path(ca_record["key_path"])
                )
        except Exception as e:
            print(f"Failed to load CA: {e}")
            return

        # Get certificate details
        name = prompt("Certificate name (for tracking): ").strip()
        if not name:
            print("Certificate name is required!")
            return

        if self.storage.get_certificate(name):
            print(f"Certificate '{name}' already exists!")
            return

        common_name = prompt("Common Name (e.g., 'server.local'): ").strip()
        if not common_name:
            print("Common Name is required!")
            return

        # SAN DNS names
        san_dns = []
        print("\nSubject Alternative Names (DNS)")
        print("Enter DNS names one at a time. Press Enter on empty line to finish.")
        while True:
            dns_name = prompt(
                f"  DNS name {len(san_dns) + 1} (or Enter to finish): "
            ).strip()
            if not dns_name:
                break
            san_dns.append(dns_name)

        # SAN IP addresses
        san_ip = []
        print("\nSubject Alternative Names (IP)")
        print("Enter IP addresses one at a time. Press Enter on empty line to finish.")
        while True:
            ip = prompt(
                f"  IP address {len(san_ip) + 1} (or Enter to finish): ",
                validator=IPAddressValidator(),
            ).strip()
            if not ip:
                break
            san_ip.append(ip)

        organization = prompt("Organization (optional): ").strip() or None
        country = (
            prompt(
                "Country code (2 letters, optional): ", validator=CountryCodeValidator()
            )
            .strip()
            .upper()
            or None
        )

        validity_input = prompt("Validity in days (default: 1825): ").strip()
        validity_days = int(validity_input) if validity_input else 1825

        print("\nGenerating certificate...")
        try:
            cert, key = CertificateManager.create_certificate(
                common_name=common_name,
                ca_cert=ca_cert,
                ca_key=ca_key,
                san_dns=san_dns if san_dns else None,
                san_ip=san_ip if san_ip else None,
                organization=organization,
                country=country,
                validity_days=validity_days,
            )

            # Save files
            file_name = sanitize_name(name)
            cert_path = self.config.certs_dir / f"{file_name}.crt"
            key_path = self.config.certs_dir / f"{file_name}.key"

            CertificateManager.save_certificate(cert, cert_path)
            CertificateManager.save_private_key(key, key_path)

            # Store in database
            self.storage.add_certificate(
                name=name,
                common_name=common_name,
                cert_path=cert_path,
                key_path=key_path,
                ca_id=ca_record["id"],
                valid_until=cert.not_valid_after_utc,
                san_dns=san_dns if san_dns else None,
                san_ip=san_ip if san_ip else None,
                organization=organization,
                country=country,
            )

            # Create packages
            print("\nCreating deployment packages...")

            # Export CA cert to temp file if not already on disk
            ca_cert_path = ca_record.get("cert_path")
            temp_ca_file = None
            if not ca_cert_path:
                # CA is stored in database, export to temp file
                import tempfile

                temp_ca_file = tempfile.NamedTemporaryFile(
                    mode="wb", suffix=".pem", delete=False
                )
                temp_ca_file.write(ca_record["cert_data"])
                temp_ca_file.close()
                ca_cert_path = temp_ca_file.name

            try:
                server_zip, client_zip = create_combined_package(
                    cert_path=cert_path,
                    key_path=key_path,
                    ca_cert_path=Path(ca_cert_path),
                    output_dir=self.config.output_dir,
                    cert_name=file_name,
                    ca_name=sanitize_name(ca_record["name"]),
                    common_name=common_name,
                    created_at=cert.not_valid_before_utc.isoformat(),
                    valid_until=cert.not_valid_after_utc.isoformat(),
                    ca_common_name=ca_record["common_name"],
                    ca_created_at=ca_record["created_at"],
                    ca_valid_until=ca_record["valid_until"],
                    san_dns=san_dns if san_dns else None,
                    san_ip=san_ip if san_ip else None,
                )
            finally:
                # Clean up temp file if we created one
                if temp_ca_file:
                    import os

                    try:
                        os.unlink(temp_ca_file.name)
                    except Exception:
                        pass

            print("\n✓ Certificate created successfully!")
            print(f"  Certificate: {cert_path}")
            print(f"  Private Key: {key_path}")
            print(f"  Valid until: {cert.not_valid_after_utc}")
            print(f"\n  Server package: {server_zip}")
            print(f"  Client package: {client_zip}")

        except Exception as e:
            print(f"\n✗ Failed to create certificate: {e}")
            import traceback

            traceback.print_exc()

    def _list_certificates(self):
        """List all certificates."""
        print("\nCertificates")
        print("-" * 50)

        certs = self.storage.list_certificates()
        if not certs:
            print("No certificates found.")
            return

        for cert in certs:
            file_name = sanitize_name(cert["name"])
            server_zip = self.config.output_dir / f"{file_name}_server.zip"

            print(f"\n{cert['name']}")
            print(f"  Common Name: {cert['common_name']}")
            print(f"  Created: {cert['created_at'][:10]}")
            print(f"  Expires: {cert['valid_until'][:10]}")
            if cert["san_dns"]:
                print(f"  DNS SANs: {', '.join(cert['san_dns'])}")
            if cert["san_ip"]:
                print(f"  IP SANs: {', '.join(cert['san_ip'])}")
            print(f"  Certificate: {cert['cert_path']}")
            if server_zip.exists():
                print(f"  Server Package: {server_zip}")
            else:
                print("  Server Package: Not found")

        input("\nPress Enter to continue...")

    def _list_cas(self):
        """List all root certificates."""
        print("\nRoot Certificates")
        print("-" * 50)

        cas = self.storage.list_cas()
        if not cas:
            print("No root certificates found.")
            return

        for ca in cas:
            file_name = sanitize_name(ca["name"])
            client_zip = self.config.output_dir / f"{file_name}_client.zip"

            print(f"\n{ca['name']}")
            print(f"  Common Name: {ca['common_name']}")
            print(f"  Created: {ca['created_at'][:10]}")
            print(f"  Expires: {ca['valid_until'][:10]}")
            if ca["organization"]:
                print(f"  Organization: {ca['organization']}")
            print("  Storage: Encrypted database")
            if client_zip.exists():
                print(f"  Client Package: {client_zip}")
            else:
                print("  Client Package: Not found")

        input("\nPress Enter to continue...")

    def _forget_certificate(self):
        """Remove a certificate from tracking."""
        print("\nForget Certificate")
        print("-" * 50)

        certs = self.storage.list_certificates()
        if not certs:
            print("No certificates to forget!")
            return

        cert_choice = radiolist_dialog(
            title="Select Certificate",
            text="Choose a certificate to forget:",
            values=[(cert["name"], cert["common_name"]) for cert in certs],
        ).run()

        if not cert_choice:
            return

        # Get certificate details before deleting
        cert_record = self.storage.get_certificate(cert_choice)

        # Ask if user wants to delete files
        delete_files = button_dialog(
            title="Delete Files",
            text=f"Delete certificate files from disk?\n\nCertificate: {cert_record['cert_path']}\nPrivate Key: {cert_record['key_path']}",  # noqa: E501
            buttons=[
                ("Yes, delete files", True),
                ("No, keep files", False),
            ],
        ).run()

        # Confirm the action
        if delete_files:
            confirm_text = (
                f"Forget certificate '{cert_choice}' and DELETE files from disk?"
            )
        else:
            confirm_text = (
                f"Forget certificate '{cert_choice}'? (files will remain on disk)"
            )

        confirm = button_dialog(
            title="Confirm",
            text=confirm_text,
            buttons=[
                ("Yes", True),
                ("No", False),
            ],
        ).run()

        if confirm:
            # Delete from database
            self.storage.delete_certificate(cert_choice)

            # Delete files if requested
            if delete_files:
                try:
                    cert_path = Path(cert_record["cert_path"])
                    key_path = Path(cert_record["key_path"])

                    if cert_path.exists():
                        cert_path.unlink()
                    if key_path.exists():
                        key_path.unlink()

                    print(
                        f"\n✓ Certificate '{cert_choice}' forgotten and files deleted"
                    )
                except Exception as e:
                    print(f"\n✓ Certificate '{cert_choice}' forgotten from database")
                    print(f"⚠ Warning: Failed to delete files: {e}")
            else:
                print(f"\n✓ Certificate '{cert_choice}' forgotten (files kept on disk)")
        else:
            print("\nCancelled")

    def _forget_ca(self):
        """Remove a root certificate from tracking."""
        print("\nForget Root Certificate")
        print("-" * 50)

        cas = self.storage.list_cas()
        if not cas:
            print("No root certificates to forget!")
            return

        ca_choice = radiolist_dialog(
            title="Select Root Certificate",
            text="Choose a root certificate to forget:",
            values=[(ca["name"], ca["common_name"]) for ca in cas],
        ).run()

        if not ca_choice:
            return

        # Get CA details
        ca_record = self.storage.get_ca(ca_choice)

        # Check if there are certificates signed by this CA
        all_certs = self.storage.list_certificates()
        dependent_certs = [
            cert for cert in all_certs if cert["ca_id"] == ca_record["id"]
        ]

        if dependent_certs:
            cert_names = ", ".join([cert["name"] for cert in dependent_certs])
            print(
                f"\n⚠ Warning: This root certificate has "
                f"{len(dependent_certs)} dependent certificate(s):"
            )
            print(f"  {cert_names}")
            print(
                "\nYou must forget these certificates first before forgetting the root certificate."
            )
            input("\nPress Enter to continue...")
            return

        # Check for client package zip file
        file_name = sanitize_name(ca_choice)
        client_zip = self.config.output_dir / f"{file_name}_client.zip"

        delete_package = False
        if client_zip.exists():
            delete_package = button_dialog(
                title="Delete Client Package",
                text=f"Delete client package from disk?\n\n{client_zip}",
                buttons=[
                    ("Yes, delete package", True),
                    ("No, keep package", False),
                ],
            ).run()

        # Confirm the action
        if delete_package:
            confirm_text = f"Forget root certificate '{ca_choice}' and DELETE client package from disk?"  # noqa: E501
        else:
            confirm_text = f"Forget root certificate '{ca_choice}'?\n\nThe root certificate and private key will be permanently removed from the encrypted database."  # noqa: E501
            if client_zip.exists():
                confirm_text += "\n\n(Client package will remain on disk)"

        confirm = button_dialog(
            title="Confirm",
            text=confirm_text,
            buttons=[
                ("Yes", True),
                ("No", False),
            ],
        ).run()

        if confirm:
            # Delete from database
            success = self.storage.delete_ca(ca_choice)

            if success:
                # Delete client package if requested
                if delete_package and client_zip.exists():
                    try:
                        client_zip.unlink()
                        print(
                            f"\n✓ CA '{ca_choice}' forgotten and client package deleted"
                        )
                    except Exception as e:
                        print(f"\n✓ CA '{ca_choice}' forgotten from database")
                        print(f"⚠ Warning: Failed to delete client package: {e}")
                else:
                    status = (
                        "(client package kept on disk)" if client_zip.exists() else ""
                    )
                    print(f"\n✓ Root certificate '{ca_choice}' forgotten {status}")
            else:
                print(f"\n✗ Failed to forget root certificate '{ca_choice}'")
        else:
            print("\nCancelled")


def main():
    """CLI entry point."""
    try:
        cli = CertManagerCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
