"""Utility functions for packaging and file operations."""

import zipfile
from pathlib import Path
from typing import Tuple, Optional, List, Union
from datetime import datetime


def create_server_package(
    cert_path: Path,
    key_path: Path,
    ca_cert_path: Path,
    output_dir: Path,
    cert_name: str,
    common_name: str,
    created_at: Union[datetime, str],
    valid_until: Union[datetime, str],
    san_dns: Optional[List[str]] = None,
    san_ip: Optional[List[str]] = None,
) -> Path:
    """Create a zip package for server deployment.

    Args:
        cert_path: Path to the server certificate
        key_path: Path to the server private key
        ca_cert_path: Path to the CA certificate
        output_dir: Directory to save the zip file
        cert_name: Name for the certificate (used in zip filename)
        common_name: Certificate common name
        created_at: Creation datetime or ISO format timestamp
        valid_until: Expiration datetime or ISO format timestamp
        san_dns: List of DNS SANs
        san_ip: List of IP SANs

    Returns:
        Path to the created zip file
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / f"{cert_name}_server.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(cert_path, f"{cert_name}.crt")
        zf.write(key_path, f"{cert_name}.key")
        zf.write(ca_cert_path, "ca.crt")

        # Format dates for display
        if isinstance(created_at, datetime):
            created = created_at.strftime("%Y-%m-%d %H:%M:%S")
        else:
            created = created_at[:19] if len(created_at) >= 19 else created_at

        if isinstance(valid_until, datetime):
            expires = valid_until.strftime("%Y-%m-%d %H:%M:%S")
        else:
            expires = valid_until[:19] if len(valid_until) >= 19 else valid_until

        # Build SAN section
        san_section = ""
        if san_dns or san_ip:
            san_section = "\n\nSubject Alternative Names (SANs):\n"
            if san_dns:
                san_section += f"  DNS: {', '.join(san_dns)}\n"
            if san_ip:
                san_section += f"  IP:  {', '.join(san_ip)}\n"

        # Add README for server deployment
        readme_content = f"""Server Certificate Package for {cert_name}
{'=' * (35 + len(cert_name))}

Certificate Details:
--------------------
Common Name:     {common_name}
Created:         {created}
Expires:         {expires}
Key Algorithm:   RSA 4096-bit
Signature:       SHA-256{san_section}

This package contains the following files:

1. {cert_name}.crt - Server certificate
2. {cert_name}.key - Private key (keep secure!)
3. ca.crt - CA certificate (certificate chain)

Installation Instructions:
--------------------------

The exact installation steps depend on your server software:

Web Servers (Apache/Nginx):
- Place certificate and key in appropriate directories (e.g., /etc/ssl/)
- Update server configuration to reference these files
- Ensure ca.crt is included for the certificate chain
- Set appropriate permissions (key file should be readable only by server user)

Application Servers:
- Consult your application's documentation for SSL certificate configuration
- Some applications may require a combined certificate chain file

Security Notes:
- The .key file contains your private key - keep it secure
- Set restrictive file permissions (e.g., chmod 600 for the key)
- Never commit these files to version control
- Regularly rotate certificates before expiration
"""
        zf.writestr("README.txt", readme_content)

    return zip_path


def create_client_package(
    ca_cert_path: Path,
    output_dir: Path,
    ca_name: str,
    ca_common_name: str,
    ca_created_at: Union[datetime, str],
    ca_valid_until: Union[datetime, str],
) -> Path:
    """Create a zip package for client distribution.

    Args:
        ca_cert_path: Path to the CA certificate
        output_dir: Directory to save the zip file
        ca_name: Name of the CA (used in zip filename)
        ca_common_name: CA certificate common name
        ca_created_at: Creation datetime or ISO format timestamp
        ca_valid_until: Expiration datetime or ISO format timestamp

    Returns:
        Path to the created zip file
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / f"{ca_name}_client.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(ca_cert_path, f"{ca_name}_CA.crt")

        # Format dates for display
        if isinstance(ca_created_at, datetime):
            created = ca_created_at.strftime("%Y-%m-%d %H:%M:%S")
        else:
            created = ca_created_at[:19] if len(ca_created_at) >= 19 else ca_created_at

        if isinstance(ca_valid_until, datetime):
            expires = ca_valid_until.strftime("%Y-%m-%d %H:%M:%S")
        else:
            expires = (
                ca_valid_until[:19] if len(ca_valid_until) >= 19 else ca_valid_until
            )

        # Add comprehensive README for clients
        readme_content = f"""Client Certificate Installation - {ca_name} CA
{'=' * (38 + len(ca_name))}

CA Certificate Details:
-----------------------
Common Name:     {ca_common_name}
Created:         {created}
Expires:         {expires}
Key Algorithm:   RSA 4096-bit
Signature:       SHA-256

This package contains the root CA certificate that clients need to trust
in order to accept certificates signed by this CA.

File: {ca_name}_CA.crt

Installation Instructions by Platform:
---------------------------------------

Windows:
1. Double-click the .crt file
2. Click "Install Certificate"
3. Select "Local Machine" (requires admin) or "Current User"
4. Choose "Place all certificates in the following store"
5. Select "Trusted Root Certification Authorities"
6. Complete the wizard

macOS:
1. Double-click the .crt file to open Keychain Access
2. Select "System" or "login" keychain
3. Find the imported certificate
4. Double-click it and expand "Trust"
5. Set "When using this certificate" to "Always Trust"
6. Close the window and enter your password

Linux (most distributions):
1. Copy the .crt file to /usr/local/share/ca-certificates/
   sudo cp {ca_name}_CA.crt /usr/local/share/ca-certificates/
2. Update the certificate store:
   sudo update-ca-certificates

iOS/iPadOS:
1. Email the .crt file to yourself or host it on a web server
2. Tap the certificate file
3. Go to Settings > General > VPN & Device Management
4. Tap the profile and install it
5. Go to Settings > General > About > Certificate Trust Settings
6. Enable full trust for the root certificate

Android:
1. Go to Settings > Security > Encryption & credentials
2. Tap "Install a certificate"
3. Select "CA certificate"
4. Navigate to and select the .crt file

Web Browsers (if not using system store):
- Firefox: Preferences > Privacy & Security > Certificates > View Certificates
  > Authorities > Import
- Chrome: Uses system certificate store (follow OS instructions above)

Important Security Note:
------------------------
Only install this certificate on devices where you need to access services
secured with certificates signed by this CA. Installing CA certificates grants
trust to any certificate signed by that CA.
"""
        zf.writestr("README.txt", readme_content)

    return zip_path


def create_combined_package(
    cert_path: Path,
    key_path: Path,
    ca_cert_path: Path,
    output_dir: Path,
    cert_name: str,
    ca_name: str,
    common_name: str,
    created_at: Union[datetime, str],
    valid_until: Union[datetime, str],
    ca_common_name: str,
    ca_created_at: Union[datetime, str],
    ca_valid_until: Union[datetime, str],
    san_dns: Optional[List[str]] = None,
    san_ip: Optional[List[str]] = None,
) -> Tuple[Path, Path]:
    """Create both server and client packages.

    Args:
        cert_path: Path to the server certificate
        key_path: Path to the server private key
        ca_cert_path: Path to the CA certificate
        output_dir: Directory to save the zip files
        cert_name: Name for the certificate
        ca_name: Name of the CA
        common_name: Certificate common name
        created_at: Certificate creation timestamp
        valid_until: Certificate expiration timestamp
        ca_common_name: CA common name
        ca_created_at: CA creation timestamp
        ca_valid_until: CA expiration timestamp
        san_dns: List of DNS SANs
        san_ip: List of IP SANs

    Returns:
        Tuple of (server_zip_path, client_zip_path)
    """
    server_zip = create_server_package(
        cert_path,
        key_path,
        ca_cert_path,
        output_dir,
        cert_name,
        common_name,
        created_at,
        valid_until,
        san_dns,
        san_ip,
    )
    client_zip = create_client_package(
        ca_cert_path, output_dir, ca_name, ca_common_name, ca_created_at, ca_valid_until
    )

    return server_zip, client_zip
