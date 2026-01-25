<p align="center">
<img src="./cert_manager/icon.png" style="height: 400px;" alt="Project logo: A lock high-fiving itself">
</p>

# Self-Certified

A self-signed SSL root and server certificate manager. Be your own CA and give yourself a (secure) high-five!

## Overview

Self-Certified is a Python utility for creating and managing self-signed SSL certificates when paid certificates or Let's Encrypt are not an option. Handles root certificate creation, server certificate signing, and package generation for deployment.

This is not a replacement for something like Let's Encrypt because every client that visits a server using a `Self-Certified` certificate will need a copy of your new root certificate. However, for small-scale deployments on home networks with a known number of client devices, this will make the process of creating and signing much easier.

## Features

- Create or import root certificates and private keys
- Generate and sign SSL certificates
- Subject Alternative Names (SAN) support for DNS and IP
- Encrypted storage for sensitive data
- Automated package generation for server deployment and client distribution
- GUI or CLI
- All sensitive root certificate data is saved in the database
- Database requires password on each access

## Basic concepts

`Self-Certified` creates [self-signed SSL certificates](https://en.wikipedia.org/wiki/Self-signed_certificate). The biggest thing to know is that these are not, by default, trusted by ANYTHING. Unlike a free certificate issued by [Let's Encrypt](https://letsencrypt.org/) (which is free) or one of the overpriced certificates issued by the commercial providers, you are the source of trust.

SSL certificates work like this. Someone reputable (a "Certificate Authority" or "CA") creates a root certificate. That root certificate can be used to sign certificates that will be used by other servers. Usually there is a high bar to have a certificate signed, including proving ownership of the server where the certificate will be deployed.

Just having a signed certificate on the server doesn't do much; clients need to know whether certificates are trustworthy. They do this by also having a copy of the root certificate from the CA, which can be used to check if the signed server certificate is actually authentic.

Even if they offer SSL connections, many consumer and DIY devices don't come with signed certificates (e.g., home NAS devices, developer webservers, etc.). When you see an SSL warning about an untrusted connection, this means the server is offering up a certificate and an SSL connection, but your device doesn't have the root certificate used to create it, and can't tell if the certificate is valid.

The process for creating a certificate is well documented, but it involves a number of steps. `Self-Certified` is an attempt to simplify this by acting as a CA and generating a root certificate, creating other signed server certificates, and packaging everything with both client and server instructions to get rid of SSL warnings in a way that maintains the integrity of your connections.

## Quick Start

The easiest way to get started is to use the launcher scripts, which automatically check dependencies and set up the environment:

**macOS/Linux:**

```bash
# Launch GUI
./gui.sh

# Launch CLI
./cli.sh
```

**Windows (PowerShell):**

```powershell
# Launch GUI
.\gui.ps1

# Launch CLI
.\cli.ps1
```

The launcher scripts automatically:

- Check for Python 3.8+ and OpenSSL
- Create a virtual environment (if needed)
- Upgrade pip
- Install/upgrade required dependencies
- Launch the application

## Manual Installation

If you prefer to set up manually without using the launcher scripts:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Then run directly:

```bash
# GUI
python -m cert_manager.gui
# or: python gui.py

# CLI
python -m cert_manager.cli
# or: python main.py
```

## Usage

1. Generate a root certificate and individual server certificates using either the **GUI** or **CLI** (see Quick Start above).

1. Deploy the server certificate and private key on your server. **IMPORTANT**: Protect your private key! It should never be anywhere but the server.

1. Export a root client package containing the root certificate and instructions.

1. Install the **root** certificate on any device that will be connecting to the server. This will trust the server certificate you just created, plus any others you need to create for other servers.

## Tips

### Keep track of your database and password

`Self-Certified` asks your for a password because it saves your root certificate and private key (the REALLY IMPORTANT private key that you should NEVER USE OR SHARE) in an encrypted database in `cert_storage`.

Don't lose the contents of `cert_storage`, and don't lose your password. You won't be able to issue new certificates.

### Make sure your root certificate has a long expiration

When your root certificate expires, clients will no longer be able to verify server certificates. Set a long expiration for your root certificate (i.e., 10+ years). You can use a shorter expiration on your server certs if you prefer; you'll just have to replace them with another signed cert.

### Install the root certificate on all of your clients, not server certs

The point of the root certificate is that it's the foundation of the chain of trust. If your devices trust the root, then they'll trust all certificates signed by the root (until it expires, see above).

## Storage

By default, certificates and metadata are stored in `cert_storage/output`. The GUI can save output wherever you choose

<!-- markdownlint-disable-file MD041 -->