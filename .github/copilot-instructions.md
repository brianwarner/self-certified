# Copilot Instructions for Internal Certificate Manager

**NOTE: Keep this file up-to-date as the project evolves.**

## Project Overview

A Python utility for creating and managing self-signed SSL certificates for internal devices where paid certificates or Let's Encrypt are not options.

## Core Requirements

### Functionality

- Create or use existing root CA certificates
- Guide users through creating and signing individual certificates
- Generate zip files for server deployment and client distribution
- Export CA certificates as client packages (cert only, no private key)
- Allow forgetting/removing certificate records
- Note: Certificate renewal removed from UI - not currently supported

### Security

- Encrypt sensitive data at rest (private keys, CA data)
- Follow security best practices for certificate generation
- Store encrypted metadata about certificates and locations

### Storage

- Default: subdirectory in workspace (excluded from git)
- Configurable: allow custom paths for metadata and outputs
- Track certificate locations and metadata in encrypted database

### UI Phases

1. **Phase 1**: CLI with text-based GUI using prompt_toolkit
2. **Phase 2 (Current)**: tkinter GUI - fully implemented and functional

### Testing

- Target: 85% test coverage
- Minimum enforced: 80%
- Tests stored in `tests/` directory
- Write tests as features are developed

## Technical Approach

### Key Libraries

- `cryptography` - certificate generation and management
- `prompt_toolkit` - interactive CLI interface
- `tkinter` - GUI interface (Phase 2)
- SQLite (built-in) with Fernet encryption - secure metadata storage
- Standard library modules for zip, file operations

### Architecture

- Modular design with separate concerns:
  - Certificate operations (CA, signing, generation)
  - Storage/database management
  - Configuration management
  - CLI interface (prompt_toolkit)
  - GUI interface (tkinter)
  - File/zip utilities

### File Organization

- `certs_dir` (config.certs_dir) - certificate and key storage
- `output_dir` (config.output_dir) - package zip files
- `metadata_db` (config.metadata_db) - encrypted SQLite database
- Naming convention: `basename.pem` for certificates, `basename.key` for private keys

### GUI Implementation Details

- Threading: Use `self.after()` (not `self.root.after()`) for callbacks in Toplevel dialogs
- Button layout: Pack buttons first with `side=BOTTOM`, then canvas with `fill/expand`
- Static methods: Use `CertificateManager.method_name()` for static methods
- Database-stored CAs: Create temp files for export operations, cleanup in finally blocks
- File dialogs: Use `initialdir=expanduser("~")` for user-friendly starting location
- DateTime formatting: Use `_format_datetime()` helper for consistent display (yyyy-mm-dd at hh:mm)
- Tests: Mock `_setup_ui` and `_init_storage` to prevent GUI popups during pytest

### Code Style

- Technical users: minimal hand-holding in code comments
- Clear, concise function/class names
- Type hints throughout
- Keep explanations brief and relevant
- Never use bare `except:` clauses - always specify `except Exception:` or a specific exception type

### Documentation

- README: basic information only
- No quickstart guides or verbose tutorials
- Assume users are technically proficient

## Development Guidelines

- Implement features incrementally with tests
- Maintain security-first mindset
- Keep configuration flexible
- Ensure clean separation between UI and business logic for future GUI addition
