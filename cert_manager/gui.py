"""Tkinter GUI interface for Internal Certificate Manager."""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from pathlib import Path
from typing import Optional
from datetime import datetime
import threading
import ipaddress
from cryptography import x509
from PIL import Image, ImageTk

from cert_manager.config import Config
from cert_manager.storage import CertificateStorage
from cert_manager.certificates import CertificateManager
from cert_manager.utils import create_combined_package


def sanitize_name(name: str) -> str:
    """Sanitize name for use in filenames.

    Args:
        name: Name to sanitize

    Returns:
        Sanitized name safe for use in filenames
    """
    import re

    # Convert to lowercase
    name = name.lower()
    # Replace spaces and special characters with underscores
    name = re.sub(r"[^a-z0-9_-]", "_", name)
    # Remove consecutive underscores
    name = re.sub(r"_+", "_", name)
    # Remove leading/trailing underscores
    name = name.strip("_")
    return name


class CertificateManagerGUI:
    """Main GUI application for certificate management."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Internal Certificate Manager")
        self.root.geometry("900x600")

        # Set window icon
        icon_path = Path(__file__).parent / "icon.png"
        if icon_path.exists():
            try:
                icon_image = Image.open(icon_path)
                icon_photo = ImageTk.PhotoImage(icon_image)
                self.root.iconphoto(True, icon_photo)
            except Exception:
                pass  # If icon loading fails, just use default

        self.config = Config()
        self.config.ensure_directories()

        self.storage: Optional[CertificateStorage] = None
        self.cert_manager = CertificateManager()

        self._setup_ui()
        self._init_storage()

    def _setup_ui(self):
        """Setup the main UI components."""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Root Certificate Menu
        ca_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Root Certificate", menu=ca_menu)
        ca_menu.add_command(label="Create New Root", command=self._create_ca)
        ca_menu.add_command(label="Import Existing Root", command=self._import_ca)
        ca_menu.add_command(label="Export Root", command=self._export_ca)
        ca_menu.add_separator()
        ca_menu.add_command(label="Forget Root", command=self._forget_ca)

        # Certificate Menu
        cert_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Certificates", menu=cert_menu)
        cert_menu.add_command(
            label="Create & Sign Certificate", command=self._create_certificate
        )
        cert_menu.add_separator()
        cert_menu.add_command(
            label="Forget Certificate", command=self._forget_certificate
        )

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

        # Main container with notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Root Certificate tab
        self.ca_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ca_frame, text="Root Certificates")
        self._setup_ca_tab()

        # Certificates tab
        self.cert_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cert_frame, text="Certificates")
        self._setup_cert_tab()

        # Status bar
        self.status_bar = ttk.Label(
            self.root,
            text=f"Output directory: {self.config.output_dir}",
            relief=tk.SUNKEN,
            anchor=tk.W,
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _setup_ca_tab(self):
        """Setup CA certificates tab."""
        # Toolbar
        toolbar = ttk.Frame(self.ca_frame)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="Create Root", command=self._create_ca).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(toolbar, text="Import Root", command=self._import_ca).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(toolbar, text="Export Root", command=self._export_ca).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(
            toolbar, text="Export Client Package", command=self._export_client_package
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Forget Root", command=self._forget_ca).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(toolbar, text="Refresh", command=self._refresh_ca_list).pack(
            side=tk.LEFT, padx=2
        )

        # Treeview for CA list
        tree_frame = ttk.Frame(self.ca_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.ca_tree = ttk.Treeview(
            tree_frame,
            columns=("Common Name", "Created", "Valid Until"),
            show="tree headings",
            yscrollcommand=scrollbar.set,
        )
        self.ca_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.ca_tree.yview)

        self.ca_tree.heading("#0", text="Name")
        self.ca_tree.heading("Common Name", text="Common Name")
        self.ca_tree.heading("Created", text="Created")
        self.ca_tree.heading("Valid Until", text="Valid Until")

        self.ca_tree.column("#0", width=200)
        self.ca_tree.column("Common Name", width=250)
        self.ca_tree.column("Created", width=200)
        self.ca_tree.column("Valid Until", width=200)

    def _setup_cert_tab(self):
        """Setup certificates tab."""
        # Toolbar
        toolbar = ttk.Frame(self.cert_frame)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        ttk.Button(
            toolbar, text="Create Certificate", command=self._create_certificate
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            toolbar, text="Export Certificate", command=self._export_certificate
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            toolbar, text="Forget Certificate", command=self._forget_certificate
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Refresh", command=self._refresh_cert_list).pack(
            side=tk.LEFT, padx=2
        )

        # Treeview for certificate list
        tree_frame = ttk.Frame(self.cert_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.cert_tree = ttk.Treeview(
            tree_frame,
            columns=("Common Name", "CA", "Created", "Valid Until"),
            show="tree headings",
            yscrollcommand=scrollbar.set,
        )
        self.cert_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.cert_tree.yview)

        self.cert_tree.heading("#0", text="Name")
        self.cert_tree.heading("Common Name", text="Common Name")
        self.cert_tree.heading("CA", text="Root CA")
        self.cert_tree.heading("Created", text="Created")
        self.cert_tree.heading("Valid Until", text="Valid Until")

        self.cert_tree.column("#0", width=150)
        self.cert_tree.column("Common Name", width=200)
        self.cert_tree.column("CA", width=150)
        self.cert_tree.column("Created", width=180)
        self.cert_tree.column("Valid Until", width=180)

    def _init_storage(self):
        """Initialize storage with password."""
        max_attempts = 3
        attempt = 0

        while attempt < max_attempts:
            dialog = PasswordDialog(self.root, "Enter database password:")
            password = dialog.result

            if not password:
                messagebox.showerror("Error", "Password is required")
                self.root.destroy()
                import sys

                sys.exit(1)
                return

            try:
                self.storage = CertificateStorage(self.config.metadata_db, password)
                self._refresh_ca_list()
                self._refresh_cert_list()
                return  # Success!
            except Exception as e:
                attempt += 1
                remaining = max_attempts - attempt

                if remaining > 0:
                    messagebox.showerror(
                        "Error",
                        f"Failed to initialize storage: {e}\n\n"
                        f"Attempts remaining: {remaining}",
                    )
                else:
                    messagebox.showerror(
                        "Error",
                        f"Failed to initialize storage after {max_attempts} attempts.\n\n{e}",
                    )
                    self.root.destroy()
                    import sys

                    sys.exit(1)

    def _refresh_ca_list(self):
        """Refresh CA certificate list."""
        if not self.storage:
            return

        # Clear existing items
        for item in self.ca_tree.get_children():
            self.ca_tree.delete(item)

        # Load CAs
        cas = self.storage.list_cas()
        for ca in cas:
            # Format datetime strings
            created = self._format_datetime(ca["created_at"])
            valid_until = self._format_datetime(ca["valid_until"])
            self.ca_tree.insert(
                "",
                tk.END,
                text=ca["name"],
                values=(ca["common_name"], created, valid_until),
            )

    def _refresh_cert_list(self):
        """Refresh certificate list."""
        if not self.storage:
            return

        # Clear existing items
        for item in self.cert_tree.get_children():
            self.cert_tree.delete(item)

        # Load certificates
        certs = self.storage.list_certificates()
        for cert in certs:
            # Format datetime strings
            created = self._format_datetime(cert["created_at"])
            valid_until = self._format_datetime(cert["valid_until"])
            self.cert_tree.insert(
                "",
                tk.END,
                text=cert["name"],
                values=(
                    cert["common_name"],
                    cert["ca_name"],
                    created,
                    valid_until,
                ),
            )

    def _format_datetime(self, dt_string: str) -> str:
        """Format datetime string as yyyy-mm-dd hh:mm.

        Args:
            dt_string: ISO format datetime string or formatted string

        Returns:
            Formatted string as yyyy-mm-dd hh:mm
        """
        try:
            # Try parsing as ISO format datetime
            if "T" in dt_string:
                dt = datetime.fromisoformat(dt_string.replace("Z", "+00:00"))
            else:
                # Already might be formatted or just a date
                return dt_string[:16] if len(dt_string) >= 16 else dt_string
            return dt.strftime("%Y-%m-%d at %H:%M")
        except Exception:
            # If parsing fails, return as-is
            return dt_string

    def _create_ca(self):
        """Create new CA certificate."""
        dialog = CreateCADialog(self.root, self.storage, self.config, self.cert_manager)
        if dialog.result:
            self._refresh_ca_list()

    def _import_ca(self):
        """Import existing CA certificate."""
        dialog = ImportCADialog(self.root, self.storage, self.config)
        if dialog.result:
            self._refresh_ca_list()

    def _export_ca(self):
        """Export root certificate."""
        if not self.storage:
            return

        cas = self.storage.list_cas()
        if not cas:
            messagebox.showinfo("Info", "No root certificates available")
            return

        # Select root certificate
        dialog = SelectItemDialog(
            self.root,
            "Select root certificate to export",
            [(ca["name"], ca["common_name"]) for ca in cas],
        )
        ca_name = dialog.result
        if not ca_name:
            return

        # Select output directory
        from os.path import expanduser

        output_dir = filedialog.askdirectory(
            title="Select output directory", initialdir=expanduser("~")
        )
        if not output_dir:
            return

        try:
            output_path = Path(output_dir)
            base_name = sanitize_name(ca_name)
            cert_file = output_path / f"{base_name}.pem"
            key_file = output_path / f"{base_name}.key"

            self.storage.export_ca(ca_name, cert_file, key_file)
            messagebox.showinfo(
                "Success",
                f"Root certificate exported to:\n{cert_file}\n{key_file}\n\nThis file contains the private key.\nDo NOT share it with others!",  # noqa: E501
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export root certificate: {e}")

    def _export_client_package(self):
        """Export root certificate as client package (cert only, no private key)."""
        if not self.storage:
            return

        cas = self.storage.list_cas()
        if not cas:
            messagebox.showinfo("Info", "No root certificates available")
            return

        # Select root certificate
        dialog = SelectItemDialog(
            self.root,
            "Select root certificate for client package",
            [(ca["name"], ca["common_name"]) for ca in cas],
        )
        ca_name = dialog.result
        if not ca_name:
            return

        # Get root certificate details
        ca_record = self.storage.get_ca(ca_name)
        if not ca_record:
            messagebox.showerror("Error", "Failed to load root certificate")
            return

        # Select output directory
        from os.path import expanduser

        output_dir = filedialog.askdirectory(
            title="Select output directory", initialdir=expanduser("~")
        )
        if not output_dir:
            return

        try:
            output_path = Path(output_dir)

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
                    output_dir=output_path,
                    ca_name=sanitize_name(ca_record["name"]),
                    ca_common_name=ca_record["common_name"],
                    ca_created_at=ca_record["created_at"],
                    ca_valid_until=ca_record["valid_until"],
                )

                messagebox.showinfo(
                    "Success",
                    f"Client package created successfully\n\n"
                    f"Package: {zip_path}\n\n"
                    f"This package contains the root certificate and installation "
                    f"instructions for end users. It does NOT contain the private key.",
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
            messagebox.showerror("Error", f"Failed to create client package: {e}")

    def _forget_ca(self):
        """Forget (delete) root certificate."""
        if not self.storage:
            return

        cas = self.storage.list_cas()
        if not cas:
            messagebox.showinfo("Info", "No root certificates available")
            return

        # Select root certificate
        dialog = SelectItemDialog(
            self.root,
            "Select root certificate to forget",
            [(ca["name"], ca["common_name"]) for ca in cas],
        )
        ca_name = dialog.result
        if not ca_name:
            return

        # Confirm deletion
        if not messagebox.askyesno(
            "Confirm", f"Are you sure you want to forget root certificate '{ca_name}'?"
        ):
            return

        try:
            self.storage.delete_ca(ca_name)
            self._refresh_ca_list()
            self._refresh_cert_list()
            messagebox.showinfo(
                "Success", f"Root certificate '{ca_name}' has been forgotten"
            )
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to forget root certificate: {e}")

    def _create_certificate(self):
        """Create and sign certificate."""
        if not self.storage:
            return

        cas = self.storage.list_cas()
        if not cas:
            messagebox.showinfo(
                "Info",
                "No root certificates available. Create or import a root certificate first.",
            )
            return

        dialog = CreateCertificateDialog(
            self.root, self.storage, self.config, self.cert_manager, cas
        )
        if dialog.result:
            self._refresh_cert_list()

    def _export_certificate(self):
        """Export certificate and key files."""
        if not self.storage:
            return

        certs = self.storage.list_certificates()
        if not certs:
            messagebox.showinfo("Info", "No certificates available")
            return

        # Select certificate
        dialog = SelectItemDialog(
            self.root,
            "Select certificate to export",
            [(cert["name"], cert["common_name"]) for cert in certs],
        )
        cert_name = dialog.result
        if not cert_name:
            return

        # Get certificate details
        cert_record = self.storage.get_certificate(cert_name)
        if not cert_record:
            messagebox.showerror("Error", "Certificate not found")
            return

        # Select output directory
        from os.path import expanduser

        output_dir = filedialog.askdirectory(
            title="Select output directory", initialdir=expanduser("~")
        )
        if not output_dir:
            return

        try:
            output_path = Path(output_dir)
            base_name = sanitize_name(cert_name)
            cert_file = output_path / f"{base_name}.pem"
            key_file = output_path / f"{base_name}.key"

            # Copy certificate and key files
            import shutil

            cert_path = Path(cert_record["cert_path"])
            key_path = Path(cert_record["key_path"])

            shutil.copy2(cert_path, cert_file)
            shutil.copy2(key_path, key_file)

            messagebox.showinfo(
                "Success", f"Certificate exported to:\n{cert_file}\n{key_file}"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export certificate: {e}")

    def _forget_certificate(self):
        """Forget (delete) certificate."""
        if not self.storage:
            return

        certs = self.storage.list_certificates()
        if not certs:
            messagebox.showinfo("Info", "No certificates available")
            return

        # Select certificate
        dialog = SelectItemDialog(
            self.root,
            "Select certificate to forget",
            [(cert["name"], cert["common_name"]) for cert in certs],
        )
        cert_name = dialog.result
        if not cert_name:
            return

        # Confirm deletion
        if not messagebox.askyesno(
            "Confirm", f"Are you sure you want to forget certificate '{cert_name}'?"
        ):
            return

        try:
            self.storage.delete_certificate(cert_name)
            self._refresh_cert_list()
            messagebox.showinfo(
                "Success", f"Certificate '{cert_name}' has been forgotten"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to forget certificate: {e}")

    def _show_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About",
            "Internal Certificate Manager\n\n"
            "A utility for creating and managing self-signed SSL certificates "
            "for internal devices.",
        )

    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


class PasswordDialog(simpledialog.Dialog):
    """Dialog for entering password."""

    def __init__(self, parent, title):
        self.result = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Password:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.password_entry = ttk.Entry(master, show="*", width=30)
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)
        return self.password_entry

    def apply(self):
        self.result = self.password_entry.get()


class SelectItemDialog(simpledialog.Dialog):
    """Dialog for selecting an item from a list."""

    def __init__(self, parent, title, items):
        self.items = items  # List of (value, label) tuples
        self.result = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Select:").pack(padx=5, pady=5)

        self.listbox = tk.Listbox(master, height=10, width=50)
        self.listbox.pack(padx=5, pady=5)

        for value, label in self.items:
            self.listbox.insert(tk.END, f"{value} - {label}")

        if self.items:
            self.listbox.select_set(0)

        return self.listbox

    def apply(self):
        selection = self.listbox.curselection()
        if selection:
            value, _ = self.items[selection[0]]
            self.result = value


class CreateCADialog(tk.Toplevel):
    """Dialog for creating a new root certificate."""

    def __init__(self, parent, storage, config, cert_manager):
        super().__init__(parent)
        self.title("Create Root Certificate")
        self.storage = storage
        self.config = config
        self.cert_manager = cert_manager
        self.result = False

        self._setup_ui()

        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        self.wait_window()

    def _setup_ui(self):
        """Setup dialog UI."""
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Name
        ttk.Label(frame, text="Name: *").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.name_entry = ttk.Entry(frame, width=40)
        self.name_entry.grid(row=0, column=1, pady=5)

        # Common Name
        ttk.Label(frame, text="Common Name: *").grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        self.cn_entry = ttk.Entry(frame, width=40)
        self.cn_entry.grid(row=1, column=1, pady=5)

        # Organization (optional)
        ttk.Label(frame, text="Organization:").grid(
            row=2, column=0, sticky=tk.W, pady=5
        )
        self.org_entry = ttk.Entry(frame, width=40)
        self.org_entry.grid(row=2, column=1, pady=5)

        # Country (optional)
        ttk.Label(frame, text="Country Code:").grid(
            row=3, column=0, sticky=tk.W, pady=5
        )
        self.country_entry = ttk.Entry(frame, width=40)
        self.country_entry.grid(row=3, column=1, pady=5)

        # Validity days
        ttk.Label(frame, text="Validity (days):").grid(
            row=4, column=0, sticky=tk.W, pady=5
        )
        self.days_entry = ttk.Entry(frame, width=40)
        self.days_entry.insert(0, "3650")
        self.days_entry.grid(row=4, column=1, pady=5)

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Create", command=self._create).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(
            side=tk.LEFT, padx=5
        )

    def _create(self):
        """Create the CA certificate."""
        name = self.name_entry.get().strip()
        common_name = self.cn_entry.get().strip()
        organization = self.org_entry.get().strip() or None
        country = self.country_entry.get().strip() or None

        if not name:
            messagebox.showerror("Error", "Name is required")
            return

        if not common_name:
            messagebox.showerror("Error", "Common Name is required")
            return

        try:
            validity_days = int(self.days_entry.get())
            if validity_days <= 0:
                raise ValueError("Must be positive")
        except ValueError:
            messagebox.showerror("Error", "Validity days must be a positive number")
            return

        if country and len(country) != 2:
            messagebox.showerror("Error", "Country code must be exactly 2 letters")
            return

        try:
            # Generate CA certificate
            cert, key = self.cert_manager.create_ca_certificate(
                common_name=common_name,
                organization=organization,
                country=country,
                validity_days=validity_days,
            )

            # Serialize to PEM
            from cert_manager.certificates import certificate_to_pem, private_key_to_pem

            cert_pem = certificate_to_pem(cert)
            key_pem = private_key_to_pem(key)

            # Store in database
            self.storage.add_ca(
                name=name,
                cert_data=cert_pem,
                key_data=key_pem,
                valid_until=cert.not_valid_after_utc,
                common_name=common_name,
                organization=organization,
                country=country,
            )

            messagebox.showinfo(
                "Success", f"Root certificate '{name}' created successfully"
            )
            self.result = True
            self.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create root certificate: {e}")


class ImportCADialog(tk.Toplevel):
    """Dialog for importing an existing root certificate."""

    def __init__(self, parent, storage, config):
        super().__init__(parent)
        self.title("Import Root Certificate")
        self.storage = storage
        self.config = config
        self.result = False

        self.cert_path = None
        self.key_path = None

        self._setup_ui()

        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        self.wait_window()

    def _setup_ui(self):
        """Setup dialog UI."""
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Name
        ttk.Label(frame, text="Name: *").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.name_entry = ttk.Entry(frame, width=40)
        self.name_entry.grid(row=0, column=1, pady=5)

        # Certificate file
        ttk.Label(frame, text="Certificate: *").grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        self.cert_label = ttk.Label(frame, text="No file selected", foreground="gray")
        self.cert_label.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Button(frame, text="Browse...", command=self._browse_cert).grid(
            row=1, column=2, padx=5
        )

        # Key file
        ttk.Label(frame, text="Private Key: *").grid(
            row=2, column=0, sticky=tk.W, pady=5
        )
        self.key_label = ttk.Label(frame, text="No file selected", foreground="gray")
        self.key_label.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Button(frame, text="Browse...", command=self._browse_key).grid(
            row=2, column=2, padx=5
        )

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)

        ttk.Button(button_frame, text="Import", command=self._import).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(
            side=tk.LEFT, padx=5
        )

    def _browse_cert(self):
        """Browse for certificate file."""
        from os.path import expanduser

        path = filedialog.askopenfilename(
            title="Select root certificate",
            filetypes=[("PEM files", "*.pem *.crt"), ("All files", "*.*")],
            initialdir=expanduser("~"),
        )
        if path:
            self.cert_path = Path(path)
            self.cert_label.config(text=self.cert_path.name, foreground="black")

    def _browse_key(self):
        """Browse for private key file."""
        from os.path import expanduser

        path = filedialog.askopenfilename(
            title="Select root certificate private key",
            filetypes=[("PEM files", "*.pem *.key"), ("All files", "*.*")],
            initialdir=expanduser("~"),
        )
        if path:
            self.key_path = Path(path)
            self.key_label.config(text=self.key_path.name, foreground="black")

    def _import(self):
        """Import the CA certificate."""
        name = self.name_entry.get().strip()

        if not name:
            messagebox.showerror("Error", "Name is required")
            return

        if not self.cert_path or not self.key_path:
            messagebox.showerror(
                "Error", "Both certificate and private key files are required"
            )
            return

        try:
            # Load files
            cert_pem = self.cert_path.read_bytes()
            key_pem = self.key_path.read_bytes()

            # Validate by loading
            cert = CertificateManager.load_certificate_from_pem(cert_pem)
            CertificateManager.load_private_key_from_pem(key_pem)

            # Extract metadata
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

            # Store in database
            self.storage.add_ca(
                name=name,
                cert_data=cert_pem,
                key_data=key_pem,
                valid_until=cert.not_valid_after_utc,
                common_name=common_name,
                organization=organization,
                country=country,
            )

            messagebox.showinfo(
                "Success", f"Root certificate '{name}' imported successfully"
            )
            self.result = True
            self.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to import root certificate: {e}")


class CreateCertificateDialog(tk.Toplevel):
    """Dialog for creating and signing a certificate."""

    def __init__(self, parent, storage, config, cert_manager, cas):
        super().__init__(parent)
        self.title("Create Certificate")
        self.geometry("600x500")
        self.storage = storage
        self.config = config
        self.cert_manager = cert_manager
        self.cas = cas
        self.result = False

        self._setup_ui()

        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        self.wait_window()

    def _setup_ui(self):
        """Setup dialog UI."""
        # Create scrollable frame
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        frame = ttk.Frame(scrollable_frame, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        row = 0

        # Root certificate selection
        ttk.Label(frame, text="Root Certificate:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        self.ca_var = tk.StringVar()
        ca_choices = [f"{ca['name']} - {ca['common_name']}" for ca in self.cas]
        self.ca_combo = ttk.Combobox(
            frame,
            textvariable=self.ca_var,
            values=ca_choices,
            width=37,
            state="readonly",
        )
        if ca_choices:
            self.ca_combo.current(0)
        self.ca_combo.grid(row=row, column=1, pady=5)
        row += 1

        # Name
        ttk.Label(frame, text="Name: *").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.name_entry = ttk.Entry(frame, width=40)
        self.name_entry.grid(row=row, column=1, pady=5)
        row += 1

        # Common Name
        ttk.Label(frame, text="Common Name: *").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        self.cn_entry = ttk.Entry(frame, width=40)
        self.cn_entry.grid(row=row, column=1, pady=5)
        row += 1

        # Organization (optional)
        ttk.Label(frame, text="Organization:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        self.org_entry = ttk.Entry(frame, width=40)
        self.org_entry.grid(row=row, column=1, pady=5)
        row += 1

        # Country (optional)
        ttk.Label(frame, text="Country Code:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        self.country_entry = ttk.Entry(frame, width=40)
        self.country_entry.grid(row=row, column=1, pady=5)
        row += 1

        # Validity days
        ttk.Label(frame, text="Validity (days):").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        self.days_entry = ttk.Entry(frame, width=40)
        self.days_entry.insert(0, "1825")
        self.days_entry.grid(row=row, column=1, pady=5)
        row += 1

        # SAN DNS (optional)
        ttk.Label(frame, text="SAN DNS Names:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        ttk.Label(frame, text="(comma-separated)", font=("", 8)).grid(
            row=row, column=1, sticky=tk.W
        )
        row += 1
        self.san_dns_entry = ttk.Entry(frame, width=40)
        self.san_dns_entry.grid(row=row, column=1, pady=5)
        row += 1

        # SAN IP (optional)
        ttk.Label(frame, text="SAN IP Addresses:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        ttk.Label(frame, text="(comma-separated)", font=("", 8)).grid(
            row=row, column=1, sticky=tk.W
        )
        row += 1
        self.san_ip_entry = ttk.Entry(frame, width=40)
        self.san_ip_entry.grid(row=row, column=1, pady=5)
        row += 1

        # Buttons at bottom (pack first so they stay at bottom)
        button_frame = ttk.Frame(self)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)

        # Center the buttons
        inner_button_frame = ttk.Frame(button_frame)
        inner_button_frame.pack(expand=True)

        ttk.Button(inner_button_frame, text="Create", command=self._create).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(inner_button_frame, text="Cancel", command=self.destroy).pack(
            side=tk.LEFT, padx=5
        )

        # Pack canvas and scrollbar (after buttons so they fill remaining space)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _create(self):
        """Create the certificate."""
        # Get root certificate
        ca_selection = self.ca_combo.get()
        if not ca_selection:
            messagebox.showerror("Error", "Please select a root certificate")
            return

        ca_name = ca_selection.split(" - ")[0]
        ca_record = self.storage.get_ca(ca_name)
        if not ca_record:
            messagebox.showerror("Error", "Failed to load root certificate")
            return

        # Get values
        name = self.name_entry.get().strip()
        common_name = self.cn_entry.get().strip()
        organization = self.org_entry.get().strip() or None
        country = self.country_entry.get().strip() or None
        san_dns_raw = self.san_dns_entry.get().strip()
        san_ip_raw = self.san_ip_entry.get().strip()

        if not name:
            messagebox.showerror("Error", "Name is required")
            return

        if not common_name:
            messagebox.showerror("Error", "Common Name is required")
            return

        try:
            validity_days = int(self.days_entry.get())
            if validity_days <= 0:
                raise ValueError("Must be positive")
        except ValueError:
            messagebox.showerror("Error", "Validity days must be a positive number")
            return

        if country and len(country) != 2:
            messagebox.showerror("Error", "Country code must be exactly 2 letters")
            return

        # Parse SAN DNS
        san_dns = None
        if san_dns_raw:
            san_dns = [s.strip() for s in san_dns_raw.split(",") if s.strip()]

        # Parse and validate SAN IP
        san_ip = None
        if san_ip_raw:
            try:
                san_ip = []
                for ip in san_ip_raw.split(","):
                    ip = ip.strip()
                    if ip:
                        ipaddress.ip_address(ip)  # Validate
                        san_ip.append(ip)
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid IP address: {e}")
                return

        try:
            # Show progress
            progress = ProgressDialog(self, "Creating certificate...")

            def create_cert():
                try:
                    # Load CA
                    ca_cert = CertificateManager.load_certificate_from_pem(
                        ca_record["cert_data"]
                    )
                    ca_key = CertificateManager.load_private_key_from_pem(
                        ca_record["key_data"]
                    )

                    # Generate certificate
                    cert, key = self.cert_manager.create_certificate(
                        common_name=common_name,
                        ca_cert=ca_cert,
                        ca_key=ca_key,
                        san_dns=san_dns,
                        san_ip=san_ip,
                        organization=organization,
                        country=country,
                        validity_days=validity_days,
                    )

                    # Save to files
                    file_name = sanitize_name(name)
                    cert_path = self.config.certs_dir / f"{file_name}.pem"
                    key_path = self.config.certs_dir / f"{file_name}.key"

                    self.cert_manager.save_certificate(cert, cert_path)
                    self.cert_manager.save_private_key(key, key_path)

                    # Store in database
                    self.storage.add_certificate(
                        name=name,
                        common_name=common_name,
                        cert_path=cert_path,
                        key_path=key_path,
                        ca_id=ca_record["id"],
                        valid_until=cert.not_valid_after_utc,
                        san_dns=san_dns,
                        san_ip=san_ip,
                        organization=organization,
                        country=country,
                    )

                    # Create deployment packages
                    ca_cert_path = ca_record.get("cert_path")
                    temp_ca_file = None

                    if not ca_cert_path:
                        # CA stored in database, create temp file
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
                            san_dns=san_dns,
                            san_ip=san_ip,
                        )
                    finally:
                        if temp_ca_file:
                            import os

                            try:
                                os.unlink(temp_ca_file.name)
                            except Exception:
                                pass

                    self.after(
                        0,
                        lambda: progress.close(
                            success=True,
                            message=f"Certificate '{name}' created successfully\n\n"
                            f"Certificate: {cert_path}\n"
                            f"Private Key: {key_path}\n"
                            f"Server package: {server_zip}\n"
                            f"Client package: {client_zip}",
                        ),
                    )

                except Exception as e:
                    error_msg = str(e)
                    self.after(
                        0, lambda: progress.close(success=False, message=error_msg)
                    )

            # Run in thread
            thread = threading.Thread(target=create_cert, daemon=True)
            thread.start()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create certificate: {e}")


class ProgressDialog(tk.Toplevel):
    """Progress dialog for long-running operations."""

    def __init__(self, parent, message):
        super().__init__(parent)
        self.title("Please wait")
        self.geometry("400x100")
        self.resizable(False, False)

        ttk.Label(self, text=message).pack(pady=20)

        progress = ttk.Progressbar(self, mode="indeterminate")
        progress.pack(fill=tk.X, padx=20, pady=10)
        progress.start(10)

        # Make dialog modal
        self.transient(parent)
        self.grab_set()

        # Center on parent
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

    def close(self, success=True, message=""):
        """Close the dialog and show result."""
        self.destroy()

        if success:
            messagebox.showinfo("Success", message)
            # Set result on parent if it's a dialog
            if hasattr(self.master, "result"):
                self.master.result = True
                self.master.destroy()
        else:
            messagebox.showerror("Error", f"Operation failed: {message}")


def main():
    """Run the GUI application."""
    app = CertificateManagerGUI()
    app.run()


if __name__ == "__main__":
    main()
