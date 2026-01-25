"""Tests for GUI components."""

import pytest
import tkinter as tk
from unittest.mock import Mock, patch
from cert_manager.gui import (
    CertificateManagerGUI,
    PasswordDialog,
    SelectItemDialog,
    CreateCADialog,
)


@pytest.fixture
def root():
    """Create a Tk root for testing."""
    root = tk.Tk()
    yield root
    try:
        root.destroy()
    except Exception:
        pass


def test_password_dialog_basic(root):
    """Test PasswordDialog basic functionality."""
    with patch.object(PasswordDialog, "wait_window"):
        dialog = PasswordDialog(root, "Test Password")
        dialog.password_entry.insert(0, "test123")
        dialog.apply()
        assert dialog.result == "test123"


def test_password_dialog_empty(root):
    """Test PasswordDialog with empty password."""
    with patch.object(PasswordDialog, "wait_window"):
        dialog = PasswordDialog(root, "Test Password")
        dialog.apply()
        assert dialog.result == ""


def test_select_item_dialog_basic(root):
    """Test SelectItemDialog basic functionality."""
    items = [("ca1", "CA One"), ("ca2", "CA Two")]

    with patch.object(SelectItemDialog, "wait_window"):
        dialog = SelectItemDialog(root, "Select Item", items)
        dialog.listbox.selection_clear(0)  # Clear default selection
        dialog.listbox.select_set(1)
        dialog.apply()
        assert dialog.result == "ca2"


def test_select_item_dialog_no_selection(root):
    """Test SelectItemDialog with no selection."""
    items = [("ca1", "CA One")]

    with patch.object(SelectItemDialog, "wait_window"):
        dialog = SelectItemDialog(root, "Select Item", items)
        dialog.listbox.selection_clear(0)
        dialog.apply()
        assert dialog.result is None


def test_select_item_dialog_empty_list(root):
    """Test SelectItemDialog with empty list."""
    with patch.object(SelectItemDialog, "wait_window"):
        dialog = SelectItemDialog(root, "Select Item", [])
        assert dialog.listbox.size() == 0


@patch("cert_manager.gui.CertificateStorage")
@patch("cert_manager.gui.messagebox")
def test_gui_initialization_cancelled(mock_msgbox, mock_storage, tmp_path):
    """Test GUI initialization when password dialog is cancelled."""
    with patch("cert_manager.gui.PasswordDialog") as mock_dialog:
        mock_dialog.return_value.result = None  # User cancelled

        with patch.object(CertificateManagerGUI, "_setup_ui"):
            with patch.object(CertificateManagerGUI, "_init_storage") as mock_init:
                mock_root = Mock()

                with patch("tkinter.Tk", return_value=mock_root):
                    CertificateManagerGUI()

                    # _init_storage should have been called
                    mock_init.assert_called_once()


@patch("cert_manager.gui.messagebox")
@patch("cert_manager.gui.CertificateStorage")
def test_gui_show_about(mock_storage, mock_msgbox):
    """Test about dialog."""
    with patch("cert_manager.gui.PasswordDialog") as mock_dialog:
        mock_dialog.return_value.result = "test123"

        with patch.object(CertificateManagerGUI, "_setup_ui"):
            with patch.object(CertificateManagerGUI, "_init_storage"):
                mock_root = Mock()

                with patch("tkinter.Tk", return_value=mock_root):
                    gui = CertificateManagerGUI()
                    gui._show_about()
                    mock_msgbox.showinfo.assert_called_once()
                    args = mock_msgbox.showinfo.call_args[0]
                    assert "About" in args[0]
                    assert "Internal Certificate Manager" in args[1]


def test_create_ca_dialog_validation(root, tmp_path):
    """Test CreateCADialog input validation."""
    mock_storage = Mock()
    mock_config = Mock()
    mock_config.output_dir = tmp_path
    mock_cert_manager = Mock()

    with patch.object(CreateCADialog, "wait_window"):
        with patch("cert_manager.gui.messagebox") as mock_msgbox:
            dialog = CreateCADialog(root, mock_storage, mock_config, mock_cert_manager)

            # Test empty name
            dialog.name_entry.insert(0, "")
            dialog.cn_entry.insert(0, "Test CA")
            dialog._create()
            mock_msgbox.showerror.assert_called_with("Error", "Name is required")

            # Reset mock
            mock_msgbox.reset_mock()

            # Test empty common name
            dialog.name_entry.delete(0, tk.END)
            dialog.name_entry.insert(0, "testca")
            dialog.cn_entry.delete(0, tk.END)
            dialog._create()
            mock_msgbox.showerror.assert_called_with("Error", "Common Name is required")


def test_create_ca_dialog_country_validation(root, tmp_path):
    """Test CreateCADialog country code validation."""
    mock_storage = Mock()
    mock_config = Mock()
    mock_config.output_dir = tmp_path
    mock_cert_manager = Mock()

    with patch.object(CreateCADialog, "wait_window"):
        with patch("cert_manager.gui.messagebox") as mock_msgbox:
            dialog = CreateCADialog(root, mock_storage, mock_config, mock_cert_manager)

            dialog.name_entry.insert(0, "testca")
            dialog.cn_entry.insert(0, "Test CA")
            dialog.country_entry.insert(0, "USA")  # Should be 2 letters
            dialog._create()

            mock_msgbox.showerror.assert_called_with(
                "Error", "Country code must be exactly 2 letters"
            )


def test_create_ca_dialog_validity_validation(root, tmp_path):
    """Test CreateCADialog validity days validation."""
    mock_storage = Mock()
    mock_config = Mock()
    mock_config.output_dir = tmp_path
    mock_cert_manager = Mock()

    with patch.object(CreateCADialog, "wait_window"):
        with patch("cert_manager.gui.messagebox") as mock_msgbox:
            dialog = CreateCADialog(root, mock_storage, mock_config, mock_cert_manager)

            dialog.name_entry.insert(0, "testca")
            dialog.cn_entry.insert(0, "Test CA")
            dialog.days_entry.delete(0, tk.END)
            dialog.days_entry.insert(0, "invalid")
            dialog._create()

            mock_msgbox.showerror.assert_called_with(
                "Error", "Validity days must be a positive number"
            )

            # Reset and test negative number
            mock_msgbox.reset_mock()
            dialog.days_entry.delete(0, tk.END)
            dialog.days_entry.insert(0, "-10")
            dialog._create()

            mock_msgbox.showerror.assert_called_with(
                "Error", "Validity days must be a positive number"
            )
