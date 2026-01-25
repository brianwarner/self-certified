"""Tests for CLI helper functions."""

from cert_manager.cli import sanitize_name


def test_sanitize_name_basic():
    """Test basic name sanitization."""
    assert sanitize_name("my-server") == "my_server"
    assert sanitize_name("MyServer") == "myserver"
    assert sanitize_name("my_server") == "my_server"


def test_sanitize_name_special_characters():
    """Test sanitization of special characters."""
    assert sanitize_name("server@home.local") == "server_home_local"
    assert sanitize_name("server (production)") == "server_production"
    assert sanitize_name("server#1") == "server_1"
    assert sanitize_name("my-server.test") == "my_server_test"


def test_sanitize_name_multiple_special_chars():
    """Test multiple consecutive special characters."""
    assert sanitize_name("server---test") == "server_test"
    assert sanitize_name("server   test") == "server_test"
    assert sanitize_name("server@@@test") == "server_test"


def test_sanitize_name_leading_trailing():
    """Test removal of leading/trailing underscores."""
    assert sanitize_name("_server") == "server"
    assert sanitize_name("server_") == "server"
    assert sanitize_name("_server_") == "server"
    assert sanitize_name("-server-") == "server"


def test_sanitize_name_numbers():
    """Test that numbers are preserved."""
    assert sanitize_name("server123") == "server123"
    assert sanitize_name("123server") == "123server"
    assert sanitize_name("server-123") == "server_123"


def test_sanitize_name_case_conversion():
    """Test case conversion to lowercase."""
    assert sanitize_name("UPPERCASE") == "uppercase"
    assert sanitize_name("MixedCase") == "mixedcase"
    assert sanitize_name("camelCase") == "camelcase"


def test_sanitize_name_empty_and_edge_cases():
    """Test edge cases."""
    assert sanitize_name("") == ""
    assert sanitize_name("a") == "a"
    assert sanitize_name("123") == "123"
    assert sanitize_name("___") == ""
