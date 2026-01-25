#!/usr/bin/env bash
# GUI launcher for Internal Certificate Manager
# This script checks dependencies, sets up virtual environment, and launches the GUI

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get Python version
get_python_version() {
    "$1" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

# Function to compare versions (returns 0 if version1 >= version2)
version_gte() {
    printf '%s\n%s' "$2" "$1" | sort -V -C
}

echo ""
print_status "Internal Certificate Manager - GUI"
echo ""

# Check for Python 3
print_status "Checking for Python..."
PYTHON_CMD=""

if command_exists python3; then
    PYTHON_CMD="python3"
elif command_exists python; then
    # Check if python is Python 3
    PYTHON_VERSION=$(get_python_version python)
    if [[ "$PYTHON_VERSION" == 3.* ]]; then
        PYTHON_CMD="python"
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    print_error "Python 3 is not installed or not in PATH"
    echo "  Please install Python 3.8 or later from https://www.python.org/"
    exit 1
fi

PYTHON_VERSION=$(get_python_version "$PYTHON_CMD")
print_success "Found Python $PYTHON_VERSION at $(which $PYTHON_CMD)"

# Check Python version is 3.8+
if ! version_gte "$PYTHON_VERSION" "3.8.0"; then
    print_error "Python 3.8 or later is required (found $PYTHON_VERSION)"
    exit 1
fi

# Check for OpenSSL
print_status "Checking for OpenSSL..."
if command_exists openssl; then
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    print_success "Found OpenSSL $OPENSSL_VERSION"
else
    print_warning "OpenSSL not found in PATH"
    echo "  OpenSSL is recommended but not strictly required for runtime"
    echo "  The Python cryptography library will use its bundled OpenSSL"
fi

# Check for virtual environment
print_status "Checking for virtual environment..."
if [ -d ".venv" ]; then
    print_success "Virtual environment exists"
else
    print_status "Creating virtual environment..."
    "$PYTHON_CMD" -m venv .venv
    print_success "Virtual environment created"
fi

# Activate virtual environment
print_status "Activating virtual environment..."
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    print_success "Virtual environment activated"
else
    print_error "Failed to find activation script"
    exit 1
fi

# Verify we're in the virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    print_error "Failed to activate virtual environment"
    exit 1
fi

# Upgrade pip
print_status "Upgrading pip..."
python -m pip install --upgrade pip --quiet
print_success "pip upgraded"

# Check if requirements need to be installed/upgraded
print_status "Checking requirements..."
REQUIREMENTS_FILE="requirements.txt"

if [ ! -f "$REQUIREMENTS_FILE" ]; then
    print_error "requirements.txt not found"
    exit 1
fi

# Check if requirements are already satisfied
NEEDS_INSTALL=false

# Try to check if packages are installed
if ! python -c "import cryptography, prompt_toolkit, PIL" 2>/dev/null; then
    NEEDS_INSTALL=true
fi

if [ "$NEEDS_INSTALL" = true ]; then
    print_status "Installing requirements..."
    pip install -r "$REQUIREMENTS_FILE"
    print_success "Requirements installed"
else
    # Check for outdated packages
    OUTDATED=$(pip list --outdated --format=columns 2>/dev/null | grep -E '(cryptography|prompt-toolkit|Pillow)' || true)
    if [ -n "$OUTDATED" ]; then
        print_status "Upgrading outdated packages..."
        pip install --upgrade -r "$REQUIREMENTS_FILE"
        print_success "Requirements upgraded"
    else
        print_success "All requirements are up to date"
    fi
fi

# Launch GUI
echo ""
print_status "Launching GUI..."
echo ""
python -m cert_manager.gui
