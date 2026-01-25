# GUI launcher for Internal Certificate Manager (PowerShell)
# This script checks dependencies, sets up virtual environment, and launches the GUI

# Ensure script stops on errors
$ErrorActionPreference = "Stop"

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "==> " -ForegroundColor Blue -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Error-Message {
    param([string]$Message)
    Write-Host "✗ " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

# Function to check if command exists
function Test-Command {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# Function to compare versions
function Test-VersionGreaterOrEqual {
    param(
        [string]$Version1,
        [string]$Version2
    )
    [version]$Version1 -ge [version]$Version2
}

Write-Host ""
Write-Status "Internal Certificate Manager - GUI"
Write-Host ""

# Check for Python 3
Write-Status "Checking for Python..."
$PythonCmd = $null

# Try python3 first, then python, then py
$PythonCommands = @("python3", "python", "py")
foreach ($cmd in $PythonCommands) {
    if (Test-Command $cmd) {
        try {
            $version = & $cmd --version 2>&1 | Select-String -Pattern "Python (\d+\.\d+\.\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }
            if ($version -like "3.*") {
                $PythonCmd = $cmd
                $PythonVersion = $version
                break
            }
        } catch {
            continue
        }
    }
}

if (-not $PythonCmd) {
    Write-Error-Message "Python 3 is not installed or not in PATH"
    Write-Host "  Please install Python 3.8 or later from https://www.python.org/"
    exit 1
}

$PythonPath = (Get-Command $PythonCmd).Source
Write-Success "Found Python $PythonVersion at $PythonPath"

# Check Python version is 3.8+
if (-not (Test-VersionGreaterOrEqual $PythonVersion "3.8.0")) {
    Write-Error-Message "Python 3.8 or later is required (found $PythonVersion)"
    exit 1
}

# Check for OpenSSL
Write-Status "Checking for OpenSSL..."
if (Test-Command openssl) {
    $OpenSSLVersion = (& openssl version).Split()[1]
    Write-Success "Found OpenSSL $OpenSSLVersion"
} else {
    Write-Warning "OpenSSL not found in PATH"
    Write-Host "  OpenSSL is recommended but not strictly required for runtime"
    Write-Host "  The Python cryptography library will use its bundled OpenSSL"
}

# Check for virtual environment
Write-Status "Checking for virtual environment..."
if (Test-Path ".venv") {
    Write-Success "Virtual environment exists"
} else {
    Write-Status "Creating virtual environment..."
    & $PythonCmd -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Message "Failed to create virtual environment"
        exit 1
    }
    Write-Success "Virtual environment created"
}

# Activate virtual environment
Write-Status "Activating virtual environment..."
$ActivateScript = ".venv\Scripts\Activate.ps1"
if (Test-Path $ActivateScript) {
    & $ActivateScript
    Write-Success "Virtual environment activated"
} else {
    Write-Error-Message "Failed to find activation script at $ActivateScript"
    exit 1
}

# Verify we're in the virtual environment
if (-not $env:VIRTUAL_ENV) {
    Write-Error-Message "Failed to activate virtual environment"
    exit 1
}

# Upgrade pip
Write-Status "Upgrading pip..."
& python -m pip install --upgrade pip --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to upgrade pip (continuing anyway)"
}
Write-Success "pip upgraded"

# Check if requirements need to be installed/upgraded
Write-Status "Checking requirements..."
$RequirementsFile = "requirements.txt"

if (-not (Test-Path $RequirementsFile)) {
    Write-Error-Message "requirements.txt not found"
    exit 1
}

# Check if requirements are already satisfied
$NeedsInstall = $false

# Try to check if packages are installed
try {
    & python -c "import cryptography, prompt_toolkit, PIL" 2>$null
    if ($LASTEXITCODE -ne 0) {
        $NeedsInstall = $true
    }
} catch {
    $NeedsInstall = $true
}

if ($NeedsInstall) {
    Write-Status "Installing requirements..."
    & pip install -r $RequirementsFile
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Message "Failed to install requirements"
        exit 1
    }
    Write-Success "Requirements installed"
} else {
    Write-Status "Checking for requirement updates..."
    # Check for outdated packages
    $Outdated = & pip list --outdated --format=columns 2>$null | Select-String -Pattern "(cryptography|prompt-toolkit|Pillow)"
    if ($Outdated) {
        Write-Status "Upgrading outdated packages..."
        & pip install --upgrade -r $RequirementsFile
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Some packages failed to upgrade (continuing anyway)"
        }
        Write-Success "Requirements upgraded"
    } else {
        Write-Success "All requirements are up to date"
    }
}

# Launch GUI
Write-Host ""
Write-Status "Launching GUI..."
Write-Host ""
& python -m cert_manager.gui
