#!/bin/bash
#
# GlobalConnect/GlobalDetect Installation Script
#
# Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
# All rights reserved.
#
# Usage:
#   ./install.sh              # Install to virtual environment in current directory
#   ./install.sh --venv       # Install to virtual environment (explicit)
#   ./install.sh --system     # Install to /usr/local/globaldetect (requires sudo)
#   ./install.sh --user       # Install to ~/.local/globaldetect
#   ./install.sh --help       # Show help
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_NAME="dnsscience-globalconnect"
SYSTEM_INSTALL_DIR="/usr/local/globaldetect"
USER_INSTALL_DIR="${HOME}/.local/globaldetect"
MIN_PYTHON_VERSION="3.10"

# Command aliases to create
COMMANDS=(
    "dnsscience-globalconnect"
    "globalconnect"
    "dnsscience-globaldetect"
    "globaldetect"
)

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show usage
show_help() {
    cat << EOF
GlobalConnect/GlobalDetect Installation Script

Usage: $0 [OPTIONS]

Options:
    --venv          Install to virtual environment in current directory (default)
    --system        Install to /usr/local/globaldetect (requires sudo)
    --user          Install to ~/.local/globaldetect (no sudo required)
    --extras EXTRA  Install optional extras (dev, enterprise, server, backup, all)
    --uninstall     Uninstall from specified location
    --help          Show this help message

Examples:
    $0                          # Install to ./venv
    $0 --venv                   # Install to ./venv (explicit)
    $0 --system                 # Install to /usr/local/globaldetect
    $0 --system --extras all    # System install with all extras
    $0 --user                   # Install to ~/.local/globaldetect
    $0 --uninstall --system     # Uninstall from /usr/local

After installation, the following commands will be available:
    - dnsscience-globalconnect  (primary)
    - globalconnect             (alias)
    - dnsscience-globaldetect   (alias)
    - globaldetect              (alias)

EOF
}

# Check Python version
check_python() {
    print_info "Checking Python version..."

    # Find Python 3.10+
    PYTHON_CMD=""
    for cmd in python3.12 python3.11 python3.10 python3 python; do
        if command -v "$cmd" &> /dev/null; then
            version=$($cmd -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
            major=$(echo "$version" | cut -d. -f1)
            minor=$(echo "$version" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
                PYTHON_CMD="$cmd"
                print_success "Found Python $version ($cmd)"
                break
            fi
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        print_error "Python ${MIN_PYTHON_VERSION}+ is required but not found"
        print_info "Please install Python ${MIN_PYTHON_VERSION} or later"
        exit 1
    fi
}

# Get the directory where this script is located
get_script_dir() {
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
}

# Install to virtual environment
install_venv() {
    local venv_dir="${1:-venv}"
    local extras="$2"

    print_info "Installing to virtual environment: $venv_dir"

    # Create venv if it doesn't exist
    if [ ! -d "$venv_dir" ]; then
        print_info "Creating virtual environment..."
        $PYTHON_CMD -m venv "$venv_dir"
    fi

    # Activate and install
    source "$venv_dir/bin/activate"

    print_info "Upgrading pip..."
    pip install --upgrade pip wheel setuptools > /dev/null

    print_info "Installing package..."
    if [ -n "$extras" ]; then
        pip install -e ".[${extras}]"
    else
        pip install -e .
    fi

    print_success "Installation complete!"
    echo ""
    print_info "To use, activate the virtual environment:"
    echo "    source $venv_dir/bin/activate"
    echo ""
    print_info "Then run:"
    echo "    globalconnect --help"
    echo "    globaldetect --help"
}

# Install to system location
install_system() {
    local install_dir="$1"
    local extras="$2"
    local need_sudo="$3"
    local sudo_cmd=""

    if [ "$need_sudo" = "yes" ]; then
        sudo_cmd="sudo"
        print_info "Installing to $install_dir (requires sudo)"
    else
        print_info "Installing to $install_dir"
    fi

    # Create installation directory
    if [ ! -d "$install_dir" ]; then
        print_info "Creating installation directory..."
        $sudo_cmd mkdir -p "$install_dir"
    fi

    # Create virtual environment in install dir
    local venv_dir="$install_dir/venv"
    if [ ! -d "$venv_dir" ]; then
        print_info "Creating virtual environment..."
        $sudo_cmd $PYTHON_CMD -m venv "$venv_dir"
    fi

    # Install package
    print_info "Installing package..."
    if [ "$need_sudo" = "yes" ]; then
        sudo "$venv_dir/bin/pip" install --upgrade pip wheel setuptools > /dev/null
        if [ -n "$extras" ]; then
            sudo "$venv_dir/bin/pip" install ".[${extras}]"
        else
            sudo "$venv_dir/bin/pip" install .
        fi
    else
        "$venv_dir/bin/pip" install --upgrade pip wheel setuptools > /dev/null
        if [ -n "$extras" ]; then
            "$venv_dir/bin/pip" install ".[${extras}]"
        else
            "$venv_dir/bin/pip" install .
        fi
    fi

    # Create symlinks
    create_symlinks "$install_dir" "$need_sudo"

    print_success "Installation complete!"
    echo ""
    print_info "The following commands are now available:"
    for cmd in "${COMMANDS[@]}"; do
        if [ "$need_sudo" = "yes" ]; then
            echo "    /usr/local/bin/$cmd"
        else
            echo "    ~/.local/bin/$cmd"
        fi
    done
}

# Create symlinks to /usr/local/bin or ~/.local/bin
create_symlinks() {
    local install_dir="$1"
    local need_sudo="$2"
    local sudo_cmd=""
    local bin_dir="/usr/local/bin"

    if [ "$need_sudo" = "yes" ]; then
        sudo_cmd="sudo"
        bin_dir="/usr/local/bin"
    else
        bin_dir="${HOME}/.local/bin"
        mkdir -p "$bin_dir"
    fi

    print_info "Creating command symlinks in $bin_dir..."

    for cmd in "${COMMANDS[@]}"; do
        local target="$bin_dir/$cmd"
        local source="$install_dir/venv/bin/$cmd"

        # Remove existing symlink if present
        if [ -L "$target" ] || [ -e "$target" ]; then
            $sudo_cmd rm -f "$target"
        fi

        # Create new symlink
        $sudo_cmd ln -s "$source" "$target"
        print_success "Created: $target -> $source"
    done
}

# Uninstall
uninstall() {
    local install_dir="$1"
    local need_sudo="$2"
    local sudo_cmd=""
    local bin_dir="/usr/local/bin"

    if [ "$need_sudo" = "yes" ]; then
        sudo_cmd="sudo"
        bin_dir="/usr/local/bin"
    else
        bin_dir="${HOME}/.local/bin"
    fi

    print_info "Uninstalling from $install_dir..."

    # Remove symlinks
    print_info "Removing command symlinks..."
    for cmd in "${COMMANDS[@]}"; do
        local target="$bin_dir/$cmd"
        if [ -L "$target" ]; then
            $sudo_cmd rm -f "$target"
            print_success "Removed: $target"
        fi
    done

    # Remove installation directory
    if [ -d "$install_dir" ]; then
        print_info "Removing installation directory..."
        $sudo_cmd rm -rf "$install_dir"
        print_success "Removed: $install_dir"
    fi

    print_success "Uninstallation complete!"
}

# Main
main() {
    local mode="venv"
    local extras=""
    local do_uninstall="no"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --venv)
                mode="venv"
                shift
                ;;
            --system)
                mode="system"
                shift
                ;;
            --user)
                mode="user"
                shift
                ;;
            --extras)
                extras="$2"
                shift 2
                ;;
            --uninstall)
                do_uninstall="yes"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    echo ""
    echo "=============================================="
    echo "  GlobalConnect/GlobalDetect Installer"
    echo "  DNS Science.io - After Dark Systems, LLC"
    echo "=============================================="
    echo ""

    # Get script directory
    get_script_dir
    cd "$SCRIPT_DIR"

    # Check Python
    check_python

    # Handle uninstall
    if [ "$do_uninstall" = "yes" ]; then
        case $mode in
            system)
                uninstall "$SYSTEM_INSTALL_DIR" "yes"
                ;;
            user)
                uninstall "$USER_INSTALL_DIR" "no"
                ;;
            venv)
                print_info "To uninstall venv, simply delete the venv directory"
                ;;
        esac
        exit 0
    fi

    # Handle install
    case $mode in
        venv)
            install_venv "venv" "$extras"
            ;;
        system)
            install_system "$SYSTEM_INSTALL_DIR" "$extras" "yes"
            ;;
        user)
            install_system "$USER_INSTALL_DIR" "$extras" "no"
            ;;
    esac
}

main "$@"
