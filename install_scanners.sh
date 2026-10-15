#!/bin/bash

###############################################################################
# KeyTrap Scanner Installation Script
# Installs optional scanner binaries: trufflehog and gitleaks
# Platform-aware: macOS (Homebrew), Linux, Windows (WSL)
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if grep -qi microsoft /proc/version; then
            echo "wsl"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install on macOS using Homebrew
install_macos() {
    print_header "Installing scanners on macOS"
    
    # Check if Homebrew is installed
    if ! command_exists brew; then
        print_error "Homebrew not installed. Install from: https://brew.sh"
        print_info "Then run this script again."
        return 1
    fi
    
    # Install gitleaks
    if ! command_exists gitleaks; then
        print_info "Installing gitleaks..."
        brew install gitleaks
        print_success "gitleaks installed"
    else
        print_success "gitleaks already installed"
    fi
    
    # Install trufflehog
    if ! command_exists trufflehog; then
        print_info "Installing trufflehog..."
        brew install trufflehog
        print_success "trufflehog installed"
    else
        print_success "trufflehog already installed"
    fi
}

# Install on Linux
install_linux() {
    print_header "Installing scanners on Linux"
    
    # Detect if it's a Debian-based system
    if command_exists apt-get; then
        print_info "Detected apt-based system"
        
        # Install gitleaks
        if ! command_exists gitleaks; then
            print_info "Installing gitleaks..."
            GITLEAKS_VERSION="8.18.0"
            GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-x64"
            
            if command_exists wget; then
                wget -q "$GITLEAKS_URL" -O /tmp/gitleaks
            elif command_exists curl; then
                curl -sL "$GITLEAKS_URL" -o /tmp/gitleaks
            else
                print_error "Neither wget nor curl found. Install one and try again."
                return 1
            fi
            
            chmod +x /tmp/gitleaks
            sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
            print_success "gitleaks installed"
        else
            print_success "gitleaks already installed"
        fi
        
        # Install trufflehog via pip (recommended for Linux)
        if ! command_exists trufflehog; then
            print_info "Installing trufflehog..."
            if command_exists pip3; then
                pip3 install truffleHog3
                print_success "trufflehog installed"
            else
                print_error "pip3 not found. Install Python 3 with pip and try again."
                return 1
            fi
        else
            print_success "trufflehog already installed"
        fi
    else
        print_warning "Unsupported Linux distribution. Install manually:"
        echo "  Gitleaks: https://github.com/gitleaks/gitleaks/releases"
        echo "  TruffleHog: https://github.com/trufflesecurity/trufflehog/releases"
        return 1
    fi
}

# Install on Windows (WSL)
install_windows() {
    print_header "Installing scanners on Windows"
    
    print_warning "Windows detected. Use WSL2:"
    echo ""
    echo "  1. Install WSL2: https://docs.microsoft.com/en-us/windows/wsl/install"
    echo "  2. Install Ubuntu in WSL2"
    echo "  3. Run this script inside WSL2"
    echo ""
    echo ""
    
    return 1
}

# Install on WSL
install_wsl() {
    print_header "Installing scanners on WSL"
    
    # Install gitleaks
    if ! command_exists gitleaks; then
        print_info "Installing gitleaks..."
        GITLEAKS_VERSION="8.18.0"
        GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-x64"
        
        if command_exists wget; then
            wget -q "$GITLEAKS_URL" -O /tmp/gitleaks
        elif command_exists curl; then
            curl -sL "$GITLEAKS_URL" -o /tmp/gitleaks
        else
            print_error "Neither wget nor curl found. Install one and try again."
            return 1
        fi
        
        chmod +x /tmp/gitleaks
        sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
        print_success "gitleaks installed"
    else
        print_success "gitleaks already installed"
    fi
    
    # Install trufflehog
    if ! command_exists trufflehog; then
        print_info "Installing trufflehog..."
        if command_exists pip3; then
            pip3 install truffleHog3
            print_success "trufflehog installed"
        else
            print_error "pip3 not found. Install Python 3 and try again."
            return 1
        fi
    else
        print_success "trufflehog already installed"
    fi
}

# Main flow
main() {
    print_header "KeyTrap Scanner Installation"
    
    os=$(detect_os)
    print_info "Detected OS: $os"
    
    # Check current installation status
    echo ""
    print_info "Checking current installation status:"
    
    if command_exists gitleaks; then
        GITLEAKS_VERSION=$(gitleaks version 2>/dev/null || echo "unknown")
        print_success "gitleaks installed (version: $GITLEAKS_VERSION)"
    else
        print_warning "gitleaks not installed"
    fi
    
    if command_exists trufflehog; then
        TRUFFLEHOG_VERSION=$(trufflehog --version 2>/dev/null || echo "unknown")
        print_success "trufflehog installed (version: $TRUFFLEHOG_VERSION)"
    else
        print_warning "trufflehog not installed"
    fi
    
    # Check if both are already installed
    if command_exists gitleaks && command_exists trufflehog; then
        echo ""
        print_success "Both scanners are already installed!"
        return 0
    fi
    
    # Install based on OS
    echo ""
    case "$os" in
        macos)
            install_macos
            ;;
        linux)
            install_linux
            ;;
        wsl)
            install_wsl
            ;;
        windows)
            install_windows
            ;;
        *)
            print_error "Unknown OS: $os"
            return 1
            ;;
    esac
    
    install_status=$?
    
    # Verify installation
    echo ""
    print_header "Installation Summary"
    
    if command_exists gitleaks; then
        GITLEAKS_VERSION=$(gitleaks version 2>/dev/null || echo "installed")
        print_success "gitleaks ready ($GITLEAKS_VERSION)"
    else
        print_warning "gitleaks not available (optional)"
    fi
    
    if command_exists trufflehog; then
        TRUFFLEHOG_VERSION=$(trufflehog --version 2>/dev/null || echo "installed")
        print_success "trufflehog ready ($TRUFFLEHOG_VERSION)"
    else
        print_warning "trufflehog not available (optional)"
    fi
    
    echo ""
    if [ $install_status -eq 0 ]; then
        print_success "Scanner installation completed!"
        print_info "You can now run: keytrap scan <repo> --output findings.json"
        print_info "Both GitleaksAgent and TruffleHogAgent will be available."
    else
        print_warning "Scanner installation was not fully completed."
        print_info "You can still use KeyTrap with CustomRegexAgent and EntropyAgent."
        print_info "Run: keytrap scan <repo> --output findings.json"
    fi
    
    return $install_status
}

# Run main
main "$@"
