#!/bin/bash

# NmapVulnFinder Setup Script
# ===========================
# This script sets up the NmapVulnFinder tool and its dependencies

set -e  # Exit on any error

echo "🔍 NmapVulnFinder Setup Script"
echo "==============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_warning "This script should not be run as root for security reasons"
   print_warning "Some operations may require sudo, which will be prompted when needed"
fi

# Check Python version
print_status "Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    print_status "Python version: $PYTHON_VERSION"
    
    # Check if Python version is 3.8 or higher
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        print_success "Python version is compatible"
    else
        print_error "Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check if pip is installed
print_status "Checking pip installation..."
if command -v pip3 &> /dev/null; then
    print_success "pip3 is available"
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    print_success "pip is available"
    PIP_CMD="pip"
else
    print_error "pip is not installed. Please install pip."
    exit 1
fi

# Check if nmap is installed
print_status "Checking Nmap installation..."
if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version | head -n1 | awk '{print $3}')
    print_success "Nmap is installed (version $NMAP_VERSION)"
else
    print_warning "Nmap is not installed"
    print_status "Attempting to install Nmap..."
    
    # Detect OS and install nmap
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            print_status "Installing Nmap using apt-get..."
            sudo apt-get update
            sudo apt-get install -y nmap
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL
            print_status "Installing Nmap using yum..."
            sudo yum install -y nmap
        elif command -v dnf &> /dev/null; then
            # Fedora
            print_status "Installing Nmap using dnf..."
            sudo dnf install -y nmap
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            print_status "Installing Nmap using pacman..."
            sudo pacman -S --noconfirm nmap
        else
            print_error "Unable to detect package manager. Please install Nmap manually."
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            print_status "Installing Nmap using Homebrew..."
            brew install nmap
        else
            print_error "Homebrew not found. Please install Homebrew or install Nmap manually."
            print_error "Visit: https://nmap.org/download.html"
            exit 1
        fi
    else
        print_error "Unsupported operating system. Please install Nmap manually."
        print_error "Visit: https://nmap.org/download.html"
        exit 1
    fi
    
    # Verify installation
    if command -v nmap &> /dev/null; then
        print_success "Nmap installed successfully"
    else
        print_error "Nmap installation failed"
        exit 1
    fi
fi

# Install Python dependencies
print_status "Installing Python dependencies..."
if [[ -f "requirements.txt" ]]; then
    $PIP_CMD install -r requirements.txt
    print_success "Python dependencies installed"
else
    print_error "requirements.txt not found. Make sure you're in the correct directory."
    exit 1
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p reports logs examples templates
print_success "Directories created"

# Make scripts executable
print_status "Making scripts executable..."
chmod +x nmap_cve_finder.py batch_scanner.py
print_success "Scripts are now executable"

# Check if Vulners API key is set
print_status "Checking Vulners API key..."
if [[ -n "$VULNERS_API_KEY" ]]; then
    print_success "Vulners API key is set"
else
    print_warning "Vulners API key is not set"
    print_status "You can get a free API key from: https://vulners.com/api"
    print_status "Set it with: export VULNERS_API_KEY='your-key-here'"
fi

# Test basic functionality
print_status "Testing basic functionality..."
if python3 -c "import nmap; import requests; import rich; print('All imports successful')" 2>/dev/null; then
    print_success "Basic functionality test passed"
else
    print_error "Basic functionality test failed. Some dependencies may not be installed correctly."
    exit 1
fi

# Display usage information
echo ""
print_success "🎉 Setup completed successfully!"
echo ""
echo "Quick Start Commands:"
echo "===================="
echo ""
echo "1. Basic scan:"
echo "   python3 nmap_cve_finder.py -t scanme.nmap.org"
echo ""
echo "2. Quick scan with common ports:"
echo "   python3 nmap_cve_finder.py -t example.com --scan-type quick -p 80,443,22"
echo ""
echo "3. Batch scan from file:"
echo "   python3 batch_scanner.py -f examples/targets.txt --scan-type quick"
echo ""
echo "4. Generate HTML report:"
echo "   python3 nmap_cve_finder.py -t target.com --output html --output-file report.html"
echo ""
echo "5. High-severity vulnerabilities only:"
echo "   python3 nmap_cve_finder.py -t target.com --min-cvss 7.0"
echo ""
echo "For more options, use:"
echo "   python3 nmap_cve_finder.py --help"
echo "   python3 batch_scanner.py --help"
echo ""
echo "⚠️  Remember: Only scan systems you own or have explicit permission to test!"
echo ""
print_success "Happy hunting! 🔍"