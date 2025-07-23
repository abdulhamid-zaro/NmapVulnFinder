# 🔍 NmapVulnFinder - Advanced CVE Discovery Tool

A powerful Python-based cybersecurity reconnaissance tool that performs deep scanning of web targets using Nmap, then automatically extracts and reports known vulnerabilities (CVEs) based on detected service versions.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Nmap](https://img.shields.io/badge/nmap-required-red.svg)

## 🎯 Key Features

- **🔍 Service Detection & Fingerprinting**: Uses Nmap's powerful scanning capabilities to detect services and versions
- **🚨 Automated CVE Discovery**: Maps detected services to known vulnerabilities using the Vulners database
- **📊 Multiple Output Formats**: Terminal, JSON, HTML, Markdown, and CSV reports
- **⚡ Batch Scanning**: Scan multiple targets in parallel with consolidated reporting
- **🎨 Beautiful Terminal Output**: Rich, colorized output with progress bars and tables
- **🔧 Flexible Configuration**: Multiple scan types (quick, comprehensive, stealth, aggressive)
- **📈 CVSS Filtering**: Filter vulnerabilities by severity score
- **🎯 Service Filtering**: Focus on specific services (Apache, SSH, etc.)

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- Nmap installed on your system
- Internet connection for vulnerability database queries

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/your-username/NmapVulnFinder.git
cd NmapVulnFinder

# Install Python dependencies
pip install -r requirements.txt

# Make scripts executable (Linux/Mac)
chmod +x nmap_cve_finder.py batch_scanner.py
```

### Install Nmap

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**CentOS/RHEL:**
```bash
sudo yum install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download from [https://nmap.org/download.html](https://nmap.org/download.html)

## 🚀 Quick Start

### Basic Single Target Scan

```bash
# Scan a single target with default settings
python nmap_cve_finder.py -t 192.168.1.1

# Quick scan of common ports
python nmap_cve_finder.py -t example.com --scan-type quick -p 80,443,22,21,25

# Comprehensive scan with high-severity vulnerabilities only
python nmap_cve_finder.py -t 10.0.0.1 --scan-type comprehensive --min-cvss 7.0
```

### Batch Scanning

```bash
# Scan multiple targets from a file
python batch_scanner.py -f targets.txt --scan-type quick

# Scan CIDR range with parallel workers
python batch_scanner.py -t "192.168.1.0/24,10.0.0.1" --workers 10 --expand-cidrs

# Generate HTML report for multiple targets
python batch_scanner.py -f targets.txt --output html --output-file report.html
```

## 📖 Usage Examples

### 1. Basic Vulnerability Scanning

```bash
# Scan target with comprehensive analysis
python nmap_cve_finder.py -t scanme.nmap.org --scan-type comprehensive
```

### 2. Focus on Specific Services

```bash
# Only show Apache-related vulnerabilities
python nmap_cve_finder.py -t example.com --service-filter apache

# Scan SSH services only
python nmap_cve_finder.py -t 192.168.1.0/24 -p 22 --service-filter ssh
```

### 3. High-Severity Vulnerabilities Only

```bash
# Show only critical and high-severity CVEs
python nmap_cve_finder.py -t target.com --min-cvss 7.0 --output json --output-file critical_vulns.json
```

### 4. Stealth Scanning

```bash
# Slow, stealthy scan to avoid detection
python nmap_cve_finder.py -t sensitive-target.com --scan-type stealth
```

### 5. Batch Processing with Reports

```bash
# Scan multiple targets and generate comprehensive HTML report
python batch_scanner.py -f corporate_assets.txt \
    --scan-type comprehensive \
    --min-cvss 4.0 \
    --workers 8 \
    --output html \
    --output-file vulnerability_report.html
```

## 📝 Command Line Options

### Single Target Scanner (`nmap_cve_finder.py`)

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | Target IP, hostname, or CIDR range | Required |
| `-p, --ports` | Port range to scan | `1-65535` |
| `--scan-type` | Scan type: quick, comprehensive, stealth, aggressive | `comprehensive` |
| `--min-cvss` | Minimum CVSS score (0.0-10.0) | `0.0` |
| `--service-filter` | Filter by service name | None |
| `--output` | Output format: terminal, json, html, markdown | `terminal` |
| `--output-file` | File to save report | None |
| `--vulners-api-key` | Vulners API key for enhanced data | None |
| `-v, --verbose` | Enable verbose output | False |

### Batch Scanner (`batch_scanner.py`)

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file` | File containing targets (one per line) | None |
| `-t, --targets` | Comma-separated list of targets | None |
| `--workers` | Number of parallel workers | `5` |
| `--expand-cidrs` | Expand CIDR ranges to individual IPs | False |
| All other options from single scanner | | |

## 📊 Output Formats

### Terminal Output
Beautiful, colorized output with:
- Service discovery table
- Vulnerability summary with severity breakdown
- Top vulnerabilities sorted by CVSS score
- Color-coded severity levels

### JSON Output
Structured data perfect for integration:
```json
{
  "scan_info": {
    "timestamp": "2024-01-15T10:30:00",
    "tool": "NmapCVEFinder",
    "version": "1.0"
  },
  "services": [...],
  "vulnerabilities": [...],
  "summary": {...}
}
```

### HTML Output
Professional web-based reports with:
- Executive dashboard with statistics
- Interactive tables
- Severity-based color coding
- Responsive design

### CSV Output
Spreadsheet-compatible format for:
- Data analysis
- Reporting to management
- Integration with other tools

## 🔧 Configuration

### Environment Variables

```bash
# Set Vulners API key for enhanced vulnerability data
export VULNERS_API_KEY="your-api-key-here"

# Set default scan type
export DEFAULT_SCAN_TYPE="comprehensive"

# Set minimum CVSS score
export DEFAULT_MIN_CVSS="4.0"

# Set log level
export LOG_LEVEL="INFO"
```

### Scan Types

| Type | Description | Speed | Stealth | Accuracy |
|------|-------------|-------|---------|----------|
| `quick` | Fast scan, basic service detection | ⚡⚡⚡ | 🥷🥷 | 📊📊 |
| `comprehensive` | Thorough scan with vulnerability scripts | ⚡⚡ | 🥷 | 📊📊📊 |
| `stealth` | Slow, stealthy scan | ⚡ | 🥷🥷🥷 | 📊📊 |
| `aggressive` | Fast, aggressive scan with all scripts | ⚡⚡⚡ | 🥷 | 📊📊📊 |

## 🎯 Target Examples

### Single Targets
```bash
# IP address
python nmap_cve_finder.py -t 192.168.1.1

# Hostname
python nmap_cve_finder.py -t example.com

# CIDR range
python nmap_cve_finder.py -t 10.0.0.0/24
```

### Batch Targets File (`targets.txt`)
```
# Corporate web servers
web1.company.com
web2.company.com
192.168.1.0/24

# Database servers
db.company.com:3306
192.168.2.10

# Development environment
dev.company.com
staging.company.com
```

## 🔒 Security Considerations

### Responsible Usage
- Only scan systems you own or have explicit permission to test
- Be aware of scan timing and frequency to avoid overwhelming targets
- Use stealth mode for sensitive environments
- Respect rate limits and network policies

### Legal Disclaimer
This tool is for authorized security testing only. Users are responsible for complying with applicable laws and regulations. Unauthorized scanning may be illegal in your jurisdiction.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/your-username/NmapVulnFinder.git
cd NmapVulnFinder

# Install development dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 nmap_cve_finder.py batch_scanner.py
```

## 📋 Roadmap

- [ ] Integration with additional vulnerability databases (NVD, ExploitDB)
- [ ] Docker containerization
- [ ] Web interface for easier usage
- [ ] Integration with popular security frameworks
- [ ] Custom vulnerability rule engine
- [ ] Historical scan comparison
- [ ] Automated remediation suggestions

## 🐛 Troubleshooting

### Common Issues

**"Nmap not found"**
```bash
# Install nmap and ensure it's in PATH
which nmap
sudo apt-get install nmap  # Ubuntu/Debian
```

**"Permission denied"**
```bash
# Some scans require root privileges
sudo python nmap_cve_finder.py -t target.com
```

**"API rate limit exceeded"**
```bash
# Get a Vulners API key for higher limits
export VULNERS_API_KEY="your-key"
```

**"No vulnerabilities found"**
- Try different scan types
- Check if services are actually running
- Verify network connectivity
- Use verbose mode for debugging

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Nmap](https://nmap.org/) - The Network Mapper
- [Vulners](https://vulners.com/) - Vulnerability database
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal output
- The cybersecurity community for continuous feedback and improvements

## 📞 Support

- 📧 Email: support@nmapvulnfinder.com
- 🐛 Issues: [GitHub Issues](https://github.com/your-username/NmapVulnFinder/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/your-username/NmapVulnFinder/discussions)

---

**⚠️ Remember: Use this tool responsibly and only on systems you own or have explicit permission to test!**
