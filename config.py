#!/usr/bin/env python3
"""
Configuration file for Nmap CVE Discovery Tool
==============================================

This file contains default settings and configuration options
that can be customized for different scanning scenarios.
"""

import os
from pathlib import Path

# Base configuration
class Config:
    """Main configuration class"""
    
    # Tool information
    TOOL_NAME = "NmapCVEFinder"
    TOOL_VERSION = "1.0.0"
    TOOL_DESCRIPTION = "Advanced Nmap-Based CVE Discovery Tool"
    
    # Default scan settings
    DEFAULT_PORTS = "1-65535"
    DEFAULT_SCAN_TYPE = "comprehensive"
    DEFAULT_MIN_CVSS = 0.0
    DEFAULT_OUTPUT_FORMAT = "terminal"
    
    # Nmap scan configurations
    SCAN_CONFIGS = {
        "quick": {
            "args": "-sV --version-intensity 5 -T4",
            "description": "Fast scan with basic service detection",
            "estimated_time": "2-5 minutes"
        },
        "comprehensive": {
            "args": "-sV -sC --version-intensity 9 -T4 --script vulners,vuln",
            "description": "Thorough scan with vulnerability scripts",
            "estimated_time": "10-30 minutes"
        },
        "stealth": {
            "args": "-sV -sS -T2 --version-intensity 5",
            "description": "Slow, stealthy scan to avoid detection",
            "estimated_time": "30-60 minutes"
        },
        "aggressive": {
            "args": "-sV -sC -A --version-intensity 9 -T5 --script vulners,vuln,exploit",
            "description": "Aggressive scan with all available scripts",
            "estimated_time": "5-15 minutes"
        }
    }
    
    # Vulnerability database settings
    VULNERS_API_BASE_URL = "https://vulners.com/api/v3"
    VULNERS_API_TIMEOUT = 10
    VULNERS_API_RETRIES = 3
    VULNERS_MAX_RESULTS = 100
    
    # CVSS scoring thresholds
    CVSS_THRESHOLDS = {
        "CRITICAL": 9.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 0.1
    }
    
    # Output settings
    OUTPUT_FORMATS = ["terminal", "json", "html", "markdown", "csv", "xml"]
    MAX_TERMINAL_RESULTS = 50
    MAX_DESCRIPTION_LENGTH = 200
    
    # File paths
    BASE_DIR = Path(__file__).parent
    OUTPUT_DIR = BASE_DIR / "reports"
    TEMPLATES_DIR = BASE_DIR / "templates"
    LOGS_DIR = BASE_DIR / "logs"
    
    # Logging configuration
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE = LOGS_DIR / "nmap_cve_finder.log"
    
    # Performance settings
    MAX_CONCURRENT_SCANS = 5
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 0.3
    
    # Security settings
    ALLOWED_PRIVATE_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12", 
        "192.168.0.0/16",
        "127.0.0.0/8"
    ]
    
    # Service detection patterns
    SERVICE_PATTERNS = {
        "web_servers": ["apache", "nginx", "iis", "lighttpd", "tomcat"],
        "databases": ["mysql", "postgresql", "mongodb", "redis", "elasticsearch"],
        "ssh_services": ["openssh", "ssh"],
        "ftp_services": ["vsftpd", "proftpd", "filezilla"],
        "mail_services": ["postfix", "sendmail", "exim", "dovecot"],
        "dns_services": ["bind", "dnsmasq", "powerdns"]
    }
    
    # Common vulnerable services (for prioritization)
    HIGH_PRIORITY_SERVICES = [
        "apache",
        "nginx", 
        "openssh",
        "mysql",
        "postgresql",
        "wordpress",
        "joomla",
        "drupal",
        "phpmyadmin"
    ]
    
    # Report templates
    REPORT_TEMPLATES = {
        "executive_summary": {
            "include_technical_details": False,
            "focus_on_risk": True,
            "max_vulnerabilities": 10
        },
        "technical_report": {
            "include_technical_details": True,
            "include_remediation": True,
            "include_references": True
        },
        "compliance_report": {
            "include_cvss_scores": True,
            "group_by_severity": True,
            "include_timeline": True
        }
    }
    
    # Environment-specific settings
    @classmethod
    def load_environment_config(cls):
        """Load configuration from environment variables"""
        # API Keys
        cls.VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")
        cls.SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
        cls.NVD_API_KEY = os.getenv("NVD_API_KEY")
        
        # Override defaults from environment
        cls.DEFAULT_SCAN_TYPE = os.getenv("DEFAULT_SCAN_TYPE", cls.DEFAULT_SCAN_TYPE)
        cls.DEFAULT_MIN_CVSS = float(os.getenv("DEFAULT_MIN_CVSS", cls.DEFAULT_MIN_CVSS))
        cls.LOG_LEVEL = os.getenv("LOG_LEVEL", cls.LOG_LEVEL)
        cls.MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", cls.MAX_CONCURRENT_SCANS))
        
        # Create directories if they don't exist
        cls.OUTPUT_DIR.mkdir(exist_ok=True)
        cls.LOGS_DIR.mkdir(exist_ok=True)
        cls.TEMPLATES_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def get_scan_config(cls, scan_type: str) -> dict:
        """Get scan configuration for specified type"""
        return cls.SCAN_CONFIGS.get(scan_type, cls.SCAN_CONFIGS["comprehensive"])
    
    @classmethod
    def get_severity_from_cvss(cls, cvss_score: float) -> str:
        """Determine severity level from CVSS score"""
        if cvss_score >= cls.CVSS_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif cvss_score >= cls.CVSS_THRESHOLDS["HIGH"]:
            return "HIGH"
        elif cvss_score >= cls.CVSS_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        else:
            return "LOW"
    
    @classmethod
    def is_high_priority_service(cls, service_name: str) -> bool:
        """Check if service is high priority for vulnerability scanning"""
        return any(priority in service_name.lower() 
                  for priority in cls.HIGH_PRIORITY_SERVICES)

# Development configuration
class DevelopmentConfig(Config):
    """Configuration for development environment"""
    LOG_LEVEL = "DEBUG"
    DEFAULT_SCAN_TYPE = "quick"
    MAX_TERMINAL_RESULTS = 20
    VULNERS_API_TIMEOUT = 5

# Production configuration  
class ProductionConfig(Config):
    """Configuration for production environment"""
    LOG_LEVEL = "WARNING"
    MAX_CONCURRENT_SCANS = 10
    VULNERS_API_TIMEOUT = 15
    MAX_RETRIES = 5

# Testing configuration
class TestingConfig(Config):
    """Configuration for testing environment"""
    LOG_LEVEL = "DEBUG"
    DEFAULT_SCAN_TYPE = "quick"
    VULNERS_API_TIMEOUT = 2
    MAX_TERMINAL_RESULTS = 5

# Configuration factory
def get_config(environment: str = "production") -> Config:
    """Get configuration based on environment"""
    configs = {
        "development": DevelopmentConfig,
        "production": ProductionConfig,
        "testing": TestingConfig
    }
    
    config_class = configs.get(environment, ProductionConfig)
    config_class.load_environment_config()
    return config_class

# Load default configuration
config = get_config(os.getenv("ENVIRONMENT", "production"))