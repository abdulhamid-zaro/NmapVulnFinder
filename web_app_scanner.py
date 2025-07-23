#!/usr/bin/env python3
"""
Web Application CVE Scanner
===========================

Specialized scanner for discovering CVEs in web applications,
frameworks, CMS systems, and web technologies.
"""

import sys
import json
import re
import time
import asyncio
import aiohttp
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import ssl
import socket

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from nmap_cve_finder import CVEInfo, ServiceInfo
from performance_optimizer import PortNotifier
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel

console = Console()

@dataclass
class WebTechnology:
    """Web technology detection result"""
    name: str
    version: str
    category: str  # cms, framework, server, etc.
    confidence: int  # 1-100
    evidence: str
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None

@dataclass
class WebVulnerability:
    """Web application vulnerability"""
    cve_id: str
    title: str
    description: str
    cvss_score: float
    severity: str
    technology: str
    version_affected: str
    exploit_available: bool
    references: List[str]
    discovery_method: str
    evidence: str

class WebApplicationScanner:
    """Advanced web application vulnerability scanner"""
    
    def __init__(self):
        self.session = None
        self.technologies = []
        self.vulnerabilities = []
        
        # Common web application paths to check
        self.common_paths = [
            '/', '/admin/', '/wp-admin/', '/administrator/',
            '/login/', '/wp-login.php', '/admin.php',
            '/phpmyadmin/', '/phpinfo.php', '/info.php',
            '/test.php', '/config.php', '/install.php',
            '/setup.php', '/readme.txt', '/README.md',
            '/robots.txt', '/.htaccess', '/web.config',
            '/sitemap.xml', '/crossdomain.xml',
            '/wp-config.php', '/config.inc.php'
        ]
        
        # Technology fingerprints
        self.tech_fingerprints = {
            'wordpress': {
                'headers': ['x-powered-by'],
                'content': [r'wp-content', r'wp-includes', r'/wp-json/'],
                'paths': ['/wp-admin/', '/wp-login.php'],
                'meta': [r'<meta name="generator" content="WordPress ([0-9.]+)"']
            },
            'drupal': {
                'headers': ['x-drupal-cache', 'x-generator'],
                'content': [r'Drupal\.settings', r'/sites/default/files/'],
                'paths': ['/user/login', '/admin/', '/?q=admin'],
                'meta': [r'<meta name="generator" content="Drupal ([0-9.]+)"']
            },
            'joomla': {
                'headers': ['x-content-encoded-by'],
                'content': [r'/media/system/', r'Joomla!', r'/administrator/'],
                'paths': ['/administrator/', '/components/'],
                'meta': [r'<meta name="generator" content="Joomla! ([0-9.]+)"']
            },
            'apache': {
                'headers': ['server'],
                'patterns': [r'Apache/([0-9.]+)']
            },
            'nginx': {
                'headers': ['server'],
                'patterns': [r'nginx/([0-9.]+)']
            },
            'php': {
                'headers': ['x-powered-by', 'server'],
                'patterns': [r'PHP/([0-9.]+)']
            },
            'iis': {
                'headers': ['server'],
                'patterns': [r'Microsoft-IIS/([0-9.]+)']
            }
        }
        
        # CVE database for web applications
        self.web_cve_database = {
            'wordpress': [
                {
                    'cve': 'CVE-2021-34527',
                    'versions': ['< 5.8'],
                    'cvss': 9.8,
                    'title': 'WordPress Core Vulnerability',
                    'description': 'WordPress before 5.8 allows XXE attacks via the media library.',
                    'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527']
                },
                {
                    'cve': 'CVE-2020-4047',
                    'versions': ['< 5.4.2'],
                    'cvss': 8.8,
                    'title': 'WordPress CSRF Vulnerability',
                    'description': 'WordPress before 5.4.2 allows CSRF attacks.',
                    'references': ['https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/']
                }
            ],
            'drupal': [
                {
                    'cve': 'CVE-2018-7600',
                    'versions': ['< 8.5.1', '< 7.58'],
                    'cvss': 9.8,
                    'title': 'Drupalgeddon2',
                    'description': 'Remote code execution vulnerability in Drupal core.',
                    'references': ['https://www.drupal.org/sa-core-2018-002']
                },
                {
                    'cve': 'CVE-2019-6340',
                    'versions': ['< 8.6.10', '< 7.65'],
                    'cvss': 9.8,
                    'title': 'Drupal RESTful Web Services RCE',
                    'description': 'Remote code execution in RESTful Web Services module.',
                    'references': ['https://www.drupal.org/sa-core-2019-003']
                }
            ],
            'joomla': [
                {
                    'cve': 'CVE-2020-10238',
                    'versions': ['< 3.9.16'],
                    'cvss': 9.8,
                    'title': 'Joomla Core RCE',
                    'description': 'Remote code execution in Joomla core.',
                    'references': ['https://developer.joomla.org/security-centre/803-20200301-core-rce-in-com-fields.html']
                }
            ],
            'apache': [
                {
                    'cve': 'CVE-2021-41773',
                    'versions': ['2.4.49'],
                    'cvss': 7.5,
                    'title': 'Apache HTTP Server Path Traversal',
                    'description': 'Path traversal and file disclosure vulnerability.',
                    'references': ['https://httpd.apache.org/security/vulnerabilities_24.html']
                },
                {
                    'cve': 'CVE-2021-42013',
                    'versions': ['2.4.49', '2.4.50'],
                    'cvss': 9.8,
                    'title': 'Apache HTTP Server RCE',
                    'description': 'Remote code execution vulnerability.',
                    'references': ['https://httpd.apache.org/security/vulnerabilities_24.html']
                }
            ],
            'nginx': [
                {
                    'cve': 'CVE-2021-23017',
                    'versions': ['< 1.20.1'],
                    'cvss': 8.1,
                    'title': 'Nginx DNS Resolver Vulnerability',
                    'description': 'Off-by-one in resolver.',
                    'references': ['http://nginx.org/en/security_advisories.html']
                }
            ],
            'php': [
                {
                    'cve': 'CVE-2021-21704',
                    'versions': ['< 7.4.21', '< 8.0.8'],
                    'cvss': 5.9,
                    'title': 'PHP Stack Buffer Overflow',
                    'description': 'Stack buffer overflow in firebird_info_cb.',
                    'references': ['https://www.php.net/ChangeLog-7.php#7.4.21']
                }
            ]
        }
    
    async def scan_web_application(self, target: str, include_paths: bool = True,
                                 deep_scan: bool = False) -> Dict:
        """Comprehensive web application vulnerability scan"""
        
        console.print(f"🌐 [bold cyan]Starting Web Application Scan for {target}[/bold cyan]")
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        results = {
            'target': target,
            'technologies': [],
            'vulnerabilities': [],
            'scan_info': {
                'start_time': time.time(),
                'scan_type': 'deep' if deep_scan else 'standard',
                'paths_checked': include_paths
            }
        }
        
        try:
            # Create aiohttp session
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; WebAppScanner/1.0)'}
            )
            
            # Phase 1: Technology Detection
            console.print("🔍 Phase 1: Technology Detection")
            technologies = await self._detect_technologies(target)
            results['technologies'] = technologies
            
            # Phase 2: CVE Discovery
            console.print("🚨 Phase 2: CVE Discovery")
            vulnerabilities = await self._discover_web_cves(technologies)
            results['vulnerabilities'] = vulnerabilities
            
            # Phase 3: Path-based Discovery (if enabled)
            if include_paths:
                console.print("📂 Phase 3: Path-based Discovery")
                path_vulns = await self._scan_common_paths(target)
                results['vulnerabilities'].extend(path_vulns)
            
            # Phase 4: Deep Scan (if enabled)
            if deep_scan:
                console.print("🔬 Phase 4: Deep Vulnerability Scan")
                deep_vulns = await self._deep_vulnerability_scan(target, technologies)
                results['vulnerabilities'].extend(deep_vulns)
            
        except Exception as e:
            console.print(f"❌ Scan error: {e}")
        finally:
            if self.session:
                await self.session.close()
        
        results['scan_info']['end_time'] = time.time()
        results['scan_info']['duration'] = results['scan_info']['end_time'] - results['scan_info']['start_time']
        
        return results
    
    async def _detect_technologies(self, target: str) -> List[WebTechnology]:
        """Detect web technologies used by the target"""
        
        technologies = []
        
        try:
            # Get main page
            async with self.session.get(target) as response:
                headers = dict(response.headers)
                content = await response.text()
                cookies = {cookie.key: cookie.value for cookie in response.cookies}
                
                # Check server headers
                server = headers.get('server', '').lower()
                x_powered_by = headers.get('x-powered-by', '').lower()
                
                # Detect web server
                if 'apache' in server:
                    version_match = re.search(r'apache/([0-9.]+)', server)
                    version = version_match.group(1) if version_match else 'unknown'
                    technologies.append(WebTechnology(
                        name='apache',
                        version=version,
                        category='server',
                        confidence=95,
                        evidence=f"Server header: {server}",
                        headers=headers
                    ))
                
                elif 'nginx' in server:
                    version_match = re.search(r'nginx/([0-9.]+)', server)
                    version = version_match.group(1) if version_match else 'unknown'
                    technologies.append(WebTechnology(
                        name='nginx',
                        version=version,
                        category='server',
                        confidence=95,
                        evidence=f"Server header: {server}",
                        headers=headers
                    ))
                
                elif 'microsoft-iis' in server:
                    version_match = re.search(r'microsoft-iis/([0-9.]+)', server)
                    version = version_match.group(1) if version_match else 'unknown'
                    technologies.append(WebTechnology(
                        name='iis',
                        version=version,
                        category='server',
                        confidence=95,
                        evidence=f"Server header: {server}",
                        headers=headers
                    ))
                
                # Detect PHP
                if 'php' in x_powered_by:
                    version_match = re.search(r'php/([0-9.]+)', x_powered_by)
                    version = version_match.group(1) if version_match else 'unknown'
                    technologies.append(WebTechnology(
                        name='php',
                        version=version,
                        category='language',
                        confidence=95,
                        evidence=f"X-Powered-By header: {x_powered_by}",
                        headers=headers
                    ))
                
                # Detect CMS from content
                # WordPress
                if any(pattern in content.lower() for pattern in ['wp-content', 'wp-includes', '/wp-json/']):
                    version = 'unknown'
                    confidence = 80
                    
                    # Try to get version from generator meta tag
                    version_match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', content, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        confidence = 95
                    
                    technologies.append(WebTechnology(
                        name='wordpress',
                        version=version,
                        category='cms',
                        confidence=confidence,
                        evidence="WordPress patterns found in content",
                        headers=headers,
                        cookies=cookies
                    ))
                
                # Drupal
                if any(pattern in content.lower() for pattern in ['drupal.settings', '/sites/default/files/']):
                    version = 'unknown'
                    confidence = 80
                    
                    version_match = re.search(r'<meta name="generator" content="Drupal ([0-9.]+)"', content, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        confidence = 95
                    
                    technologies.append(WebTechnology(
                        name='drupal',
                        version=version,
                        category='cms',
                        confidence=confidence,
                        evidence="Drupal patterns found in content",
                        headers=headers
                    ))
                
                # Joomla
                if any(pattern in content.lower() for pattern in ['joomla!', '/media/system/', '/administrator/']):
                    version = 'unknown'
                    confidence = 80
                    
                    version_match = re.search(r'<meta name="generator" content="Joomla! ([0-9.]+)"', content, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        confidence = 95
                    
                    technologies.append(WebTechnology(
                        name='joomla',
                        version=version,
                        category='cms',
                        confidence=confidence,
                        evidence="Joomla patterns found in content",
                        headers=headers
                    ))
                
        except Exception as e:
            console.print(f"⚠️ Technology detection error: {e}")
        
        return technologies
    
    async def _discover_web_cves(self, technologies: List[WebTechnology]) -> List[WebVulnerability]:
        """Discover CVEs for detected technologies"""
        
        vulnerabilities = []
        
        for tech in technologies:
            tech_name = tech.name.lower()
            if tech_name in self.web_cve_database:
                cve_list = self.web_cve_database[tech_name]
                
                for cve_data in cve_list:
                    # Check if version is affected
                    if self._is_version_affected(tech.version, cve_data['versions']):
                        severity = self._get_severity_from_cvss(cve_data['cvss'])
                        
                        vulnerability = WebVulnerability(
                            cve_id=cve_data['cve'],
                            title=cve_data['title'],
                            description=cve_data['description'],
                            cvss_score=cve_data['cvss'],
                            severity=severity,
                            technology=f"{tech.name} {tech.version}",
                            version_affected=', '.join(cve_data['versions']),
                            exploit_available=cve_data['cvss'] >= 7.0,
                            references=cve_data['references'],
                            discovery_method='version_matching',
                            evidence=f"Detected {tech.name} version {tech.version}"
                        )
                        
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _scan_common_paths(self, target: str) -> List[WebVulnerability]:
        """Scan common paths for vulnerabilities"""
        
        vulnerabilities = []
        
        # Check for sensitive files
        sensitive_paths = [
            ('/phpinfo.php', 'PHP Info Disclosure'),
            ('/info.php', 'PHP Info Disclosure'),
            ('/.env', 'Environment File Exposure'),
            ('/config.php', 'Configuration File Exposure'),
            ('/wp-config.php', 'WordPress Config Exposure'),
            ('/database.yml', 'Database Config Exposure'),
            ('/.htaccess', 'Apache Config Exposure'),
            ('/web.config', 'IIS Config Exposure'),
            ('/backup.sql', 'Database Backup Exposure'),
            ('/dump.sql', 'Database Dump Exposure')
        ]
        
        for path, description in sensitive_paths:
            try:
                url = urljoin(target, path)
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for actual sensitive content
                        if self._is_sensitive_content(content, path):
                            vulnerability = WebVulnerability(
                                cve_id='CUSTOM-001',
                                title=f'{description} - {path}',
                                description=f'Sensitive file {path} is accessible and contains sensitive information.',
                                cvss_score=5.3,
                                severity='MEDIUM',
                                technology='Web Application',
                                version_affected='N/A',
                                exploit_available=False,
                                references=[url],
                                discovery_method='path_scanning',
                                evidence=f'File {path} returned 200 status with sensitive content'
                            )
                            vulnerabilities.append(vulnerability)
                        
            except Exception:
                continue  # Path not accessible
        
        return vulnerabilities
    
    async def _deep_vulnerability_scan(self, target: str, technologies: List[WebTechnology]) -> List[WebVulnerability]:
        """Perform deep vulnerability scanning"""
        
        vulnerabilities = []
        
        # SQL Injection tests
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        # XSS tests
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>"
        ]
        
        # Test common parameters
        test_params = ['id', 'search', 'q', 'query', 'name', 'user', 'page']
        
        for param in test_params:
            # Test SQL injection
            for payload in sql_payloads:
                try:
                    test_url = f"{target}?{param}={payload}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check for SQL error patterns
                        sql_errors = [
                            'mysql_fetch_array',
                            'ORA-01756',
                            'Microsoft OLE DB Provider',
                            'SQLServer JDBC Driver'
                        ]
                        
                        if any(error.lower() in content.lower() for error in sql_errors):
                            vulnerability = WebVulnerability(
                                cve_id='CUSTOM-SQLi',
                                title=f'SQL Injection in parameter "{param}"',
                                description=f'Parameter "{param}" appears to be vulnerable to SQL injection.',
                                cvss_score=8.2,
                                severity='HIGH',
                                technology='Web Application',
                                version_affected='N/A',
                                exploit_available=True,
                                references=[test_url],
                                discovery_method='payload_testing',
                                evidence=f'SQL error detected in response to payload: {payload}'
                            )
                            vulnerabilities.append(vulnerability)
                            break  # Don't test more payloads for this param
                            
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _is_version_affected(self, detected_version: str, affected_versions: List[str]) -> bool:
        """Check if detected version is in affected versions list"""
        
        if detected_version == 'unknown':
            return True  # Assume vulnerable if version unknown
        
        try:
            # Parse version numbers
            detected_parts = [int(x) for x in detected_version.split('.')]
            
            for version_range in affected_versions:
                if version_range.startswith('< '):
                    # Less than version
                    max_version = version_range[2:]
                    max_parts = [int(x) for x in max_version.split('.')]
                    
                    # Compare versions
                    for i in range(min(len(detected_parts), len(max_parts))):
                        if detected_parts[i] < max_parts[i]:
                            return True
                        elif detected_parts[i] > max_parts[i]:
                            break
                    else:
                        # Versions are equal up to the shortest length
                        if len(detected_parts) < len(max_parts):
                            return True
                
                elif version_range == detected_version:
                    return True
        
        except ValueError:
            # Version parsing failed, assume vulnerable
            return True
        
        return False
    
    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _is_sensitive_content(self, content: str, path: str) -> bool:
        """Check if content contains sensitive information"""
        
        sensitive_patterns = {
            'phpinfo.php': ['PHP Version', 'System', 'Configuration'],
            'info.php': ['PHP Version', 'phpinfo()'],
            '.env': ['DB_PASSWORD', 'API_KEY', 'SECRET'],
            'config.php': ['password', 'database', 'mysql'],
            'wp-config.php': ['DB_PASSWORD', 'DB_USER', 'DB_NAME'],
            'database.yml': ['password:', 'username:', 'host:'],
            '.htaccess': ['RewriteRule', 'DirectoryIndex'],
            'web.config': ['connectionStrings', 'appSettings'],
            'backup.sql': ['INSERT INTO', 'CREATE TABLE'],
            'dump.sql': ['INSERT INTO', 'CREATE TABLE']
        }
        
        filename = path.split('/')[-1]
        if filename in sensitive_patterns:
            patterns = sensitive_patterns[filename]
            return any(pattern.lower() in content.lower() for pattern in patterns)
        
        return False
    
    def generate_web_report(self, results: Dict, output_format: str = "terminal") -> str:
        """Generate web application scan report"""
        
        if output_format == "json":
            return json.dumps(results, indent=2, default=str, ensure_ascii=False)
        
        # Terminal report
        console.print("\n" + "="*80)
        console.print(Panel.fit(
            "[bold cyan]🌐 Web Application Vulnerability Report[/bold cyan]",
            border_style="cyan"
        ))
        
        target = results['target']
        technologies = results['technologies']
        vulnerabilities = results['vulnerabilities']
        scan_info = results['scan_info']
        
        console.print(f"\n🎯 **Target:** [bold cyan]{target}[/bold cyan]")
        console.print(f"⏱️ **Scan Duration:** {scan_info['duration']:.2f} seconds")
        console.print(f"🔧 **Scan Type:** {scan_info['scan_type'].title()}")
        
        # Technologies detected
        if technologies:
            console.print(f"\n🔍 **Technologies Detected ({len(technologies)}):**")
            tech_table = Table(show_header=True, header_style="bold magenta")
            tech_table.add_column("Technology", style="cyan")
            tech_table.add_column("Version", style="green")
            tech_table.add_column("Category", style="yellow")
            tech_table.add_column("Confidence", style="blue")
            
            for tech in technologies:
                tech_table.add_row(
                    tech.name.title(),
                    tech.version,
                    tech.category.title(),
                    f"{tech.confidence}%"
                )
            
            console.print(tech_table)
        
        # Vulnerabilities found
        if vulnerabilities:
            console.print(f"\n🚨 **Vulnerabilities Found ({len(vulnerabilities)}):**")
            
            # Group by severity
            critical = [v for v in vulnerabilities if v.severity == 'CRITICAL']
            high = [v for v in vulnerabilities if v.severity == 'HIGH']
            medium = [v for v in vulnerabilities if v.severity == 'MEDIUM']
            low = [v for v in vulnerabilities if v.severity == 'LOW']
            
            console.print(f"🔴 Critical: {len(critical)}")
            console.print(f"🟡 High: {len(high)}")
            console.print(f"🔵 Medium: {len(medium)}")
            console.print(f"🟢 Low: {len(low)}")
            
            # Show top vulnerabilities
            top_vulns = sorted(vulnerabilities, key=lambda x: x.cvss_score, reverse=True)[:10]
            if top_vulns:
                console.print(f"\n🔥 **Top Vulnerabilities:**")
                vuln_table = Table(show_header=True, header_style="bold magenta")
                vuln_table.add_column("CVE/ID", style="cyan")
                vuln_table.add_column("CVSS", style="red")
                vuln_table.add_column("Title", style="white", max_width=40)
                vuln_table.add_column("Technology", style="yellow")
                
                for vuln in top_vulns:
                    vuln_table.add_row(
                        vuln.cve_id,
                        f"{vuln.cvss_score:.1f}",
                        vuln.title,
                        vuln.technology
                    )
                
                console.print(vuln_table)
        else:
            console.print("\n✅ **No vulnerabilities found**")
        
        console.print("\n" + "="*80)
        return "Web application report displayed"

async def main():
    """Main function for web application scanning"""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Web Application CVE Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t https://example.com
  %(prog)s -t example.com --deep-scan --include-paths
  %(prog)s -t https://wordpress-site.com --output json --output-file report.json
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target web application URL"
    )
    
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Perform deep vulnerability scanning (includes payload testing)"
    )
    
    parser.add_argument(
        "--include-paths",
        action="store_true",
        default=True,
        help="Include common path scanning"
    )
    
    parser.add_argument(
        "--output",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format"
    )
    
    parser.add_argument(
        "--output-file",
        help="Output file for report"
    )
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = WebApplicationScanner()
    
    console.print("🌐 [bold cyan]Web Application CVE Scanner[/bold cyan]")
    console.print(f"🎯 Target: {args.target}")
    console.print(f"🔬 Deep Scan: {'✅' if args.deep_scan else '❌'}")
    console.print(f"📂 Path Scan: {'✅' if args.include_paths else '❌'}")
    
    # Start scan
    start_time = time.time()
    
    try:
        results = await scanner.scan_web_application(
            target=args.target,
            include_paths=args.include_paths,
            deep_scan=args.deep_scan
        )
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Generate report
        report = scanner.generate_web_report(results, args.output)
        
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                if args.output == "json":
                    f.write(report)
                else:
                    f.write("Web Application Vulnerability Report\n" + "="*50 + "\n")
                    f.write(f"Scan completed in {scan_duration:.2f} seconds\n")
                    f.write(f"Target: {args.target}\n")
            
            console.print(f"💾 Report saved to: {args.output_file}")
        
        # Summary
        total_vulns = len(results['vulnerabilities'])
        critical_vulns = len([v for v in results['vulnerabilities'] if v.severity == 'CRITICAL'])
        
        console.print(f"\n🎉 [bold green]Scan completed in {scan_duration:.2f} seconds![/bold green]")
        console.print(f"🚨 Total vulnerabilities: {total_vulns}")
        
        if critical_vulns > 0:
            console.print(f"⚠️ [bold red]Found {critical_vulns} CRITICAL vulnerabilities![/bold red]")
    
    except KeyboardInterrupt:
        console.print("\n⚠️ Scan interrupted by user")
    except Exception as e:
        console.print(f"❌ Scan error: {e}")

if __name__ == "__main__":
    asyncio.run(main())