#!/usr/bin/env python3
"""
Advanced Nmap-Based CVE Discovery Tool
=====================================

A cybersecurity reconnaissance tool that performs deep scanning of web targets
using Nmap, then automatically extracts and reports known vulnerabilities (CVEs)
based on detected service versions.

Author: Security Research Team
License: MIT
"""

import sys
import json
import re
import time
import argparse
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import nmap
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from colorama import init, Fore, Style
from tabulate import tabulate
from jinja2 import Template

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Rich console for beautiful output
console = Console()

@dataclass
class CVEInfo:
    """Data class to store CVE information"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published_date: str
    service: str
    port: int
    exploit_available: bool = False
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

@dataclass
class ServiceInfo:
    """Data class to store service information"""
    port: int
    protocol: str
    service: str
    version: str
    product: str
    extrainfo: str
    cpes: List[str] = None
    
    def __post_init__(self):
        if self.cpes is None:
            self.cpes = []

class VulnersAPI:
    """Interface to Vulners vulnerability database"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://vulners.com/api/v3"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NmapCVEFinder/1.0'
        })
    
    def search_cve_by_cpe(self, cpe: str, limit: int = 50) -> List[Dict]:
        """Search for CVEs by CPE identifier"""
        try:
            url = f"{self.base_url}/search/lucene/"
            data = {
                'query': f'affectedSoftware.cpe23:"{cpe}"',
                'sort': 'cvss.score',
                'order': 'desc',
                'size': limit
            }
            
            if self.api_key:
                data['apiKey'] = self.api_key
            
            response = self.session.post(url, json=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if result.get('result') == 'OK':
                return result.get('data', {}).get('search', [])
            return []
            
        except Exception as e:
            console.print(f"[yellow]Warning: Vulners API error: {e}[/yellow]")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get detailed information about a specific CVE"""
        try:
            url = f"{self.base_url}/search/id/"
            data = {
                'id': cve_id
            }
            
            if self.api_key:
                data['apiKey'] = self.api_key
            
            response = self.session.post(url, json=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if result.get('result') == 'OK':
                documents = result.get('data', {}).get('documents', {})
                return documents.get(cve_id, {})
            return None
            
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get CVE details for {cve_id}: {e}[/yellow]")
            return None

class NmapCVEScanner:
    """Main scanner class that orchestrates the vulnerability discovery process"""
    
    def __init__(self, vulners_api_key: Optional[str] = None):
        self.nm = nmap.PortScanner()
        self.vulners_api = VulnersAPI(vulners_api_key)
        self.services: List[ServiceInfo] = []
        self.vulnerabilities: List[CVEInfo] = []
        
    def scan_target(self, target: str, ports: str = "1-65535", 
                   scan_type: str = "comprehensive") -> bool:
        """
        Perform Nmap scan on target
        
        Args:
            target: IP address or hostname to scan
            ports: Port range to scan (default: 1-65535)
            scan_type: Type of scan (quick, comprehensive, stealth)
        """
        try:
            console.print(f"[cyan]Starting scan of {target}...[/cyan]")
            
            # Define scan arguments based on scan type
            scan_args = {
                "quick": "-sV --version-intensity 5 -T4",
                "comprehensive": "-sV -sC --version-intensity 9 -T4 --script vulners,vuln",
                "stealth": "-sV -sS -T2 --version-intensity 5"
            }
            
            args = scan_args.get(scan_type, scan_args["comprehensive"])
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Scanning ports and services...", total=None)
                
                # Perform the scan
                self.nm.scan(target, ports, arguments=args)
                
                progress.update(task, description="Processing scan results...")
                
                # Process results
                self._process_scan_results(target)
                
                progress.update(task, description="Scan completed!", completed=True)
            
            return True
            
        except Exception as e:
            console.print(f"[red]Error during scan: {e}[/red]")
            return False
    
    def _process_scan_results(self, target: str):
        """Process Nmap scan results and extract service information"""
        self.services.clear()
        
        if target not in self.nm.all_hosts():
            console.print(f"[yellow]No results found for {target}[/yellow]")
            return
        
        host_info = self.nm[target]
        
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()
            
            for port in ports:
                port_info = host_info[protocol][port]
                
                if port_info['state'] == 'open':
                    service = ServiceInfo(
                        port=port,
                        protocol=protocol,
                        service=port_info.get('name', 'unknown'),
                        version=port_info.get('version', ''),
                        product=port_info.get('product', ''),
                        extrainfo=port_info.get('extrainfo', ''),
                        cpes=port_info.get('cpe', [])
                    )
                    self.services.append(service)
    
    def discover_vulnerabilities(self, min_cvss: float = 0.0, 
                               service_filter: Optional[str] = None) -> List[CVEInfo]:
        """
        Discover vulnerabilities for detected services
        
        Args:
            min_cvss: Minimum CVSS score to include (0.0-10.0)
            service_filter: Filter by service name (e.g., 'apache', 'ssh')
        """
        self.vulnerabilities.clear()
        
        console.print("[cyan]Discovering vulnerabilities...[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for service in self.services:
                if service_filter and service_filter.lower() not in service.service.lower():
                    continue
                
                task = progress.add_task(
                    f"Checking {service.service} on port {service.port}...", 
                    total=None
                )
                
                # Search by CPE if available
                for cpe in service.cpes:
                    vulns = self.vulners_api.search_cve_by_cpe(cpe)
                    
                    for vuln in vulns:
                        cvss_score = self._extract_cvss_score(vuln)
                        
                        if cvss_score >= min_cvss:
                            cve_info = self._create_cve_info(vuln, service, cvss_score)
                            if cve_info:
                                self.vulnerabilities.append(cve_info)
                
                # Also try version-based search if no CPE results
                if not service.cpes and service.product and service.version:
                    self._search_by_version(service, min_cvss)
                
                progress.remove_task(task)
        
        # Remove duplicates and sort by CVSS score
        self.vulnerabilities = self._deduplicate_cves()
        self.vulnerabilities.sort(key=lambda x: x.cvss_score, reverse=True)
        
        return self.vulnerabilities
    
    def _extract_cvss_score(self, vuln_data: Dict) -> float:
        """Extract CVSS score from vulnerability data"""
        try:
            # Try different possible locations for CVSS score
            cvss_paths = [
                ['cvss', 'score'],
                ['cvss2', 'cvssScore'],
                ['cvss3', 'cvssScore'],
                ['_source', 'cvss', 'score']
            ]
            
            for path in cvss_paths:
                try:
                    score = vuln_data
                    for key in path:
                        score = score[key]
                    return float(score)
                except (KeyError, TypeError, ValueError):
                    continue
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _create_cve_info(self, vuln_data: Dict, service: ServiceInfo, 
                        cvss_score: float) -> Optional[CVEInfo]:
        """Create CVEInfo object from vulnerability data"""
        try:
            cve_id = vuln_data.get('_source', {}).get('id', 
                                 vuln_data.get('id', 'Unknown'))
            
            if not cve_id.startswith('CVE-'):
                return None
            
            description = vuln_data.get('_source', {}).get('description', 
                                      vuln_data.get('title', 'No description available'))
            
            # Determine severity based on CVSS score
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            published_date = vuln_data.get('_source', {}).get('published', 
                                         vuln_data.get('published', 'Unknown'))
            
            # Check for exploit availability (simplified check)
            exploit_available = any(
                keyword in description.lower() 
                for keyword in ['exploit', 'poc', 'metasploit', 'exploit-db']
            )
            
            references = vuln_data.get('_source', {}).get('references', [])
            if isinstance(references, dict):
                references = list(references.values())
            
            return CVEInfo(
                cve_id=cve_id,
                description=description[:200] + "..." if len(description) > 200 else description,
                cvss_score=cvss_score,
                severity=severity,
                published_date=published_date,
                service=f"{service.product} {service.version}".strip(),
                port=service.port,
                exploit_available=exploit_available,
                references=references[:3]  # Limit to first 3 references
            )
            
        except Exception as e:
            console.print(f"[yellow]Warning: Error processing vulnerability data: {e}[/yellow]")
            return None
    
    def _search_by_version(self, service: ServiceInfo, min_cvss: float):
        """Search for vulnerabilities by service version"""
        # This is a simplified version search - in practice, you'd want more sophisticated matching
        if not service.product or not service.version:
            return
        
        search_query = f"{service.product} {service.version}"
        # Implementation would depend on having a local CVE database or additional API calls
        pass
    
    def _deduplicate_cves(self) -> List[CVEInfo]:
        """Remove duplicate CVEs"""
        seen = set()
        unique_cves = []
        
        for cve in self.vulnerabilities:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                unique_cves.append(cve)
        
        return unique_cves
    
    def generate_report(self, output_format: str = "terminal", 
                       output_file: Optional[str] = None) -> str:
        """
        Generate vulnerability report in specified format
        
        Args:
            output_format: Format for output (terminal, json, html, markdown)
            output_file: File to save report to (optional)
        """
        if output_format == "terminal":
            return self._generate_terminal_report()
        elif output_format == "json":
            return self._generate_json_report(output_file)
        elif output_format == "html":
            return self._generate_html_report(output_file)
        elif output_format == "markdown":
            return self._generate_markdown_report(output_file)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_terminal_report(self) -> str:
        """Generate colorized terminal report"""
        console.print("\n" + "="*80)
        console.print(Panel.fit(
            "[bold cyan]🔍 Nmap CVE Discovery Report[/bold cyan]",
            border_style="cyan"
        ))
        
        # Services summary
        if self.services:
            console.print(f"\n[bold green]📋 Discovered Services ({len(self.services)})[/bold green]")
            
            services_table = Table(show_header=True, header_style="bold magenta")
            services_table.add_column("Port", style="cyan")
            services_table.add_column("Service", style="green")
            services_table.add_column("Version", style="yellow")
            
            for service in self.services:
                version_info = f"{service.product} {service.version}".strip()
                if not version_info:
                    version_info = "Unknown"
                
                services_table.add_row(
                    f"{service.port}/{service.protocol}",
                    service.service,
                    version_info
                )
            
            console.print(services_table)
        
        # Vulnerabilities summary
        if self.vulnerabilities:
            console.print(f"\n[bold red]🚨 Discovered Vulnerabilities ({len(self.vulnerabilities)})[/bold red]")
            
            # Group by severity
            severity_counts = {}
            for vuln in self.vulnerabilities:
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            
            console.print(f"[red]Critical: {severity_counts.get('CRITICAL', 0)}[/red] | "
                         f"[yellow]High: {severity_counts.get('HIGH', 0)}[/yellow] | "
                         f"[blue]Medium: {severity_counts.get('MEDIUM', 0)}[/blue] | "
                         f"[green]Low: {severity_counts.get('LOW', 0)}[/green]")
            
            vulns_table = Table(show_header=True, header_style="bold magenta")
            vulns_table.add_column("CVE ID", style="cyan")
            vulns_table.add_column("Severity", style="bold")
            vulns_table.add_column("CVSS", style="yellow")
            vulns_table.add_column("Service", style="green")
            vulns_table.add_column("Port", style="blue")
            vulns_table.add_column("Description", style="white", max_width=50)
            
            for vuln in self.vulnerabilities[:20]:  # Show top 20
                severity_color = {
                    "CRITICAL": "red",
                    "HIGH": "yellow", 
                    "MEDIUM": "blue",
                    "LOW": "green"
                }.get(vuln.severity, "white")
                
                vulns_table.add_row(
                    vuln.cve_id,
                    f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                    f"{vuln.cvss_score:.1f}",
                    vuln.service,
                    str(vuln.port),
                    vuln.description
                )
            
            console.print(vulns_table)
            
            if len(self.vulnerabilities) > 20:
                console.print(f"[yellow]... and {len(self.vulnerabilities) - 20} more vulnerabilities[/yellow]")
        else:
            console.print("\n[green]✅ No vulnerabilities found![/green]")
        
        console.print("\n" + "="*80)
        return "Terminal report displayed"
    
    def _generate_json_report(self, output_file: Optional[str] = None) -> str:
        """Generate JSON report"""
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "tool": "NmapCVEFinder",
                "version": "1.0"
            },
            "services": [asdict(service) for service in self.services],
            "vulnerabilities": [asdict(vuln) for vuln in self.vulnerabilities],
            "summary": {
                "total_services": len(self.services),
                "total_vulnerabilities": len(self.vulnerabilities),
                "severity_breakdown": self._get_severity_breakdown()
            }
        }
        
        json_output = json.dumps(report_data, indent=2, default=str)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            console.print(f"[green]JSON report saved to {output_file}[/green]")
        
        return json_output
    
    def _generate_html_report(self, output_file: Optional[str] = None) -> str:
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap CVE Discovery Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: flex; justify-content: space-around; margin-bottom: 30px; }
        .stat-box { text-align: center; padding: 20px; background: #ecf0f1; border-radius: 8px; }
        .stat-number { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .severity-critical { color: #e74c3c; }
        .severity-high { color: #f39c12; }
        .severity-medium { color: #3498db; }
        .severity-low { color: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .cve-id { font-weight: bold; color: #2c3e50; }
        .description { max-width: 300px; word-wrap: break-word; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Nmap CVE Discovery Report</h1>
            <p>Generated on {{ timestamp }}</p>
        </div>
        
        <div class="summary">
            <div class="stat-box">
                <div class="stat-number">{{ total_services }}</div>
                <div>Services Detected</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ total_vulnerabilities }}</div>
                <div>Vulnerabilities Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-critical">{{ critical_count }}</div>
                <div>Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-high">{{ high_count }}</div>
                <div>High</div>
            </div>
        </div>
        
        <h2>📋 Discovered Services</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Product</th>
                </tr>
            </thead>
            <tbody>
                {% for service in services %}
                <tr>
                    <td>{{ service.port }}/{{ service.protocol }}</td>
                    <td>{{ service.service }}</td>
                    <td>{{ service.version or 'Unknown' }}</td>
                    <td>{{ service.product or 'Unknown' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <h2>🚨 Discovered Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th>CVSS Score</th>
                    <th>Service</th>
                    <th>Port</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td class="cve-id">{{ vuln.cve_id }}</td>
                    <td class="severity-{{ vuln.severity.lower() }}">{{ vuln.severity }}</td>
                    <td>{{ "%.1f"|format(vuln.cvss_score) }}</td>
                    <td>{{ vuln.service }}</td>
                    <td>{{ vuln.port }}</td>
                    <td class="description">{{ vuln.description }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        severity_breakdown = self._get_severity_breakdown()
        
        html_output = template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_services=len(self.services),
            total_vulnerabilities=len(self.vulnerabilities),
            critical_count=severity_breakdown.get('CRITICAL', 0),
            high_count=severity_breakdown.get('HIGH', 0),
            services=self.services,
            vulnerabilities=self.vulnerabilities
        )
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(html_output)
            console.print(f"[green]HTML report saved to {output_file}[/green]")
        
        return html_output
    
    def _generate_markdown_report(self, output_file: Optional[str] = None) -> str:
        """Generate Markdown report"""
        md_lines = [
            "# 🔍 Nmap CVE Discovery Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Tool:** NmapCVEFinder v1.0",
            "",
            "## 📊 Summary",
            "",
            f"- **Services Detected:** {len(self.services)}",
            f"- **Vulnerabilities Found:** {len(self.vulnerabilities)}",
            ""
        ]
        
        # Severity breakdown
        severity_breakdown = self._get_severity_breakdown()
        md_lines.extend([
            "### Severity Breakdown",
            "",
            f"- 🔴 **Critical:** {severity_breakdown.get('CRITICAL', 0)}",
            f"- 🟡 **High:** {severity_breakdown.get('HIGH', 0)}",
            f"- 🔵 **Medium:** {severity_breakdown.get('MEDIUM', 0)}",
            f"- 🟢 **Low:** {severity_breakdown.get('LOW', 0)}",
            ""
        ])
        
        # Services table
        if self.services:
            md_lines.extend([
                "## 📋 Discovered Services",
                "",
                "| Port | Service | Version | Product |",
                "|------|---------|---------|---------|"
            ])
            
            for service in self.services:
                version = service.version or 'Unknown'
                product = service.product or 'Unknown'
                md_lines.append(f"| {service.port}/{service.protocol} | {service.service} | {version} | {product} |")
            
            md_lines.append("")
        
        # Vulnerabilities table
        if self.vulnerabilities:
            md_lines.extend([
                "## 🚨 Discovered Vulnerabilities",
                "",
                "| CVE ID | Severity | CVSS | Service | Port | Description |",
                "|--------|----------|------|---------|------|-------------|"
            ])
            
            for vuln in self.vulnerabilities:
                severity_emoji = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟡", 
                    "MEDIUM": "🔵",
                    "LOW": "🟢"
                }.get(vuln.severity, "⚪")
                
                description = vuln.description.replace('|', '\\|')  # Escape pipes for markdown
                md_lines.append(
                    f"| {vuln.cve_id} | {severity_emoji} {vuln.severity} | {vuln.cvss_score:.1f} | "
                    f"{vuln.service} | {vuln.port} | {description} |"
                )
        
        md_output = "\n".join(md_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(md_output)
            console.print(f"[green]Markdown report saved to {output_file}[/green]")
        
        return md_output
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity"""
        breakdown = {}
        for vuln in self.vulnerabilities:
            breakdown[vuln.severity] = breakdown.get(vuln.severity, 0) + 1
        return breakdown

def main():
    """Main entry point for the CLI application"""
    parser = argparse.ArgumentParser(
        description="Advanced Nmap-Based CVE Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 --scan-type comprehensive
  %(prog)s -t example.com -p 80,443,22 --min-cvss 7.0
  %(prog)s -t 10.0.0.0/24 --output json --output-file report.json
  %(prog)s -t target.com --service-filter apache --output html
        """
    )
    
    # Required arguments
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address, hostname, or CIDR range"
    )
    
    # Optional arguments
    parser.add_argument(
        "-p", "--ports",
        default="1-65535",
        help="Port range to scan (default: 1-65535)"
    )
    
    parser.add_argument(
        "--scan-type",
        choices=["quick", "comprehensive", "stealth"],
        default="comprehensive",
        help="Type of scan to perform (default: comprehensive)"
    )
    
    parser.add_argument(
        "--min-cvss",
        type=float,
        default=0.0,
        help="Minimum CVSS score to include (0.0-10.0, default: 0.0)"
    )
    
    parser.add_argument(
        "--service-filter",
        help="Filter results by service name (e.g., 'apache', 'ssh')"
    )
    
    parser.add_argument(
        "--output",
        choices=["terminal", "json", "html", "markdown"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    
    parser.add_argument(
        "--output-file",
        help="File to save report to (required for non-terminal output)"
    )
    
    parser.add_argument(
        "--vulners-api-key",
        help="Vulners API key for enhanced vulnerability data"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.output != "terminal" and not args.output_file:
        parser.error(f"--output-file is required when using --output {args.output}")
    
    if args.min_cvss < 0.0 or args.min_cvss > 10.0:
        parser.error("--min-cvss must be between 0.0 and 10.0")
    
    # Initialize scanner
    try:
        scanner = NmapCVEScanner(args.vulners_api_key)
        
        # Perform scan
        console.print(f"[bold cyan]🎯 Target: {args.target}[/bold cyan]")
        console.print(f"[cyan]Ports: {args.ports}[/cyan]")
        console.print(f"[cyan]Scan Type: {args.scan_type}[/cyan]")
        
        if not scanner.scan_target(args.target, args.ports, args.scan_type):
            console.print("[red]❌ Scan failed![/red]")
            sys.exit(1)
        
        # Discover vulnerabilities
        vulnerabilities = scanner.discover_vulnerabilities(
            min_cvss=args.min_cvss,
            service_filter=args.service_filter
        )
        
        # Generate report
        report = scanner.generate_report(args.output, args.output_file)
        
        if args.output == "terminal":
            # Terminal output already displayed
            pass
        else:
            console.print(f"[green]✅ Report generated successfully![/green]")
        
        # Summary
        console.print(f"\n[bold green]🎉 Scan completed![/bold green]")
        console.print(f"[green]Services found: {len(scanner.services)}[/green]")
        console.print(f"[green]Vulnerabilities found: {len(vulnerabilities)}[/green]")
        
        if vulnerabilities:
            critical_count = sum(1 for v in vulnerabilities if v.severity == "CRITICAL")
            high_count = sum(1 for v in vulnerabilities if v.severity == "HIGH")
            
            if critical_count > 0:
                console.print(f"[red]⚠️  {critical_count} CRITICAL vulnerabilities found![/red]")
            if high_count > 0:
                console.print(f"[yellow]⚠️  {high_count} HIGH severity vulnerabilities found![/yellow]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        if args.verbose:
            import traceback
            console.print(f"[red]{traceback.format_exc()}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()