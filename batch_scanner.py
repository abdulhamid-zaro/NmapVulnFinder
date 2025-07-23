#!/usr/bin/env python3
"""
Batch Scanner for Nmap CVE Discovery Tool
=========================================

This utility allows scanning multiple targets in batch mode with
consolidated reporting and parallel processing capabilities.
"""

import sys
import json
import time
import argparse
import ipaddress
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from nmap_cve_finder import NmapCVEScanner, CVEInfo, ServiceInfo
from config import config

console = Console()

class BatchScanner:
    """Batch scanner for multiple targets"""
    
    def __init__(self, vulners_api_key: Optional[str] = None, max_workers: int = 5):
        self.vulners_api_key = vulners_api_key
        self.max_workers = max_workers
        self.results: Dict[str, Dict] = {}
        self.failed_targets: List[str] = []
        
    def load_targets_from_file(self, file_path: str) -> List[str]:
        """Load targets from a file (one per line)"""
        try:
            with open(file_path, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            console.print(f"[green]Loaded {len(targets)} targets from {file_path}[/green]")
            return targets
            
        except FileNotFoundError:
            console.print(f"[red]Error: File {file_path} not found[/red]")
            return []
        except Exception as e:
            console.print(f"[red]Error loading targets: {e}[/red]")
            return []
    
    def expand_cidr_ranges(self, targets: List[str]) -> List[str]:
        """Expand CIDR ranges into individual IP addresses"""
        expanded_targets = []
        
        for target in targets:
            try:
                # Check if it's a CIDR range
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    # Limit expansion to avoid scanning too many hosts
                    if network.num_addresses > 256:
                        console.print(f"[yellow]Warning: CIDR range {target} has {network.num_addresses} addresses. Limiting to first 256.[/yellow]")
                        expanded_targets.extend([str(ip) for ip in list(network.hosts())[:256]])
                    else:
                        expanded_targets.extend([str(ip) for ip in network.hosts()])
                else:
                    expanded_targets.append(target)
                    
            except ipaddress.AddressValueError:
                # Not an IP address, probably a hostname
                expanded_targets.append(target)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not process target {target}: {e}[/yellow]")
                expanded_targets.append(target)
        
        return expanded_targets
    
    def scan_single_target(self, target: str, ports: str, scan_type: str,
                          min_cvss: float, service_filter: Optional[str]) -> Dict:
        """Scan a single target and return results"""
        try:
            scanner = NmapCVEScanner(self.vulners_api_key)
            
            # Perform scan
            if not scanner.scan_target(target, ports, scan_type):
                return {
                    "target": target,
                    "status": "failed",
                    "error": "Scan failed",
                    "services": [],
                    "vulnerabilities": []
                }
            
            # Discover vulnerabilities
            vulnerabilities = scanner.discover_vulnerabilities(min_cvss, service_filter)
            
            return {
                "target": target,
                "status": "success",
                "scan_time": datetime.now().isoformat(),
                "services": [
                    {
                        "port": s.port,
                        "protocol": s.protocol,
                        "service": s.service,
                        "version": s.version,
                        "product": s.product,
                        "extrainfo": s.extrainfo,
                        "cpes": s.cpes
                    } for s in scanner.services
                ],
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "description": v.description,
                        "cvss_score": v.cvss_score,
                        "severity": v.severity,
                        "published_date": v.published_date,
                        "service": v.service,
                        "port": v.port,
                        "exploit_available": v.exploit_available,
                        "references": v.references
                    } for v in vulnerabilities
                ],
                "summary": {
                    "total_services": len(scanner.services),
                    "total_vulnerabilities": len(vulnerabilities),
                    "critical_count": sum(1 for v in vulnerabilities if v.severity == "CRITICAL"),
                    "high_count": sum(1 for v in vulnerabilities if v.severity == "HIGH"),
                    "medium_count": sum(1 for v in vulnerabilities if v.severity == "MEDIUM"),
                    "low_count": sum(1 for v in vulnerabilities if v.severity == "LOW")
                }
            }
            
        except Exception as e:
            return {
                "target": target,
                "status": "failed", 
                "error": str(e),
                "services": [],
                "vulnerabilities": []
            }
    
    def scan_targets(self, targets: List[str], ports: str = "1-65535",
                    scan_type: str = "comprehensive", min_cvss: float = 0.0,
                    service_filter: Optional[str] = None) -> Dict[str, Dict]:
        """Scan multiple targets in parallel"""
        
        console.print(f"[cyan]Starting batch scan of {len(targets)} targets...[/cyan]")
        console.print(f"[cyan]Max workers: {self.max_workers}[/cyan]")
        console.print(f"[cyan]Scan type: {scan_type}[/cyan]")
        console.print(f"[cyan]Ports: {ports}[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            main_task = progress.add_task("Scanning targets...", total=len(targets))
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all scan tasks
                future_to_target = {
                    executor.submit(
                        self.scan_single_target, 
                        target, ports, scan_type, min_cvss, service_filter
                    ): target for target in targets
                }
                
                # Process completed scans
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    
                    try:
                        result = future.result()
                        self.results[target] = result
                        
                        if result["status"] == "success":
                            vuln_count = result["summary"]["total_vulnerabilities"]
                            critical_count = result["summary"]["critical_count"]
                            
                            status_msg = f"✅ {target}: {vuln_count} vulns"
                            if critical_count > 0:
                                status_msg += f" ({critical_count} critical)"
                            
                            progress.console.print(f"[green]{status_msg}[/green]")
                        else:
                            self.failed_targets.append(target)
                            progress.console.print(f"[red]❌ {target}: {result.get('error', 'Unknown error')}[/red]")
                            
                    except Exception as e:
                        self.failed_targets.append(target)
                        progress.console.print(f"[red]❌ {target}: {str(e)}[/red]")
                    
                    progress.advance(main_task)
        
        return self.results
    
    def generate_consolidated_report(self, output_format: str = "terminal",
                                   output_file: Optional[str] = None) -> str:
        """Generate consolidated report from all scan results"""
        
        if output_format == "terminal":
            return self._generate_terminal_summary()
        elif output_format == "json":
            return self._generate_json_report(output_file)
        elif output_format == "html":
            return self._generate_html_report(output_file)
        elif output_format == "csv":
            return self._generate_csv_report(output_file)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_terminal_summary(self) -> str:
        """Generate terminal summary of batch scan results"""
        
        console.print("\n" + "="*100)
        console.print(Panel.fit(
            "[bold cyan]📊 Batch Scan Summary Report[/bold cyan]",
            border_style="cyan"
        ))
        
        # Overall statistics
        total_targets = len(self.results)
        successful_scans = sum(1 for r in self.results.values() if r["status"] == "success")
        failed_scans = len(self.failed_targets)
        
        total_services = sum(r["summary"]["total_services"] for r in self.results.values() 
                           if r["status"] == "success")
        total_vulnerabilities = sum(r["summary"]["total_vulnerabilities"] for r in self.results.values()
                                  if r["status"] == "success")
        
        # Severity breakdown
        total_critical = sum(r["summary"]["critical_count"] for r in self.results.values()
                           if r["status"] == "success")
        total_high = sum(r["summary"]["high_count"] for r in self.results.values()
                       if r["status"] == "success")
        total_medium = sum(r["summary"]["medium_count"] for r in self.results.values()
                         if r["status"] == "success")
        total_low = sum(r["summary"]["low_count"] for r in self.results.values()
                      if r["status"] == "success")
        
        # Summary table
        summary_table = Table(show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="green")
        
        summary_table.add_row("Total Targets", str(total_targets))
        summary_table.add_row("Successful Scans", str(successful_scans))
        summary_table.add_row("Failed Scans", str(failed_scans))
        summary_table.add_row("Total Services", str(total_services))
        summary_table.add_row("Total Vulnerabilities", str(total_vulnerabilities))
        summary_table.add_row("Critical Vulnerabilities", f"[red]{total_critical}[/red]")
        summary_table.add_row("High Vulnerabilities", f"[yellow]{total_high}[/yellow]")
        summary_table.add_row("Medium Vulnerabilities", f"[blue]{total_medium}[/blue]")
        summary_table.add_row("Low Vulnerabilities", f"[green]{total_low}[/green]")
        
        console.print(summary_table)
        
        # Top vulnerable targets
        if total_vulnerabilities > 0:
            console.print(f"\n[bold red]🎯 Most Vulnerable Targets[/bold red]")
            
            vulnerable_targets = [
                (target, result["summary"]["total_vulnerabilities"], result["summary"]["critical_count"])
                for target, result in self.results.items()
                if result["status"] == "success" and result["summary"]["total_vulnerabilities"] > 0
            ]
            
            # Sort by total vulnerabilities, then by critical count
            vulnerable_targets.sort(key=lambda x: (x[1], x[2]), reverse=True)
            
            vuln_table = Table(show_header=True, header_style="bold magenta")
            vuln_table.add_column("Target", style="cyan")
            vuln_table.add_column("Total Vulns", style="yellow")
            vuln_table.add_column("Critical", style="red")
            vuln_table.add_column("High", style="yellow")
            vuln_table.add_column("Medium", style="blue")
            vuln_table.add_column("Low", style="green")
            
            for target, _, _ in vulnerable_targets[:10]:  # Top 10
                result = self.results[target]
                summary = result["summary"]
                
                vuln_table.add_row(
                    target,
                    str(summary["total_vulnerabilities"]),
                    str(summary["critical_count"]),
                    str(summary["high_count"]),
                    str(summary["medium_count"]),
                    str(summary["low_count"])
                )
            
            console.print(vuln_table)
        
        # Failed targets
        if self.failed_targets:
            console.print(f"\n[bold red]❌ Failed Targets ({len(self.failed_targets)})[/bold red]")
            for target in self.failed_targets:
                error = self.results.get(target, {}).get("error", "Unknown error")
                console.print(f"[red]• {target}: {error}[/red]")
        
        console.print("\n" + "="*100)
        return "Terminal summary displayed"
    
    def _generate_json_report(self, output_file: Optional[str] = None) -> str:
        """Generate JSON report of batch scan results"""
        
        report_data = {
            "batch_scan_info": {
                "timestamp": datetime.now().isoformat(),
                "tool": "NmapCVEFinder Batch Scanner",
                "version": "1.0",
                "total_targets": len(self.results),
                "successful_scans": sum(1 for r in self.results.values() if r["status"] == "success"),
                "failed_scans": len(self.failed_targets)
            },
            "summary": {
                "total_services": sum(r["summary"]["total_services"] for r in self.results.values() 
                                    if r["status"] == "success"),
                "total_vulnerabilities": sum(r["summary"]["total_vulnerabilities"] for r in self.results.values()
                                           if r["status"] == "success"),
                "severity_breakdown": {
                    "critical": sum(r["summary"]["critical_count"] for r in self.results.values()
                                  if r["status"] == "success"),
                    "high": sum(r["summary"]["high_count"] for r in self.results.values()
                              if r["status"] == "success"),
                    "medium": sum(r["summary"]["medium_count"] for r in self.results.values()
                                if r["status"] == "success"),
                    "low": sum(r["summary"]["low_count"] for r in self.results.values()
                             if r["status"] == "success")
                }
            },
            "scan_results": self.results,
            "failed_targets": self.failed_targets
        }
        
        json_output = json.dumps(report_data, indent=2, default=str)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            console.print(f"[green]Batch JSON report saved to {output_file}[/green]")
        
        return json_output
    
    def _generate_csv_report(self, output_file: Optional[str] = None) -> str:
        """Generate CSV report of vulnerabilities from batch scan"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Target", "CVE ID", "Severity", "CVSS Score", "Service", "Port",
            "Description", "Published Date", "Exploit Available"
        ])
        
        # Write vulnerability data
        for target, result in self.results.items():
            if result["status"] == "success":
                for vuln in result["vulnerabilities"]:
                    writer.writerow([
                        target,
                        vuln["cve_id"],
                        vuln["severity"],
                        vuln["cvss_score"],
                        vuln["service"],
                        vuln["port"],
                        vuln["description"],
                        vuln["published_date"],
                        vuln["exploit_available"]
                    ])
        
        csv_output = output.getvalue()
        output.close()
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(csv_output)
            console.print(f"[green]CSV report saved to {output_file}[/green]")
        
        return csv_output
    
    def _generate_html_report(self, output_file: Optional[str] = None) -> str:
        """Generate HTML report for batch scan results"""
        from jinja2 import Template
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Batch Scan CVE Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-box { text-align: center; padding: 20px; background: #ecf0f1; border-radius: 8px; }
        .stat-number { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .severity-critical { color: #e74c3c; }
        .severity-high { color: #f39c12; }
        .severity-medium { color: #3498db; }
        .severity-low { color: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; font-size: 0.9em; }
        th { background-color: #34495e; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .target-section { margin-bottom: 40px; border: 1px solid #ddd; border-radius: 8px; padding: 20px; }
        .target-header { background: #34495e; color: white; padding: 10px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; }
        .no-vulns { color: #27ae60; font-style: italic; }
        .failed-target { background: #fee; border-left: 4px solid #e74c3c; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Batch Scan CVE Discovery Report</h1>
            <p>Generated on {{ timestamp }}</p>
            <p>{{ total_targets }} targets scanned ({{ successful_scans }} successful, {{ failed_scans }} failed)</p>
        </div>
        
        <div class="summary">
            <div class="stat-box">
                <div class="stat-number">{{ total_services }}</div>
                <div>Total Services</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ total_vulnerabilities }}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-critical">{{ critical_count }}</div>
                <div>Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-high">{{ high_count }}</div>
                <div>High</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-medium">{{ medium_count }}</div>
                <div>Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-low">{{ low_count }}</div>
                <div>Low</div>
            </div>
        </div>
        
        {% for target, result in results.items() %}
        <div class="target-section {% if result.status == 'failed' %}failed-target{% endif %}">
            <div class="target-header">
                <h2>🎯 {{ target }}</h2>
                {% if result.status == 'success' %}
                <p>{{ result.summary.total_services }} services, {{ result.summary.total_vulnerabilities }} vulnerabilities</p>
                {% else %}
                <p style="color: #e74c3c;">❌ Scan failed: {{ result.error }}</p>
                {% endif %}
            </div>
            
            {% if result.status == 'success' %}
                {% if result.vulnerabilities %}
                <table>
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Severity</th>
                            <th>CVSS</th>
                            <th>Service</th>
                            <th>Port</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for vuln in result.vulnerabilities %}
                        <tr>
                            <td><strong>{{ vuln.cve_id }}</strong></td>
                            <td class="severity-{{ vuln.severity.lower() }}">{{ vuln.severity }}</td>
                            <td>{{ "%.1f"|format(vuln.cvss_score) }}</td>
                            <td>{{ vuln.service }}</td>
                            <td>{{ vuln.port }}</td>
                            <td>{{ vuln.description[:100] }}{% if vuln.description|length > 100 %}...{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p class="no-vulns">✅ No vulnerabilities found</p>
                {% endif %}
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        
        # Calculate summary statistics
        total_services = sum(r["summary"]["total_services"] for r in self.results.values() 
                           if r["status"] == "success")
        total_vulnerabilities = sum(r["summary"]["total_vulnerabilities"] for r in self.results.values()
                                  if r["status"] == "success")
        critical_count = sum(r["summary"]["critical_count"] for r in self.results.values()
                           if r["status"] == "success")
        high_count = sum(r["summary"]["high_count"] for r in self.results.values()
                       if r["status"] == "success")
        medium_count = sum(r["summary"]["medium_count"] for r in self.results.values()
                         if r["status"] == "success")
        low_count = sum(r["summary"]["low_count"] for r in self.results.values()
                      if r["status"] == "success")
        
        html_output = template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_targets=len(self.results),
            successful_scans=sum(1 for r in self.results.values() if r["status"] == "success"),
            failed_scans=len(self.failed_targets),
            total_services=total_services,
            total_vulnerabilities=total_vulnerabilities,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            results=self.results
        )
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(html_output)
            console.print(f"[green]HTML batch report saved to {output_file}[/green]")
        
        return html_output

def main():
    """Main entry point for batch scanner"""
    parser = argparse.ArgumentParser(
        description="Batch Scanner for Nmap CVE Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f targets.txt --scan-type quick
  %(prog)s -f subnets.txt -p 80,443,22 --min-cvss 7.0 --workers 10
  %(prog)s -t 192.168.1.0/24,10.0.0.1,example.com --output json --output-file batch_report.json
        """
    )
    
    # Target specification (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-f", "--file",
        help="File containing targets (one per line)"
    )
    target_group.add_argument(
        "-t", "--targets",
        help="Comma-separated list of targets"
    )
    
    # Scan options
    parser.add_argument(
        "-p", "--ports",
        default="1-65535",
        help="Port range to scan (default: 1-65535)"
    )
    
    parser.add_argument(
        "--scan-type",
        choices=["quick", "comprehensive", "stealth", "aggressive"],
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
        "--workers",
        type=int,
        default=5,
        help="Number of parallel workers (default: 5)"
    )
    
    # Output options
    parser.add_argument(
        "--output",
        choices=["terminal", "json", "html", "csv"],
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
        "--expand-cidrs",
        action="store_true",
        help="Expand CIDR ranges into individual IP addresses"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.output != "terminal" and not args.output_file:
        parser.error(f"--output-file is required when using --output {args.output}")
    
    if args.min_cvss < 0.0 or args.min_cvss > 10.0:
        parser.error("--min-cvss must be between 0.0 and 10.0")
    
    if args.workers < 1 or args.workers > 50:
        parser.error("--workers must be between 1 and 50")
    
    # Load targets
    if args.file:
        targets = BatchScanner().load_targets_from_file(args.file)
    else:
        targets = [t.strip() for t in args.targets.split(',') if t.strip()]
    
    if not targets:
        console.print("[red]No targets to scan![/red]")
        sys.exit(1)
    
    # Expand CIDR ranges if requested
    if args.expand_cidrs:
        console.print("[cyan]Expanding CIDR ranges...[/cyan]")
        targets = BatchScanner().expand_cidr_ranges(targets)
        console.print(f"[cyan]Expanded to {len(targets)} individual targets[/cyan]")
    
    # Initialize batch scanner
    try:
        scanner = BatchScanner(args.vulners_api_key, args.workers)
        
        # Display scan configuration
        console.print(f"[bold cyan]🚀 Starting Batch Scan[/bold cyan]")
        console.print(f"[cyan]Targets: {len(targets)}[/cyan]")
        console.print(f"[cyan]Ports: {args.ports}[/cyan]")
        console.print(f"[cyan]Scan Type: {args.scan_type}[/cyan]")
        console.print(f"[cyan]Workers: {args.workers}[/cyan]")
        console.print(f"[cyan]Min CVSS: {args.min_cvss}[/cyan]")
        
        # Perform batch scan
        start_time = time.time()
        results = scanner.scan_targets(
            targets, args.ports, args.scan_type, args.min_cvss, args.service_filter
        )
        end_time = time.time()
        
        # Generate report
        report = scanner.generate_consolidated_report(args.output, args.output_file)
        
        # Final summary
        console.print(f"\n[bold green]🎉 Batch scan completed in {end_time - start_time:.1f} seconds![/bold green]")
        
        successful_scans = sum(1 for r in results.values() if r["status"] == "success")
        total_vulnerabilities = sum(r["summary"]["total_vulnerabilities"] for r in results.values()
                                  if r["status"] == "success")
        critical_count = sum(r["summary"]["critical_count"] for r in results.values()
                           if r["status"] == "success")
        
        console.print(f"[green]Successful scans: {successful_scans}/{len(targets)}[/green]")
        console.print(f"[green]Total vulnerabilities found: {total_vulnerabilities}[/green]")
        
        if critical_count > 0:
            console.print(f"[red]⚠️  {critical_count} CRITICAL vulnerabilities found across all targets![/red]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Batch scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()