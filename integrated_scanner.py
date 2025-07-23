#!/usr/bin/env python3
"""
Integrated CVE Scanner
=====================

Unified scanner that combines network scanning, port discovery, 
and web application vulnerability detection with real-time notifications.
"""

import sys
import json
import time
import argparse
import asyncio
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from fast_scanner import EnhancedFastScanner
from web_app_scanner import WebApplicationScanner, WebVulnerability
from performance_optimizer import PortNotifier
from nmap_cve_finder import CVEInfo
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns

console = Console()

class IntegratedCVEScanner:
    """Integrated scanner combining network and web application scanning"""
    
    def __init__(self, notification_config: Dict = None, max_workers: int = 10):
        self.fast_scanner = EnhancedFastScanner(notification_config, max_workers)
        self.web_scanner = WebApplicationScanner()
        self.notifier = PortNotifier(notification_config or {"notifications_enabled": False})
        
    async def comprehensive_scan(self, targets: List[str], 
                               include_web_scan: bool = True,
                               include_vulns: bool = True,
                               deep_web_scan: bool = False,
                               min_cvss: float = 0.0,
                               web_ports: List[int] = None) -> Dict:
        """
        Comprehensive scan combining network and web application scanning
        
        Args:
            targets: List of target hosts/IPs
            include_web_scan: Include web application scanning
            include_vulns: Include vulnerability discovery
            deep_web_scan: Perform deep web application scanning
            min_cvss: Minimum CVSS score for vulnerabilities
            web_ports: Specific ports to scan for web applications (default: 80, 443, 8080, 8443)
        """
        
        if web_ports is None:
            web_ports = [80, 443, 8080, 8443, 8000, 9000, 3000]
        
        console.print("🎯 [bold cyan]Starting Comprehensive CVE Scan[/bold cyan]")
        console.print(f"📋 Targets: {len(targets)}")
        console.print(f"🌐 Web Scan: {'✅' if include_web_scan else '❌'}")
        console.print(f"🔍 Vulnerability Discovery: {'✅' if include_vulns else '❌'}")
        console.print(f"🔬 Deep Web Scan: {'✅' if deep_web_scan else '❌'}")
        
        results = {
            'scan_info': {
                'start_time': time.time(),
                'targets': targets,
                'include_web_scan': include_web_scan,
                'include_vulns': include_vulns,
                'deep_web_scan': deep_web_scan,
                'min_cvss': min_cvss
            },
            'network_results': {},
            'web_results': {},
            'combined_vulnerabilities': [],
            'summary': {}
        }
        
        try:
            # Phase 1: Network Scanning
            console.print("\n🚀 [bold green]Phase 1: Network & Port Scanning[/bold green]")
            network_results = await self.fast_scanner.ultra_fast_scan(
                targets=targets,
                include_vulns=include_vulns,
                min_cvss=min_cvss
            )
            results['network_results'] = network_results
            
            # Phase 2: Web Application Scanning
            if include_web_scan:
                console.print("\n🌐 [bold yellow]Phase 2: Web Application Scanning[/bold yellow]")
                web_results = await self._scan_web_applications(
                    network_results, web_ports, deep_web_scan
                )
                results['web_results'] = web_results
            
            # Phase 3: Combine and Analyze Results
            console.print("\n📊 [bold blue]Phase 3: Results Analysis[/bold blue]")
            combined_vulns = self._combine_vulnerabilities(
                network_results, results.get('web_results', {}), min_cvss
            )
            results['combined_vulnerabilities'] = combined_vulns
            
            # Phase 4: Generate Summary
            results['summary'] = self._generate_summary(results)
            
            # Send critical vulnerability notifications
            await self._notify_critical_findings(results)
            
        except Exception as e:
            console.print(f"❌ Scan error: {e}")
        
        results['scan_info']['end_time'] = time.time()
        results['scan_info']['duration'] = results['scan_info']['end_time'] - results['scan_info']['start_time']
        
        return results
    
    async def _scan_web_applications(self, network_results: Dict, 
                                   web_ports: List[int], deep_scan: bool) -> Dict:
        """Scan web applications on discovered web ports"""
        
        web_results = {}
        web_targets = []
        
        # Identify web targets from network scan results
        for target, data in network_results.items():
            ports = data.get('ports', [])
            for port_info in ports:
                port = port_info['port']
                if port in web_ports:
                    # Determine protocol
                    protocol = 'https' if port in [443, 8443] else 'http'
                    web_url = f"{protocol}://{target}:{port}"
                    web_targets.append((target, port, web_url))
        
        if not web_targets:
            console.print("ℹ️ No web applications found on common ports")
            return {}
        
        console.print(f"🌐 Found {len(web_targets)} potential web applications")
        
        # Scan each web application
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            web_task = progress.add_task("Scanning web applications...", total=len(web_targets))
            
            for target, port, web_url in web_targets:
                progress.update(web_task, description=f"Scanning {web_url}...")
                
                try:
                    scan_result = await self.web_scanner.scan_web_application(
                        target=web_url,
                        include_paths=True,
                        deep_scan=deep_scan
                    )
                    
                    web_results[f"{target}:{port}"] = scan_result
                    
                    # Brief summary for progress
                    vulns_count = len(scan_result.get('vulnerabilities', []))
                    if vulns_count > 0:
                        console.print(f"  🚨 {web_url}: {vulns_count} vulnerabilities found")
                    else:
                        console.print(f"  ✅ {web_url}: No vulnerabilities found")
                        
                except Exception as e:
                    console.print(f"  ❌ {web_url}: Scan failed - {e}")
                    web_results[f"{target}:{port}"] = {
                        'target': web_url,
                        'error': str(e),
                        'technologies': [],
                        'vulnerabilities': []
                    }
                
                progress.advance(web_task)
        
        return web_results
    
    def _combine_vulnerabilities(self, network_results: Dict, web_results: Dict, 
                               min_cvss: float) -> List[Dict]:
        """Combine vulnerabilities from network and web scans"""
        
        combined = []
        
        # Add network vulnerabilities
        for target, data in network_results.items():
            vulnerabilities = data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                if hasattr(vuln, 'cvss_score') and vuln.cvss_score >= min_cvss:
                    combined.append({
                        'source': 'network',
                        'target': target,
                        'cve_id': vuln.cve_id,
                        'title': getattr(vuln, 'description', 'Network Vulnerability'),
                        'cvss_score': vuln.cvss_score,
                        'severity': vuln.severity,
                        'service': getattr(vuln, 'service', 'Unknown'),
                        'port': getattr(vuln, 'port', 'Unknown'),
                        'exploit_available': getattr(vuln, 'exploit_available', False)
                    })
        
        # Add web application vulnerabilities
        for target_port, data in web_results.items():
            vulnerabilities = data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                if isinstance(vuln, WebVulnerability) and vuln.cvss_score >= min_cvss:
                    combined.append({
                        'source': 'web',
                        'target': target_port,
                        'cve_id': vuln.cve_id,
                        'title': vuln.title,
                        'cvss_score': vuln.cvss_score,
                        'severity': vuln.severity,
                        'technology': vuln.technology,
                        'exploit_available': vuln.exploit_available,
                        'references': vuln.references
                    })
        
        # Sort by CVSS score (highest first)
        combined.sort(key=lambda x: x['cvss_score'], reverse=True)
        
        return combined
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Generate comprehensive scan summary"""
        
        network_results = results['network_results']
        web_results = results['web_results']
        combined_vulns = results['combined_vulnerabilities']
        
        summary = {
            'total_targets': len(network_results),
            'total_open_ports': sum(len(data.get('ports', [])) for data in network_results.values()),
            'total_web_apps': len(web_results),
            'total_vulnerabilities': len(combined_vulns),
            'vulnerability_breakdown': {
                'critical': len([v for v in combined_vulns if v['severity'] == 'CRITICAL']),
                'high': len([v for v in combined_vulns if v['severity'] == 'HIGH']),
                'medium': len([v for v in combined_vulns if v['severity'] == 'MEDIUM']),
                'low': len([v for v in combined_vulns if v['severity'] == 'LOW'])
            },
            'source_breakdown': {
                'network': len([v for v in combined_vulns if v['source'] == 'network']),
                'web': len([v for v in combined_vulns if v['source'] == 'web'])
            },
            'top_vulnerabilities': combined_vulns[:10],
            'scan_duration': results['scan_info'].get('duration', 0)
        }
        
        return summary
    
    async def _notify_critical_findings(self, results: Dict):
        """Send notifications for critical findings"""
        
        if not self.notifier.notifications_enabled:
            return
        
        combined_vulns = results['combined_vulnerabilities']
        critical_vulns = [v for v in combined_vulns if v['severity'] in ['CRITICAL', 'HIGH']]
        
        if not critical_vulns:
            return
        
        message = f"🚨 **Critical Security Findings Alert**\n"
        message += f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += f"**Targets Scanned:** {results['summary']['total_targets']}\n\n"
        message += f"**Critical/High Vulnerabilities Found:** {len(critical_vulns)}\n\n"
        
        message += "**🔥 Top Critical Vulnerabilities:**\n"
        for i, vuln in enumerate(critical_vulns[:5], 1):
            message += f"{i}. {vuln['cve_id']} (CVSS: {vuln['cvss_score']:.1f})\n"
            message += f"   Target: {vuln['target']}\n"
            message += f"   {vuln['title'][:80]}...\n\n"
        
        # Send notifications
        try:
            if self.notifier.email_config.get('enabled'):
                await self.notifier._send_email_notification(message)
            if self.notifier.webhook_config.get('enabled'):
                await self.notifier._send_webhook_notification(message)
            if self.notifier.telegram_config.get('enabled'):
                await self.notifier._send_telegram_notification(message)
        except Exception as e:
            console.print(f"⚠️ Notification error: {e}")
    
    def generate_integrated_report(self, results: Dict, output_format: str = "terminal") -> str:
        """Generate comprehensive integrated report"""
        
        if output_format == "json":
            return json.dumps(results, indent=2, default=str, ensure_ascii=False)
        
        # Terminal report
        console.print("\n" + "="*100)
        console.print(Panel.fit(
            "[bold cyan]🎯 Comprehensive CVE Security Assessment Report[/bold cyan]",
            border_style="cyan"
        ))
        
        summary = results['summary']
        scan_info = results['scan_info']
        
        # Executive Summary
        console.print("\n📊 [bold green]Executive Summary[/bold green]")
        
        summary_panels = [
            Panel(f"[bold white]{summary['total_targets']}[/bold white]\nTargets Scanned", 
                  border_style="blue"),
            Panel(f"[bold white]{summary['total_open_ports']}[/bold white]\nOpen Ports", 
                  border_style="green"),
            Panel(f"[bold white]{summary['total_web_apps']}[/bold white]\nWeb Applications", 
                  border_style="yellow"),
            Panel(f"[bold white]{summary['total_vulnerabilities']}[/bold white]\nTotal Vulnerabilities", 
                  border_style="red")
        ]
        
        console.print(Columns(summary_panels))
        
        # Vulnerability Breakdown
        console.print(f"\n🚨 [bold red]Vulnerability Breakdown[/bold red]")
        vuln_breakdown = summary['vulnerability_breakdown']
        
        breakdown_table = Table(show_header=True, header_style="bold magenta")
        breakdown_table.add_column("Severity", style="cyan")
        breakdown_table.add_column("Count", style="white")
        breakdown_table.add_column("Percentage", style="yellow")
        
        total_vulns = summary['total_vulnerabilities']
        if total_vulns > 0:
            for severity, count in vuln_breakdown.items():
                percentage = (count / total_vulns) * 100
                breakdown_table.add_row(
                    severity.upper(),
                    str(count),
                    f"{percentage:.1f}%"
                )
        
        console.print(breakdown_table)
        
        # Source Breakdown
        console.print(f"\n🔍 [bold blue]Vulnerability Sources[/bold blue]")
        source_breakdown = summary['source_breakdown']
        
        source_table = Table(show_header=True, header_style="bold magenta")
        source_table.add_column("Source", style="cyan")
        source_table.add_column("Count", style="white")
        source_table.add_column("Description", style="yellow")
        
        source_table.add_row(
            "Network", 
            str(source_breakdown.get('network', 0)),
            "Port services and network protocols"
        )
        source_table.add_row(
            "Web Applications", 
            str(source_breakdown.get('web', 0)),
            "Web frameworks, CMS, and applications"
        )
        
        console.print(source_table)
        
        # Top Vulnerabilities
        top_vulns = summary['top_vulnerabilities']
        if top_vulns:
            console.print(f"\n🔥 [bold red]Top Critical Vulnerabilities[/bold red]")
            
            vulns_table = Table(show_header=True, header_style="bold magenta")
            vulns_table.add_column("Rank", style="cyan", width=6)
            vulns_table.add_column("CVE/ID", style="red", width=15)
            vulns_table.add_column("CVSS", style="red", width=6)
            vulns_table.add_column("Target", style="yellow", width=20)
            vulns_table.add_column("Title", style="white", max_width=40)
            vulns_table.add_column("Source", style="green", width=8)
            
            for i, vuln in enumerate(top_vulns[:15], 1):
                severity_color = {
                    'CRITICAL': 'bold red',
                    'HIGH': 'red',
                    'MEDIUM': 'yellow',
                    'LOW': 'green'
                }.get(vuln['severity'], 'white')
                
                vulns_table.add_row(
                    f"#{i}",
                    vuln['cve_id'],
                    f"[{severity_color}]{vuln['cvss_score']:.1f}[/{severity_color}]",
                    vuln['target'],
                    vuln['title'][:40] + "..." if len(vuln['title']) > 40 else vuln['title'],
                    vuln['source'].title()
                )
            
            console.print(vulns_table)
        
        # Recommendations
        console.print(f"\n💡 [bold green]Security Recommendations[/bold green]")
        
        critical_count = vuln_breakdown.get('critical', 0)
        high_count = vuln_breakdown.get('high', 0)
        
        if critical_count > 0:
            console.print(f"🔴 [bold red]URGENT: {critical_count} CRITICAL vulnerabilities require immediate attention![/bold red]")
        
        if high_count > 0:
            console.print(f"🟡 [bold yellow]HIGH PRIORITY: {high_count} HIGH severity vulnerabilities should be addressed soon.[/bold yellow]")
        
        console.print("\n📋 [bold cyan]Next Steps:[/bold cyan]")
        console.print("1. Prioritize patching CRITICAL and HIGH severity vulnerabilities")
        console.print("2. Review web application security configurations")
        console.print("3. Implement network segmentation for critical services")
        console.print("4. Regular vulnerability scanning and monitoring")
        console.print("5. Security awareness training for development teams")
        
        # Scan Information
        console.print(f"\n📈 [bold blue]Scan Information[/bold blue]")
        console.print(f"⏱️ Duration: {scan_info.get('duration', 0):.2f} seconds")
        console.print(f"🔧 Network Scanning: ✅")
        console.print(f"🌐 Web Application Scanning: {'✅' if scan_info.get('include_web_scan') else '❌'}")
        console.print(f"🔬 Deep Web Scanning: {'✅' if scan_info.get('deep_web_scan') else '❌'}")
        console.print(f"📊 Minimum CVSS: {scan_info.get('min_cvss', 0.0)}")
        
        console.print("\n" + "="*100)
        return "Integrated report displayed"

async def main():
    """Main function for integrated scanning"""
    
    parser = argparse.ArgumentParser(
        description="Integrated CVE Scanner - Network + Web Application Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 --web-scan --deep-web
  %(prog)s -f targets.txt --include-vulns --min-cvss 7.0 --notifications
  %(prog)s -t example.com --web-scan --output json --output-file assessment.json
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--targets",
        help="Comma-separated list of targets (IPs, domains, URLs)"
    )
    target_group.add_argument(
        "-f", "--file",
        help="File containing targets (one per line)"
    )
    
    # Scanning options
    parser.add_argument(
        "--web-scan",
        action="store_true",
        help="Include web application scanning"
    )
    
    parser.add_argument(
        "--deep-web",
        action="store_true",
        help="Perform deep web application scanning (includes payload testing)"
    )
    
    parser.add_argument(
        "--include-vulns",
        action="store_true",
        default=True,
        help="Include vulnerability discovery (default: True)"
    )
    
    parser.add_argument(
        "--min-cvss",
        type=float,
        default=0.0,
        help="Minimum CVSS score for vulnerabilities (0.0-10.0)"
    )
    
    parser.add_argument(
        "--web-ports",
        help="Comma-separated list of web ports to scan (default: 80,443,8080,8443)"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of parallel workers (default: 10)"
    )
    
    # Notification options
    parser.add_argument(
        "--notifications",
        action="store_true",
        help="Enable notifications for critical findings"
    )
    
    parser.add_argument(
        "--notification-config",
        help="Notification configuration file"
    )
    
    # Output options
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
    
    # Prepare targets
    if args.targets:
        targets = [t.strip() for t in args.targets.split(',') if t.strip()]
    else:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            console.print(f"❌ File not found: {args.file}")
            return
    
    if not targets:
        console.print("❌ No targets to scan!")
        return
    
    # Prepare web ports
    web_ports = [80, 443, 8080, 8443, 8000, 9000, 3000]
    if args.web_ports:
        try:
            web_ports = [int(p.strip()) for p in args.web_ports.split(',')]
        except ValueError:
            console.print("❌ Invalid web ports format. Use comma-separated integers.")
            return
    
    # Prepare notification config
    notification_config = {"notifications_enabled": args.notifications}
    if args.notification_config:
        try:
            with open(args.notification_config, 'r') as f:
                notification_config = json.load(f)
                notification_config["notifications_enabled"] = args.notifications
        except FileNotFoundError:
            console.print(f"⚠️ Config file not found: {args.notification_config}")
            console.print("Using default settings")
    
    # Create integrated scanner
    scanner = IntegratedCVEScanner(notification_config, args.workers)
    
    # Display scan configuration
    console.print("🎯 [bold cyan]Integrated CVE Security Assessment[/bold cyan]")
    console.print(f"📋 Targets: {len(targets)}")
    console.print(f"⚡ Workers: {args.workers}")
    console.print(f"🌐 Web Scanning: {'✅' if args.web_scan else '❌'}")
    console.print(f"🔬 Deep Web Scan: {'✅' if args.deep_web else '❌'}")
    console.print(f"🔍 Vulnerability Discovery: {'✅' if args.include_vulns else '❌'}")
    console.print(f"📢 Notifications: {'✅' if args.notifications else '❌'}")
    console.print(f"📊 Min CVSS: {args.min_cvss}")
    
    # Start comprehensive scan
    start_time = time.time()
    
    try:
        results = await scanner.comprehensive_scan(
            targets=targets,
            include_web_scan=args.web_scan,
            include_vulns=args.include_vulns,
            deep_web_scan=args.deep_web,
            min_cvss=args.min_cvss,
            web_ports=web_ports
        )
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Generate report
        report = scanner.generate_integrated_report(results, args.output)
        
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                if args.output == "json":
                    f.write(report)
                else:
                    f.write("Integrated CVE Security Assessment Report\n" + "="*60 + "\n")
                    f.write(f"Scan completed in {scan_duration:.2f} seconds\n")
                    f.write(f"Targets: {', '.join(targets)}\n")
            
            console.print(f"💾 Report saved to: {args.output_file}")
        
        # Final summary
        summary = results['summary']
        console.print(f"\n🎉 [bold green]Assessment completed in {scan_duration:.2f} seconds![/bold green]")
        console.print(f"📊 Total vulnerabilities found: {summary['total_vulnerabilities']}")
        console.print(f"🔴 Critical: {summary['vulnerability_breakdown']['critical']}")
        console.print(f"🟡 High: {summary['vulnerability_breakdown']['high']}")
        console.print(f"🔵 Medium: {summary['vulnerability_breakdown']['medium']}")
        console.print(f"🟢 Low: {summary['vulnerability_breakdown']['low']}")
        
        critical_total = summary['vulnerability_breakdown']['critical'] + summary['vulnerability_breakdown']['high']
        if critical_total > 0:
            console.print(f"\n⚠️ [bold red]ATTENTION: {critical_total} critical/high severity vulnerabilities require immediate action![/bold red]")
    
    except KeyboardInterrupt:
        console.print("\n⚠️ Scan interrupted by user")
    except Exception as e:
        console.print(f"❌ Scan error: {e}")

if __name__ == "__main__":
    asyncio.run(main())