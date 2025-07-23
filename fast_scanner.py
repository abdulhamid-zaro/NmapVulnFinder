#!/usr/bin/env python3
"""
Fast Scanner with Real-time Notifications
=========================================

أداة محسنة للمسح السريع مع إشعارات فورية للبورتات المفتوحة
Enhanced fast scanning tool with real-time port notifications
"""

import sys
import json
import time
import argparse
import asyncio
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

# إضافة المجلد الحالي للمسار
sys.path.insert(0, str(Path(__file__).parent))

from performance_optimizer import FastScanner, PortNotifier, PerformanceOptimizer
from nmap_cve_finder import NmapCVEScanner, CVEInfo, ServiceInfo
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

console = Console()

class EnhancedFastScanner:
    """أداة المسح السريع المحسنة مع إشعارات فورية"""
    
    def __init__(self, notification_config: Dict = None, max_workers: int = 10):
        self.fast_scanner = FastScanner(max_workers)
        self.cve_scanner = NmapCVEScanner()
        self.notifier = PortNotifier(notification_config or {"notifications_enabled": False})
        self.performance_optimizer = PerformanceOptimizer()
    
    async def ultra_fast_scan(self, targets: List[str], include_vulns: bool = True,
                            min_cvss: float = 0.0, service_filter: str = None) -> Dict:
        """
        مسح سريع جداً مع اكتشاف الثغرات الاختياري
        Ultra-fast scanning with optional vulnerability discovery
        """
        
        console.print("🚀 [bold cyan]بدء المسح السريع المحسن / Starting Enhanced Fast Scan[/bold cyan]")
        console.print(f"🎯 الأهداف / Targets: {len(targets)}")
        console.print(f"⚡ السرعة / Speed: Ultra Fast Mode")
        console.print(f"🔍 البحث عن الثغرات / Vulnerability Discovery: {'✅' if include_vulns else '❌'}")
        
        results = {}
        
        # المرحلة 1: اكتشاف البورتات السريع
        # Phase 1: Fast port discovery
        console.print("\n📡 [bold green]المرحلة 1: اكتشاف البورتات السريع[/bold green]")
        port_results = await self.fast_scanner.fast_port_discovery(targets, self.notifier.config)
        
        # المرحلة 2: تحليل الثغرات (اختياري)
        # Phase 2: Vulnerability analysis (optional)
        if include_vulns:
            console.print("\n🔍 [bold yellow]المرحلة 2: تحليل الثغرات[/bold yellow]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                
                vuln_task = progress.add_task("تحليل الثغرات...", total=len(targets))
                
                for target, port_data in port_results.items():
                    if port_data and port_data.get('ports'):
                        progress.update(vuln_task, description=f"تحليل {target}...")
                        
                        # تحويل بيانات البورتات لتنسيق متوافق
                        services = self._convert_ports_to_services(port_data['ports'])
                        
                        # البحث عن الثغرات
                        vulnerabilities = await self._discover_vulnerabilities_async(
                            services, min_cvss, service_filter
                        )
                        
                        # إرسال إشعار الثغرات الحرجة
                        critical_vulns = [v for v in vulnerabilities if v.severity in ['CRITICAL', 'HIGH']]
                        if critical_vulns:
                            await self._notify_critical_vulnerabilities(target, critical_vulns)
                        
                        results[target] = {
                            'ports': port_data['ports'],
                            'vulnerabilities': vulnerabilities,
                            'scan_time': port_data.get('scan_time', time.time()),
                            'summary': {
                                'total_ports': len(port_data['ports']),
                                'total_vulnerabilities': len(vulnerabilities),
                                'critical_count': len([v for v in vulnerabilities if v.severity == 'CRITICAL']),
                                'high_count': len([v for v in vulnerabilities if v.severity == 'HIGH']),
                                'medium_count': len([v for v in vulnerabilities if v.severity == 'MEDIUM']),
                                'low_count': len([v for v in vulnerabilities if v.severity == 'LOW'])
                            }
                        }
                    else:
                        results[target] = {
                            'ports': [],
                            'vulnerabilities': [],
                            'scan_time': time.time(),
                            'summary': {'total_ports': 0, 'total_vulnerabilities': 0}
                        }
                    
                    progress.advance(vuln_task)
        else:
            # بدون تحليل الثغرات
            for target, port_data in port_results.items():
                results[target] = {
                    'ports': port_data.get('ports', []),
                    'vulnerabilities': [],
                    'scan_time': port_data.get('scan_time', time.time()),
                    'summary': {
                        'total_ports': len(port_data.get('ports', [])),
                        'total_vulnerabilities': 0
                    }
                }
        
        return results
    
    def _convert_ports_to_services(self, ports: List[Dict]) -> List[ServiceInfo]:
        """تحويل بيانات البورتات إلى كائنات ServiceInfo"""
        services = []
        
        for port in ports:
            service = ServiceInfo(
                port=port['port'],
                protocol=port['protocol'],
                service=port['service'],
                version=port.get('version', ''),
                product=port.get('service', ''),
                extrainfo=port.get('full_info', ''),
                cpes=[]  # سيتم ملؤها لاحقاً إذا لزم الأمر
            )
            services.append(service)
        
        return services
    
    async def _discover_vulnerabilities_async(self, services: List[ServiceInfo],
                                            min_cvss: float, service_filter: str) -> List[CVEInfo]:
        """اكتشاف الثغرات بطريقة غير متزامنة"""
        
        # محاكاة المسح السريع للثغرات
        # في التطبيق الحقيقي، يمكن استخدام API calls متوازية
        vulnerabilities = []
        
        for service in services:
            if service_filter and service_filter.lower() not in service.service.lower():
                continue
            
            # البحث السريع عن الثغرات (محاكاة)
            # يمكن تحسين هذا باستخدام مكالمات API متوازية
            service_vulns = await self._quick_vulnerability_lookup(service, min_cvss)
            vulnerabilities.extend(service_vulns)
        
        return vulnerabilities
    
    async def _quick_vulnerability_lookup(self, service: ServiceInfo, min_cvss: float) -> List[CVEInfo]:
        """بحث سريع عن الثغرات لخدمة معينة"""
        
        # هذا مثال مبسط - في التطبيق الحقيقي يتم استخدام Vulners API
        # This is a simplified example - in real application use Vulners API
        vulnerabilities = []
        
        # محاكاة البحث عن الثغرات الشائعة
        common_vulns = {
            'apache': [
                {'cve': 'CVE-2021-41773', 'cvss': 9.8, 'desc': 'Apache HTTP Server Path Traversal'},
                {'cve': 'CVE-2021-42013', 'cvss': 7.5, 'desc': 'Apache HTTP Server Path Traversal'}
            ],
            'nginx': [
                {'cve': 'CVE-2021-23017', 'cvss': 8.1, 'desc': 'Nginx DNS Resolver Vulnerability'}
            ],
            'ssh': [
                {'cve': 'CVE-2020-15778', 'cvss': 7.8, 'desc': 'OpenSSH User Enumeration'}
            ],
            'mysql': [
                {'cve': 'CVE-2021-2471', 'cvss': 4.4, 'desc': 'MySQL Server Vulnerability'}
            ]
        }
        
        service_name = service.service.lower()
        for vuln_service, vulns in common_vulns.items():
            if vuln_service in service_name:
                for vuln in vulns:
                    if vuln['cvss'] >= min_cvss:
                        cve_info = CVEInfo(
                            cve_id=vuln['cve'],
                            description=vuln['desc'],
                            cvss_score=vuln['cvss'],
                            severity=self._get_severity_from_cvss(vuln['cvss']),
                            published_date='2021-10-01',
                            service=f"{service.service} {service.version}".strip(),
                            port=service.port,
                            exploit_available=vuln['cvss'] >= 7.0
                        )
                        vulnerabilities.append(cve_info)
        
        return vulnerabilities
    
    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """تحديد مستوى الخطورة من نقاط CVSS"""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    async def _notify_critical_vulnerabilities(self, target: str, vulnerabilities: List[CVEInfo]):
        """إرسال إشعار للثغرات الحرجة"""
        
        if not vulnerabilities:
            return
        
        message = f"🚨 **تنبيه ثغرات حرجة / Critical Vulnerabilities Alert**\n"
        message += f"**الهدف / Target:** {target}\n"
        message += f"**الوقت / Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        message += f"**عدد الثغرات الحرجة / Critical Vulnerabilities:** {len(vulnerabilities)}\n\n"
        
        for vuln in vulnerabilities[:10]:  # أول 10 ثغرات
            message += f"• {vuln.cve_id} (CVSS: {vuln.cvss_score}) - {vuln.description[:100]}...\n"
        
        # إرسال الإشعار
        if self.notifier.notifications_enabled:
            await self.notifier._send_email_notification(message)
            await self.notifier._send_webhook_notification(message)
            await self.notifier._send_telegram_notification(message)
    
    def generate_fast_report(self, results: Dict, output_format: str = "terminal") -> str:
        """إنتاج تقرير سريع للنتائج"""
        
        if output_format == "terminal":
            return self._generate_terminal_fast_report(results)
        elif output_format == "json":
            return json.dumps(results, indent=2, default=str, ensure_ascii=False)
        else:
            return "Unsupported format for fast report"
    
    def _generate_terminal_fast_report(self, results: Dict) -> str:
        """إنتاج تقرير طرفي سريع"""
        
        console.print("\n" + "="*80)
        console.print(Panel.fit(
            "[bold cyan]🚀 تقرير المسح السريع المحسن / Enhanced Fast Scan Report[/bold cyan]",
            border_style="cyan"
        ))
        
        # إحصائيات عامة
        total_targets = len(results)
        total_ports = sum(len(r.get('ports', [])) for r in results.values())
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results.values())
        
        console.print(f"\n📊 **الإحصائيات العامة / Overall Statistics:**")
        console.print(f"🎯 إجمالي الأهداف / Total Targets: {total_targets}")
        console.print(f"🔌 إجمالي البورتات المفتوحة / Total Open Ports: {total_ports}")
        console.print(f"🚨 إجمالي الثغرات / Total Vulnerabilities: {total_vulns}")
        
        # تفاصيل كل هدف
        for target, data in results.items():
            console.print(f"\n🎯 **الهدف / Target:** [bold cyan]{target}[/bold cyan]")
            
            ports = data.get('ports', [])
            vulnerabilities = data.get('vulnerabilities', [])
            
            if ports:
                console.print(f"📋 البورتات المفتوحة / Open Ports ({len(ports)}):")
                
                # جدول البورتات
                ports_table = Table(show_header=True, header_style="bold magenta")
                ports_table.add_column("البورت / Port", style="cyan")
                ports_table.add_column("الخدمة / Service", style="green") 
                ports_table.add_column("الإصدار / Version", style="yellow")
                
                for port in ports[:10]:  # أول 10 بورتات
                    ports_table.add_row(
                        f"{port['port']}/{port['protocol']}",
                        port['service'],
                        port.get('version', 'غير محدد / Unknown')
                    )
                
                console.print(ports_table)
                
                if len(ports) > 10:
                    console.print(f"... و {len(ports) - 10} بورت إضافي / and {len(ports) - 10} more ports")
            
            if vulnerabilities:
                console.print(f"\n🚨 الثغرات المكتشفة / Discovered Vulnerabilities ({len(vulnerabilities)}):")
                
                # تجميع حسب الخطورة
                critical = [v for v in vulnerabilities if v.severity == 'CRITICAL']
                high = [v for v in vulnerabilities if v.severity == 'HIGH']
                medium = [v for v in vulnerabilities if v.severity == 'MEDIUM']
                low = [v for v in vulnerabilities if v.severity == 'LOW']
                
                console.print(f"🔴 حرجة / Critical: {len(critical)}")
                console.print(f"🟡 عالية / High: {len(high)}")
                console.print(f"🔵 متوسطة / Medium: {len(medium)}")
                console.print(f"🟢 منخفضة / Low: {len(low)}")
                
                # عرض أهم الثغرات
                top_vulns = sorted(vulnerabilities, key=lambda x: x.cvss_score, reverse=True)[:5]
                if top_vulns:
                    console.print(f"\n🔥 أهم الثغرات / Top Vulnerabilities:")
                    vulns_table = Table(show_header=True, header_style="bold magenta")
                    vulns_table.add_column("CVE ID", style="cyan")
                    vulns_table.add_column("CVSS", style="red")
                    vulns_table.add_column("الوصف / Description", style="white", max_width=50)
                    
                    for vuln in top_vulns:
                        vulns_table.add_row(
                            vuln.cve_id,
                            f"{vuln.cvss_score:.1f}",
                            vuln.description
                        )
                    
                    console.print(vulns_table)
            
            if not ports and not vulnerabilities:
                console.print("❌ لم يتم العثور على بورتات مفتوحة / No open ports found")
        
        console.print("\n" + "="*80)
        return "Terminal report displayed"

async def main():
    """الدالة الرئيسية للتطبيق"""
    
    parser = argparse.ArgumentParser(
        description="أداة المسح السريع المحسن مع إشعارات البورتات المفتوحة",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة على الاستخدام / Usage Examples:
  %(prog)s -t 192.168.1.1 --ultra-fast
  %(prog)s -t example.com,scanme.nmap.org --include-vulns --min-cvss 7.0
  %(prog)s -f targets.txt --workers 15 --notifications
        """
    )
    
    # الأهداف
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--targets",
        help="قائمة الأهداف مفصولة بفواصل / Comma-separated list of targets"
    )
    target_group.add_argument(
        "-f", "--file",
        help="ملف يحتوي على الأهداف / File containing targets (one per line)"
    )
    
    # خيارات المسح
    parser.add_argument(
        "--ultra-fast",
        action="store_true",
        help="مسح سريع جداً (بورتات فقط) / Ultra-fast scan (ports only)"
    )
    
    parser.add_argument(
        "--include-vulns",
        action="store_true",
        help="تضمين البحث عن الثغرات / Include vulnerability discovery"
    )
    
    parser.add_argument(
        "--min-cvss",
        type=float,
        default=0.0,
        help="الحد الأدنى لنقاط CVSS / Minimum CVSS score (0.0-10.0)"
    )
    
    parser.add_argument(
        "--service-filter",
        help="تصفية حسب اسم الخدمة / Filter by service name"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="عدد العمليات المتوازية / Number of parallel workers (default: 10)"
    )
    
    # خيارات الإشعارات
    parser.add_argument(
        "--notifications",
        action="store_true",
        help="تفعيل الإشعارات / Enable notifications"
    )
    
    parser.add_argument(
        "--notification-config",
        help="ملف إعدادات الإشعارات / Notification configuration file"
    )
    
    # خيارات الإخراج
    parser.add_argument(
        "--output",
        choices=["terminal", "json"],
        default="terminal",
        help="تنسيق الإخراج / Output format"
    )
    
    parser.add_argument(
        "--output-file",
        help="ملف حفظ التقرير / Output file for report"
    )
    
    args = parser.parse_args()
    
    # تحضير الأهداف
    if args.targets:
        targets = [t.strip() for t in args.targets.split(',') if t.strip()]
    else:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            console.print(f"❌ الملف غير موجود / File not found: {args.file}")
            return
    
    if not targets:
        console.print("❌ لا توجد أهداف للمسح / No targets to scan!")
        return
    
    # تحضير إعدادات الإشعارات
    notification_config = {"notifications_enabled": args.notifications}
    
    if args.notification_config:
        try:
            with open(args.notification_config, 'r') as f:
                notification_config = json.load(f)
                notification_config["notifications_enabled"] = args.notifications
        except FileNotFoundError:
            console.print(f"⚠️ ملف الإعدادات غير موجود / Config file not found: {args.notification_config}")
            console.print("استخدام الإعدادات الافتراضية / Using default settings")
    
    # إنشاء الماسح المحسن
    scanner = EnhancedFastScanner(notification_config, args.workers)
    
    # عرض معلومات المسح
    console.print("🚀 [bold cyan]بدء المسح السريع المحسن / Starting Enhanced Fast Scan[/bold cyan]")
    console.print(f"🎯 عدد الأهداف / Number of targets: {len(targets)}")
    console.print(f"⚡ عدد العمليات المتوازية / Parallel workers: {args.workers}")
    console.print(f"🔍 البحث عن الثغرات / Vulnerability discovery: {'✅' if args.include_vulns else '❌'}")
    console.print(f"📢 الإشعارات / Notifications: {'✅' if args.notifications else '❌'}")
    
    # بدء المسح
    start_time = time.time()
    
    try:
        results = await scanner.ultra_fast_scan(
            targets=targets,
            include_vulns=args.include_vulns,
            min_cvss=args.min_cvss,
            service_filter=args.service_filter
        )
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # إنتاج التقرير
        report = scanner.generate_fast_report(results, args.output)
        
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                if args.output == "json":
                    f.write(report)
                else:
                    f.write("Enhanced Fast Scan Report\n" + "="*50 + "\n")
                    f.write(f"Scan completed in {scan_duration:.2f} seconds\n")
                    f.write(f"Targets scanned: {len(targets)}\n")
            
            console.print(f"💾 التقرير محفوظ في / Report saved to: {args.output_file}")
        
        # ملخص نهائي
        console.print(f"\n🎉 [bold green]اكتمل المسح في {scan_duration:.2f} ثانية / Scan completed in {scan_duration:.2f} seconds![/bold green]")
        
        total_ports = sum(len(r.get('ports', [])) for r in results.values())
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results.values())
        
        console.print(f"📊 إجمالي البورتات المفتوحة / Total open ports: {total_ports}")
        console.print(f"🚨 إجمالي الثغرات / Total vulnerabilities: {total_vulns}")
        
        # تحذير للثغرات الحرجة
        critical_vulns = sum(len([v for v in r.get('vulnerabilities', []) if v.severity == 'CRITICAL']) 
                           for r in results.values())
        if critical_vulns > 0:
            console.print(f"⚠️ [bold red]تم العثور على {critical_vulns} ثغرة حرجة! / Found {critical_vulns} CRITICAL vulnerabilities![/bold red]")
    
    except KeyboardInterrupt:
        console.print("\n⚠️ تم إيقاف المسح بواسطة المستخدم / Scan interrupted by user")
    except Exception as e:
        console.print(f"❌ خطأ في المسح / Scan error: {e}")

if __name__ == "__main__":
    asyncio.run(main())