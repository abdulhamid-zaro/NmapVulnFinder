#!/usr/bin/env python3
"""
Performance Optimizer for NmapVulnFinder
========================================

This module provides performance optimizations and notification features
for faster scanning and real-time port discovery alerts.
"""

import asyncio
import smtplib
import json
import time
import subprocess
# Email imports - handle different Python versions
try:
    from email.mime.text import MIMEText as MimeText
    from email.mime.multipart import MIMEMultipart as MimeMultipart
except ImportError:
    try:
        from email.MIMEText import MIMEText as MimeText
        from email.MIMEMultipart import MIMEMultipart as MimeMultipart
    except ImportError:
        # Create dummy classes if email is not available
        class MimeText:
            def __init__(self, *args, **kwargs): pass
        class MimeMultipart:
            def __init__(self, *args, **kwargs): pass
from typing import List, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from rich.console import Console

console = Console()

class PerformanceOptimizer:
    """Performance optimization utilities"""
    
    @staticmethod
    def get_optimized_nmap_args(scan_type: str, target_type: str = "single") -> str:
        """Get optimized Nmap arguments based on scan type and target"""
        
        base_args = {
            "ultra_fast": "-T5 -n --max-retries 1 --max-scan-delay 0 --min-rate 5000",
            "fast": "-T4 -n --max-retries 2 --max-scan-delay 10ms --min-rate 1000", 
            "balanced": "-T4 --max-retries 3 --max-scan-delay 100ms --min-rate 500",
            "thorough": "-T3 --max-retries 3 --max-scan-delay 1s --min-rate 100"
        }
        
        # Add version detection for vulnerability scanning
        version_args = "-sV --version-intensity 5"
        
        # Add vulnerability scripts for comprehensive scans
        vuln_args = "--script vulners,vuln"
        
        # Optimize for batch scanning
        if target_type == "batch":
            batch_args = "--max-hostgroup 50 --min-hostgroup 10"
            return f"{base_args.get(scan_type, base_args['balanced'])} {version_args} {batch_args}"
        
        return f"{base_args.get(scan_type, base_args['balanced'])} {version_args} {vuln_args}"
    
    @staticmethod
    def get_top_ports(count: int = 1000) -> str:
        """Get top N most common ports for faster initial scanning"""
        
        port_lists = {
            100: "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157",
            
            1000: "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416,417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389",
            
            "all": "1-65535"
        }
        
        if count <= 100:
            return port_lists[100]
        elif count <= 1000:
            return port_lists[1000]
        else:
            return port_lists["all"]

class PortNotifier:
    """Real-time port discovery notification system"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.notifications_enabled = config.get('notifications_enabled', False)
        self.email_config = config.get('email', {})
        self.webhook_config = config.get('webhook', {})
        self.telegram_config = config.get('telegram', {})
    
    async def notify_open_ports(self, target: str, open_ports: List[Dict], 
                              critical_services: List[Dict] = None):
        """Send notifications about discovered open ports"""
        
        if not self.notifications_enabled:
            return
        
        message = self._format_port_message(target, open_ports, critical_services)
        
        # Send notifications in parallel
        tasks = []
        
        if self.email_config.get('enabled'):
            tasks.append(self._send_email_notification(message))
        
        if self.webhook_config.get('enabled'):
            tasks.append(self._send_webhook_notification(message))
        
        if self.telegram_config.get('enabled'):
            tasks.append(self._send_telegram_notification(message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def _format_port_message(self, target: str, open_ports: List[Dict], 
                           critical_services: List[Dict] = None) -> str:
        """Format port discovery message"""
        
        message = f"🎯 **Port Discovery Alert**\n"
        message += f"**Target:** {target}\n"
        message += f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Open ports summary
        message += f"**📊 Open Ports Found:** {len(open_ports)}\n\n"
        
        # Critical services alert
        if critical_services:
            message += f"🚨 **Critical Services Detected:**\n"
            for service in critical_services:
                message += f"• Port {service['port']}/{service['protocol']}: {service['service']} {service.get('version', '')}\n"
            message += "\n"
        
        # All open ports
        message += "**📋 All Open Ports:**\n"
        for port in open_ports[:20]:  # Limit to first 20 ports
            service_info = f"{port['service']}"
            if port.get('version'):
                service_info += f" {port['version']}"
            message += f"• {port['port']}/{port['protocol']}: {service_info}\n"
        
        if len(open_ports) > 20:
            message += f"... and {len(open_ports) - 20} more ports\n"
        
        return message
    
    async def _send_email_notification(self, message: str):
        """Send email notification"""
        try:
            smtp_server = self.email_config['smtp_server']
            smtp_port = self.email_config.get('smtp_port', 587)
            username = self.email_config['username']
            password = self.email_config['password']
            to_email = self.email_config['to_email']
            
            msg = MimeMultipart()
            msg['From'] = username
            msg['To'] = to_email
            msg['Subject'] = "NmapVulnFinder - Port Discovery Alert"
            
            msg.attach(MimeText(message, 'plain'))
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)
            
            console.print("✅ Email notification sent successfully")
            
        except Exception as e:
            console.print(f"❌ Failed to send email notification: {e}")
    
    async def _send_webhook_notification(self, message: str):
        """Send webhook notification"""
        try:
            webhook_url = self.webhook_config['url']
            
            payload = {
                "text": message,
                "timestamp": time.time(),
                "source": "NmapVulnFinder"
            }
            
            async with asyncio.timeout(10):
                response = requests.post(webhook_url, json=payload)
                response.raise_for_status()
            
            console.print("✅ Webhook notification sent successfully")
            
        except Exception as e:
            console.print(f"❌ Failed to send webhook notification: {e}")
    
    async def _send_telegram_notification(self, message: str):
        """Send Telegram notification"""
        try:
            bot_token = self.telegram_config['bot_token']
            chat_id = self.telegram_config['chat_id']
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            async with asyncio.timeout(10):
                response = requests.post(url, json=payload)
                response.raise_for_status()
            
            console.print("✅ Telegram notification sent successfully")
            
        except Exception as e:
            console.print(f"❌ Failed to send Telegram notification: {e}")

class FastScanner:
    """High-performance scanning implementation"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.performance_optimizer = PerformanceOptimizer()
    
    async def fast_port_discovery(self, targets: List[str], 
                                 notification_config: Dict = None) -> Dict:
        """Ultra-fast port discovery with real-time notifications"""
        
        notifier = PortNotifier(notification_config or {})
        results = {}
        
        # Phase 1: Quick port discovery (top 1000 ports)
        console.print("🚀 Phase 1: Quick port discovery (top 1000 ports)")
        quick_results = await self._parallel_port_scan(targets, "ultra_fast", 1000)
        
        # Phase 2: Service detection on discovered ports
        console.print("🔍 Phase 2: Service detection on open ports")
        for target, ports in quick_results.items():
            if ports:
                # Send immediate notification about open ports
                await notifier.notify_open_ports(target, ports)
                
                # Detailed service detection
                service_results = await self._detailed_service_scan(target, ports)
                results[target] = service_results
        
        return results
    
    async def _parallel_port_scan(self, targets: List[str], scan_type: str, 
                                port_count: int) -> Dict:
        """Parallel port scanning for multiple targets"""
        
        port_range = self.performance_optimizer.get_top_ports(port_count)
        nmap_args = self.performance_optimizer.get_optimized_nmap_args(scan_type, "batch")
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self._scan_target_ports, target, port_range, nmap_args): target
                for target in targets
            }
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    ports = future.result()
                    results[target] = ports
                    if ports:
                        console.print(f"✅ {target}: {len(ports)} open ports found")
                except Exception as e:
                    console.print(f"❌ {target}: Scan failed - {e}")
                    results[target] = []
        
        return results
    
    def _scan_target_ports(self, target: str, port_range: str, nmap_args: str) -> List[Dict]:
        """Scan target for open ports"""
        
        cmd = f"nmap {nmap_args} -p {port_range} {target}"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                  text=True, timeout=300)
            
            if result.returncode != 0:
                return []
            
            return self._parse_nmap_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            console.print(f"⏰ Scan timeout for {target}")
            return []
        except Exception as e:
            console.print(f"❌ Scan error for {target}: {e}")
            return []
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse Nmap output to extract open ports"""
        
        ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    if state == 'open':
                        port_num = port_proto.split('/')[0]
                        protocol = port_proto.split('/')[1]
                        
                        ports.append({
                            'port': int(port_num),
                            'protocol': protocol,
                            'service': service,
                            'state': state
                        })
        
        return ports
    
    async def _detailed_service_scan(self, target: str, ports: List[Dict]) -> Dict:
        """Perform detailed service detection on discovered ports"""
        
        port_list = ','.join([str(p['port']) for p in ports])
        nmap_args = "-sV --version-intensity 7 -T4"
        
        cmd = f"nmap {nmap_args} -p {port_list} {target}"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                  text=True, timeout=180)
            
            if result.returncode == 0:
                detailed_ports = self._parse_detailed_output(result.stdout)
                return {
                    'target': target,
                    'ports': detailed_ports,
                    'scan_time': time.time()
                }
            
        except Exception as e:
            console.print(f"❌ Detailed scan error for {target}: {e}")
        
        return {'target': target, 'ports': ports, 'scan_time': time.time()}
    
    def _parse_detailed_output(self, output: str) -> List[Dict]:
        """Parse detailed Nmap output with version information"""
        
        ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service_info = ' '.join(parts[2:])
                    
                    if state == 'open':
                        port_num = port_proto.split('/')[0]
                        protocol = port_proto.split('/')[1]
                        
                        # Extract service and version
                        service_parts = service_info.split()
                        service = service_parts[0] if service_parts else 'unknown'
                        version = ' '.join(service_parts[1:]) if len(service_parts) > 1 else ''
                        
                        ports.append({
                            'port': int(port_num),
                            'protocol': protocol,
                            'service': service,
                            'version': version,
                            'state': state,
                            'full_info': service_info
                        })
        
        return ports

# Configuration example for notifications
NOTIFICATION_CONFIG_EXAMPLE = {
    "notifications_enabled": True,
    "email": {
        "enabled": True,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "your-email@gmail.com",
        "password": "your-app-password",
        "to_email": "security-team@company.com"
    },
    "webhook": {
        "enabled": True,
        "url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    },
    "telegram": {
        "enabled": True,
        "bot_token": "YOUR_BOT_TOKEN",
        "chat_id": "YOUR_CHAT_ID"
    }
}

def save_notification_config():
    """Save example notification configuration"""
    with open('notification_config.json', 'w') as f:
        json.dump(NOTIFICATION_CONFIG_EXAMPLE, f, indent=2)
    
    console.print("📝 Example notification configuration saved to 'notification_config.json'")
    console.print("Edit this file with your actual credentials and endpoints")

if __name__ == "__main__":
    # Example usage
    save_notification_config()
    
    # Example of fast scanning
    async def example_fast_scan():
        scanner = FastScanner(max_workers=5)
        targets = ["scanme.nmap.org", "example.com"]
        
        # Load notification config
        try:
            with open('notification_config.json', 'r') as f:
                config = json.load(f)
        except:
            config = {"notifications_enabled": False}
        
        results = await scanner.fast_port_discovery(targets, config)
        
        for target, result in results.items():
            console.print(f"\n🎯 Results for {target}:")
            for port in result.get('ports', []):
                console.print(f"  • {port['port']}/{port['protocol']}: {port['service']} {port.get('version', '')}")
    
    # Run example
    # asyncio.run(example_fast_scan())