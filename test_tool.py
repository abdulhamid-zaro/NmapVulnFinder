#!/usr/bin/env python3
"""
Test script for NmapVulnFinder
==============================

This script tests the basic functionality of the CVE discovery tool
without requiring external network access or actual scanning.
"""

import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add the current directory to the Python path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from nmap_cve_finder import NmapCVEScanner, CVEInfo, ServiceInfo, VulnersAPI
    from batch_scanner import BatchScanner
    from config import Config, get_config
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)

class TestNmapCVEScanner(unittest.TestCase):
    """Test cases for NmapCVEScanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = NmapCVEScanner()
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner.nm)
        self.assertIsNotNone(self.scanner.vulners_api)
        self.assertEqual(len(self.scanner.services), 0)
        self.assertEqual(len(self.scanner.vulnerabilities), 0)
    
    def test_cve_info_creation(self):
        """Test CVEInfo data class"""
        cve = CVEInfo(
            cve_id="CVE-2021-44228",
            description="Apache Log4j2 vulnerability",
            cvss_score=10.0,
            severity="CRITICAL",
            published_date="2021-12-10",
            service="Apache Log4j 2.14.1",
            port=8080,
            exploit_available=True
        )
        
        self.assertEqual(cve.cve_id, "CVE-2021-44228")
        self.assertEqual(cve.cvss_score, 10.0)
        self.assertEqual(cve.severity, "CRITICAL")
        self.assertTrue(cve.exploit_available)
    
    def test_service_info_creation(self):
        """Test ServiceInfo data class"""
        service = ServiceInfo(
            port=80,
            protocol="tcp",
            service="http",
            version="2.4.41",
            product="Apache httpd",
            extrainfo="Ubuntu"
        )
        
        self.assertEqual(service.port, 80)
        self.assertEqual(service.protocol, "tcp")
        self.assertEqual(service.service, "http")
        self.assertEqual(service.product, "Apache httpd")
    
    def test_cvss_score_extraction(self):
        """Test CVSS score extraction from vulnerability data"""
        # Mock vulnerability data with different CVSS score formats
        test_data = [
            {"cvss": {"score": 9.8}},
            {"cvss2": {"cvssScore": 7.5}},
            {"_source": {"cvss": {"score": 8.1}}},
            {"invalid": "data"}
        ]
        
        expected_scores = [9.8, 7.5, 8.1, 0.0]
        
        for data, expected in zip(test_data, expected_scores):
            score = self.scanner._extract_cvss_score(data)
            self.assertEqual(score, expected)
    
    def test_vulnerability_deduplication(self):
        """Test vulnerability deduplication"""
        # Create duplicate CVEs
        cve1 = CVEInfo("CVE-2021-1234", "Test vuln", 7.5, "HIGH", "2021", "Apache", 80)
        cve2 = CVEInfo("CVE-2021-1234", "Same vuln", 7.5, "HIGH", "2021", "Apache", 80)
        cve3 = CVEInfo("CVE-2021-5678", "Different vuln", 6.0, "MEDIUM", "2021", "Nginx", 443)
        
        self.scanner.vulnerabilities = [cve1, cve2, cve3]
        deduplicated = self.scanner._deduplicate_cves()
        
        self.assertEqual(len(deduplicated), 2)
        cve_ids = [cve.cve_id for cve in deduplicated]
        self.assertIn("CVE-2021-1234", cve_ids)
        self.assertIn("CVE-2021-5678", cve_ids)

class TestVulnersAPI(unittest.TestCase):
    """Test cases for VulnersAPI"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.api = VulnersAPI()
    
    def test_api_initialization(self):
        """Test API initialization"""
        self.assertIsNotNone(self.api.session)
        self.assertEqual(self.api.base_url, "https://vulners.com/api/v3")
    
    @patch('requests.Session.post')
    def test_search_cve_by_cpe(self, mock_post):
        """Test CVE search by CPE"""
        # Mock successful API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2021-44228",
                            "description": "Log4j vulnerability",
                            "cvss": {"score": 10.0}
                        }
                    }
                ]
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        results = self.api.search_cve_by_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["_source"]["id"], "CVE-2021-44228")

class TestConfig(unittest.TestCase):
    """Test cases for configuration"""
    
    def test_config_initialization(self):
        """Test configuration initialization"""
        config = get_config("testing")
        
        self.assertEqual(config.TOOL_NAME, "NmapCVEFinder")
        self.assertEqual(config.DEFAULT_SCAN_TYPE, "quick")
        self.assertIsInstance(config.SCAN_CONFIGS, dict)
    
    def test_severity_from_cvss(self):
        """Test severity determination from CVSS score"""
        config = get_config()
        
        self.assertEqual(config.get_severity_from_cvss(10.0), "CRITICAL")
        self.assertEqual(config.get_severity_from_cvss(8.5), "HIGH")
        self.assertEqual(config.get_severity_from_cvss(5.0), "MEDIUM")
        self.assertEqual(config.get_severity_from_cvss(2.0), "LOW")
    
    def test_scan_config_retrieval(self):
        """Test scan configuration retrieval"""
        config = get_config()
        
        quick_config = config.get_scan_config("quick")
        self.assertIn("args", quick_config)
        self.assertIn("description", quick_config)
        
        # Test fallback to comprehensive for unknown scan type
        unknown_config = config.get_scan_config("unknown")
        self.assertEqual(unknown_config, config.SCAN_CONFIGS["comprehensive"])

class TestBatchScanner(unittest.TestCase):
    """Test cases for BatchScanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.batch_scanner = BatchScanner(max_workers=2)
    
    def test_batch_scanner_initialization(self):
        """Test batch scanner initialization"""
        self.assertEqual(self.batch_scanner.max_workers, 2)
        self.assertEqual(len(self.batch_scanner.results), 0)
        self.assertEqual(len(self.batch_scanner.failed_targets), 0)
    
    def test_cidr_expansion(self):
        """Test CIDR range expansion"""
        targets = ["192.168.1.1", "192.168.1.0/30", "example.com"]
        expanded = self.batch_scanner.expand_cidr_ranges(targets)
        
        # Should expand the /30 network to individual IPs
        self.assertGreater(len(expanded), len(targets))
        self.assertIn("192.168.1.1", expanded)
        self.assertIn("example.com", expanded)

def run_integration_tests():
    """Run integration tests that require external dependencies"""
    print("🧪 Running Integration Tests")
    print("=" * 50)
    
    # Test 1: Check if nmap is available
    try:
        import nmap
        nm = nmap.PortScanner()
        print("✅ Nmap Python library is working")
    except Exception as e:
        print(f"❌ Nmap Python library error: {e}")
        return False
    
    # Test 2: Check if Rich is working
    try:
        from rich.console import Console
        console = Console()
        console.print("✅ Rich library is working", style="green")
    except Exception as e:
        print(f"❌ Rich library error: {e}")
        return False
    
    # Test 3: Check if requests is working
    try:
        import requests
        # Test with a simple request (without actually making it)
        session = requests.Session()
        print("✅ Requests library is working")
    except Exception as e:
        print(f"❌ Requests library error: {e}")
        return False
    
    # Test 4: Test configuration loading
    try:
        config = get_config("testing")
        print(f"✅ Configuration loaded (scan types: {len(config.SCAN_CONFIGS)})")
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False
    
    print("\n🎉 All integration tests passed!")
    return True

def main():
    """Main test runner"""
    print("🔍 NmapVulnFinder Test Suite")
    print("=" * 50)
    
    # Run unit tests
    print("\n🧪 Running Unit Tests")
    print("-" * 30)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestNmapCVEScanner,
        TestVulnersAPI,
        TestConfig,
        TestBatchScanner
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Run integration tests
    print("\n🔧 Running Integration Tests")
    print("-" * 30)
    integration_success = run_integration_tests()
    
    # Summary
    print("\n📊 Test Summary")
    print("=" * 50)
    print(f"Unit Tests: {result.testsRun} run, {len(result.failures)} failures, {len(result.errors)} errors")
    print(f"Integration Tests: {'✅ PASSED' if integration_success else '❌ FAILED'}")
    
    if result.wasSuccessful() and integration_success:
        print("\n🎉 All tests passed! The tool is ready to use.")
        return 0
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())