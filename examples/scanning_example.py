#!/usr/bin/env python3
"""
HellSuite Scanning Example
Shows how to use the robust scanning decorators
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import setup_application_logging, get_logger
from utils.decorators import robust_scan, validate_target_url
from utils.error_handler import HellScannerError

setup_application_logging()
logger = get_logger(__name__)

@robust_scan(timeout=30, retries=2)
def custom_scanner(target_url):
    """
    Custom scanner using the robust_scan composite decorator
    Includes: timeout, retries, logging, and validation automatically
    """
    logger.info(f"Running custom scanner on: {target_url}")
    
    # Simulate scanning operations
    import time
    import random
    
    # Simulate different types of checks
    checks = [
        "Checking security headers",
        "Scanning for exposed files", 
        "Testing for SQL injection",
        "Checking XSS vulnerabilities",
        "Verifying SSL/TLS configuration"
    ]
    
    findings = []
    
    for check in checks:
        logger.debug(f"  - {check}")
        time.sleep(0.1)  # Simulate work
        
        # Randomly find vulnerabilities (for example)
        if random.random() < 0.3:
            finding = {
                'type': 'example_vulnerability',
                'severity': random.choice(['low', 'medium', 'high']),
                'description': f"Found issue in {check.lower()}",
                'target': target_url
            }
            findings.append(finding)
            logger.warning(f"    Found: {finding['description']} ({finding['severity']})")
    
    return {
        'target': target_url,
        'findings': findings,
        'total_findings': len(findings),
        'scan_duration': 'simulated'
    }

def main():
    """Run scanning examples"""
    logger.info("=== HellSuite Scanning Examples ===")
    
    # List of example targets
    test_targets = [
        "http://testphp.vulnweb.com",
        "http://example.com",
        "https://httpbin.org"
    ]
    
    for target in test_targets:
        try:
            logger.info(f"\nScanning target: {target}")
            results = custom_scanner(target)
            
            logger.info(f"Scan completed for {target}:")
            logger.info(f"  - Total findings: {results['total_findings']}")
            
            # Log findings by severity
            severities = {}
            for finding in results['findings']:
                severity = finding['severity']
                severities[severity] = severities.get(severity, 0) + 1
            
            for severity, count in severities.items():
                logger.info(f"  - {severity}: {count}")
                
        except HellScannerError as e:
            logger.error(f"Scanner error for {target}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error for {target}: {e}")
    
    logger.info("\n=== Scanning examples completed ===")

if __name__ == "__main__":
    main()