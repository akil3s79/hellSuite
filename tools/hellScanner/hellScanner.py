#!/usr/bin/env python3
"""
HellScanner - Basic Vulnerability Scanner
Simple security checks as starting point
"""

import argparse
import json
import requests
import sys
import os
from urllib.parse import urlparse
from datetime import datetime

requests.packages.urllib3.disable_warnings()

def check_security_headers(target):
    """Check for missing security headers"""
    try:
        response = requests.get(target, timeout=10, verify=False)
        headers = response.headers
        
        security_headers = {
            'Content-Security-Policy': 'Missing CSP header',
            'X-Frame-Options': 'Missing X-Frame-Options header', 
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header'
        }
        
        findings = []
        for header, description in security_headers.items():
            if header not in headers:
                findings.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': f'{description} - {header}',
                    'proof_of_concept': f'curl -I {target}',
                    'recommendation': f'Add {header} to server configuration'
                })
        
        return findings
        
    except Exception as e:
        print(f"[!] Error checking headers: {e}")
        return []

def check_exposed_files(target):
    """Check for common exposed files"""
    common_files = [
        '/.env', '/.git/config', '/backup.zip', '/wp-config.php',
        '/phpinfo.php', '/test.php', '/admin.php'
    ]
    
    findings = []
    for file_path in common_files:
        test_url = target.rstrip('/') + file_path
        try:
            response = requests.get(test_url, timeout=5, verify=False)
            if response.status_code == 200:
                findings.append({
                    'type': 'exposed_file',
                    'severity': 'high', 
                    'description': f'Exposed sensitive file: {file_path}',
                    'proof_of_concept': f'Access: {test_url}',
                    'recommendation': f'Remove or restrict access to {file_path}'
                })
        except:
            continue
    
    return findings

def integrate_with_hellsuite(target, project_name):
    """Integrate results with HellSuite database"""
    try:
        import sys
        import os
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        tools_dir = os.path.dirname(current_dir)
        hellsuite_root = os.path.dirname(tools_dir)
        hellsus_dir = os.path.join(hellsuite_root, 'hellSsus')
        
        print(f"[*] Looking for HellSuite in: {hellsus_dir}")
        
        if hellsus_dir not in sys.path:
            sys.path.append(hellsus_dir)
        
        try:
            from integrations.hellscanner_adapter import save_scan_results
            print("[+] HellScanner adapter imported successfully!")
        except ImportError:

            sys.path.append(hellsuite_root)
            from hellSsus.integrations.hellscanner_adapter import save_scan_results
            print("[+] HellScanner adapter imported (alternative path)!")
        
        all_findings = []
        all_findings.extend(check_security_headers(target))
        all_findings.extend(check_exposed_files(target))
        
        scan_data = {
            'target': target,
            'scan_date': str(datetime.now().isoformat()),
            'vulnerabilities': all_findings,
            'project_name': project_name
        }
        
        # Save to HellSuite database
        result = save_scan_results(scan_data)
        if result:
            print(f"[+] Successfully integrated {len(all_findings)} vulnerabilities into HellSuite")
            return True
        else:
            print("[!] Failed to integrate results into HellSuite")
            return False
            
    except ImportError as e:
        print(f"[!] HellSuite integration failed: {e}")
        print(f"[!] Current Python path: {sys.path}")
        return False
    except Exception as e:
        print(f"[!] Integration error: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_standalone_scan(target, output_file=None):
    """Run scan in standalone mode"""
    print(f"[*] HellScanner - Basic Security Checks")
    print(f"[*] Target: {target}")
    print("[*] Mode: Standalone")
    
    all_findings = []
    all_findings.extend(check_security_headers(target))
    all_findings.extend(check_exposed_files(target))
    
    output_data = {
        'scanner': 'HellScanner',
        'version': '1.0',
        'target': target,
        'scan_date': str(datetime.now().isoformat()),
        'vulnerabilities': all_findings,
        'summary': {
            'total_vulnerabilities': len(all_findings),
            'high_severity': len([f for f in all_findings if f['severity'] == 'high']),
            'medium_severity': len([f for f in all_findings if f['severity'] == 'medium']),
            'low_severity': len([f for f in all_findings if f['severity'] == 'low'])
        }
    }
    
    # Output results
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            print(f"[+] Results saved to: {output_file}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")
            return 1
    else:
        print(json.dumps(output_data, indent=2))

    print(f"[+] Scan completed: {len(all_findings)} vulnerabilities found")
    return output_data

def main():
    parser = argparse.ArgumentParser(description='HellScanner - Basic Vulnerability Scanner')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--target', help='Target URL to scan (standalone mode)')
    group.add_argument('--project', help='HellSuite project name (integration mode)')
    
    parser.add_argument('--url', help='Target URL (required with --project)')
    parser.add_argument('-o', '--output', help='Output JSON file (standalone mode)')
    # parser.add_argument('--silent', action='store_true', help='Suppress banner')
    
    args = parser.parse_args()
    
    # HELLSUITE INTEGRATION MODE
    if args.project:
        if not args.url:
            print("[!] Error: --url is required when using --project")
            return 1
        
        if not hasattr(args, 'silent') or not args.silent:
            print("[*] HellScanner - HellSuite Integration Mode")
        
        success = integrate_with_hellsuite(args.url, args.project)
        return 0 if success else 1
    
    # STANDALONE MODE
    elif args.target:
        result = run_standalone_scan(args.target, args.output)
        return 0 if result else 1

if __name__ == "__main__":
    sys.exit(main())