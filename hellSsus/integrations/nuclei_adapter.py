#!/usr/bin/env python3
"""
Nuclei Adapter for hellSuite - EXACT SCHEMA VERSION
Parses Nuclei JSON results into YOUR exact database schema.
"""

import json
import sqlite3
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

# Add the hellSsus root to the path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import hellconfig


class NucleiAdapter:
    """Adapter for importing Nuclei scanner results - EXACT SCHEMA VERSION."""
    
    def __init__(self, db_path=None):
        self.db_path = db_path or hellconfig.DATABASE_PATH
    
    def connect_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            print(f"[!] Database connection error: {e}", file=sys.stderr)
            return None
    
    def extract_and_normalize_url(self, nuclei_data):
        """
        Extract and normalize URL from Nuclei finding.
        Returns a clean URL suitable for your assets.url column.
        """
        url = nuclei_data.get('url') or nuclei_data.get('host') or 'unknown'
        
        if isinstance(url, list):
            url = url[0] if url else 'unknown'
        
        url = str(url).strip()
        
        if url != 'unknown' and '://' not in url:
            scheme = nuclei_data.get('scheme', 'http')
            url = f"{scheme}://{url}"
        
        return url
    
    def map_severity(self, nuclei_severity):
        """Map Nuclei severity to your severity levels."""
        if not nuclei_severity:
            return 'Info'
        
        severity = str(nuclei_severity).lower()
        if severity == 'critical':
            return 'Critical'
        elif severity == 'high':
            return 'High'
        elif severity == 'medium':
            return 'Medium'
        elif severity == 'low':
            return 'Low'
        else:
            return 'Info'
    
    def determine_vuln_type(self, nuclei_info):
        """Determine vulnerability type based on Nuclei template info - IMPROVED VERSION."""
        template_name = nuclei_info.get('name', 'Unknown').lower()
        tags = nuclei_info.get('tags', [])
        
        if not isinstance(tags, list):
            tags = []
        
        if any(word in template_name for word in ['xss', 'cross-site', 'injection']):
            return 'Web Vulnerability'
        elif any(word in template_name for word in ['sqli', 'sql-injection']):
            return 'SQL Injection'
        elif any(word in template_name for word in ['lfi', 'rfi', 'file-inclusion']):
            return 'File Inclusion'
        elif any(word in template_name for word in ['rce', 'remote-code', 'command-injection']):
            return 'Remote Code Execution'
        elif any(word in template_name for word in ['ssrf', 'server-side']):
            return 'SSRF'
        elif any(word in template_name for word in ['idor', 'insecure-direct-object']):
            return 'IDOR'
        elif any(word in template_name for word in ['cors', 'misconfig']):
            return 'Misconfiguration'
        elif any(word in template_name for word in ['exposure', 'info-disclosure']):
            return 'Information Exposure'
        elif any(tag in tags for tag in ['tech', 'technologies', 'technology', 'wappalyzer']):
            return 'Technology Detection'
        elif any(tag in tags for tag in ['cve', 'vulnerability', 'vuln']):
            return 'Security Vulnerability'
        elif any(tag in tags for tag in ['misconfig', 'config', 'configuration']):
            return 'Misconfiguration'
        elif any(tag in tags for tag in ['exposure', 'info', 'information']):
            return 'Information Exposure'
        elif 'waf' in tags:
            return 'WAF Detection'
        else:
            return 'Security Finding'
    
    def import_scan(self, scan_file, project_id=None, project_name=None):
        """Main import method - tailored to YOUR exact schema."""
        
        if not os.path.exists(scan_file):
            print(f"[!] Scan file not found: {scan_file}", file=sys.stderr)
            return False
        
        conn = self.connect_db()
        if not conn:
            return False
        
        cursor = conn.cursor()
        
        if project_id is None:
            if project_name:
                cursor.execute('SELECT id FROM projects WHERE name = ?', (project_name,))
                result = cursor.fetchone()
                if result:
                    project_id = result['id']
            
            if not project_id:
                print("[!] Project not found", file=sys.stderr)
                conn.close()
                return False
        
        print(f"[*] Starting import for project {project_id}", file=sys.stderr)
        
        # Parse JSON
        try:
            with open(scan_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                data = [data]
                
            print(f"[+] Parsed {len(data)} findings", file=sys.stderr)
            
        except Exception as e:
            print(f"[!] JSON parse error: {e}", file=sys.stderr)
            conn.close()
            return False
        
        imported = 0
        errors = 0
        
        for i, finding in enumerate(data):
            if not isinstance(finding, dict):
                errors += 1
                continue
            
            try:
                asset_url = self.extract_and_normalize_url(finding)
                
                cursor.execute(
                    'SELECT id FROM assets WHERE project_id = ? AND url = ?',
                    (project_id, asset_url)
                )
                asset = cursor.fetchone()
                
                if asset:
                    asset_id = asset['id']
                else:
                    cursor.execute(
                        '''INSERT INTO assets 
                           (url, project_id, discovery_date) 
                           VALUES (?, ?, datetime('now'))''',
                        (asset_url, project_id)
                    )
                    asset_id = cursor.lastrowid
                
                info = finding.get('info', {})
                if isinstance(info, str):
                    info = {'name': info}
                
                template_id = finding.get('template-id', 'unknown')
                template_name = info.get('name', 'Unknown')
                
                cursor.execute(
                    '''SELECT id FROM vulnerabilities 
                       WHERE project_id = ? AND asset_id = ? 
                       AND description LIKE ?''',
                    (project_id, asset_id, f'%{template_id}%')
                )
                
                if cursor.fetchone():
                    print(f"[*] Duplicate skipped: {template_name}", file=sys.stderr)
                    continue

                vuln_type = self.determine_vuln_type(info)
                severity = self.map_severity(info.get('severity'))

                description = info.get('description', '')
                if not description:
                    description = f"{template_name} detected via Nuclei"

                refs = info.get('reference', [])
                if isinstance(refs, list):
                    references = '; '.join(refs)
                else:
                    references = str(refs)
                
                # Proof of concept (curl command or request)
                poc = ""
                curl_cmd = finding.get('curl-command')
                if curl_cmd:
                    poc = f"CURL command: {curl_cmd}"
                
                # Recommendation
                recommendation = info.get('remediation', 'Apply security patches and review configuration.')
                
                # CVE if available
                cve = None
                classification = info.get('classification', {})
                if classification and isinstance(classification, dict):
                    cve = classification.get('cve-id')
                
                # Discovery date
                matched_at = finding.get('matched-at')
                if matched_at:
                    discovery_date = matched_at
                else:
                    discovery_date = datetime.now().isoformat()
                
                cursor.execute('''
                    INSERT INTO vulnerabilities 
                    (type, severity, description, reference, proof_of_concept, 
                     recommendation, cve, cvss_score, project_id, asset_id, discovery_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vuln_type,
                    severity,
                    description,
                    references,
                    poc,
                    recommendation,
                    cve,
                    None,
                    project_id,
                    asset_id,
                    discovery_date
                ))
                
                imported += 1
                
                if imported % 2 == 0:
                    print(f"[*] Imported {imported}/{len(data)}: {template_name}", file=sys.stderr)
                    
            except Exception as e:
                errors += 1
                if errors <= 3:
                    print(f"[!] Error on item {i}: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc()
        
        conn.commit()
        
        # Show summary
        cursor.execute(
            'SELECT COUNT(*) as count FROM vulnerabilities WHERE project_id = ?',
            (project_id,)
        )
        total = cursor.fetchone()['count']
        
        print(f"[+] FINAL RESULT: {imported} imported, {errors} errors", file=sys.stderr)
        print(f"[+] Total vulnerabilities in project: {total}", file=sys.stderr)
        
        if imported > 0:
            cursor.execute(
                '''SELECT v.type, v.severity, v.description, a.url 
                   FROM vulnerabilities v 
                   JOIN assets a ON v.asset_id = a.id 
                   WHERE v.project_id = ? 
                   LIMIT 3''',
                (project_id,)
            )
            print(f"\n[*] Sample imported findings:", file=sys.stderr)
            for row in cursor.fetchall():
                print(f"  - {row['type']} ({row['severity']}): {row['description'][:50]}...", file=sys.stderr)
        
        conn.close()
        return imported > 0


# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Import Nuclei results - EXACT SCHEMA VERSION')
    parser.add_argument('scan_file', help='Path to Nuclei results file')
    parser.add_argument('--project-id', type=int, help='Project ID')
    parser.add_argument('--project-name', help='Project name')
    
    args = parser.parse_args()
    
    adapter = NucleiAdapter()
    success = adapter.import_scan(
        args.scan_file, 
        project_id=args.project_id,
        project_name=args.project_name
    )
    
    sys.exit(0 if success else 1)