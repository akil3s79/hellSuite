import sqlite3
import json
import os
import sys
import argparse
from datetime import datetime
from urllib.parse import urlparse

# Import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hellconfig import DATABASE_PATH, get_latest_scan

class HellFuzzerAdapter:
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
        print(f"[*] Using database: {self.db_path}")
    
    def connect_db(self):
        """Connect to SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            print(f"[!] Database connection error: {e}")
            return None
    
    def create_project(self, project_name, description=""):
        """Create a new project in database"""
        conn = self.connect_db()
        if not conn:
            return None
        
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO projects (name, description, created_date) VALUES (?, ?, datetime('now'))",
            (project_name, description)
        )
        project_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"[+] Project created: {project_name} (ID: {project_id})")
        return project_id
    
    def import_scan(self, json_file_path=None, project_name=None, project_id=None):
        """
        Import HellFuzzer JSON results into database
        Accepts either project_name (creates new) or project_id (uses existing)
        """
        try:
            if not json_file_path:
                json_file_path = get_latest_scan("hellfuzzer")
                if not json_file_path:
                    print("[!] No HellFuzzer scan files found")
                    return False

            with open(json_file_path, 'r', encoding='utf-8') as f:
                scan_data = json.load(f)

            conn = self.connect_db()
            if not conn:
                return False

            cursor = conn.cursor()

            # Use existing project_id or create new project
            if project_id:
                cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
                if not cursor.fetchone():
                    print(f"[!] Project ID {project_id} not found")
                    return False
            elif project_name:
                project_id = self.create_project(project_name, f"HellFuzzer scan - {datetime.now().strftime('%Y-%m-%d')}")
                if not project_id:
                    return False
            else:
                print("[!] Either project_name or project_id must be provided")
                return False

            # Get base URL from scan data
            base_url = scan_data.get('scope', [''])[0]
            if not base_url:
                print("[!] No base URL found in scan data")
                return False

            # Create or get asset for the base URL
            cursor.execute(
                "SELECT id FROM assets WHERE url = ? AND project_id = ?",
                (base_url, project_id)
            )
            asset_result = cursor.fetchone()

            if asset_result:
                asset_id = asset_result[0]
                print(f"[*] Using existing asset ID: {asset_id}")
            else:
                cursor.execute(
                    "INSERT INTO assets (project_id, url, discovery_date) VALUES (?, ?, ?)",
                    (project_id, base_url, datetime.now().isoformat())
                )
                asset_id = cursor.lastrowid
                print(f"[+] Created new asset ID: {asset_id}")

            # Import findings as endpoints
            endpoints_imported = 0
            findings = scan_data.get('findings', [])
            discovery_date = datetime.now().isoformat()

            for finding in findings:
                references = finding.get('references', [])
                if not references:
                    continue
                
                finding_url = references[0]
                parsed_url = urlparse(finding_url)
                path = parsed_url.path

                if not path:
                    continue

                description = finding.get('description', '')
                status_code = 0
                
                # Extract status code from description if available
                if 'status' in description:
                    import re
                    status_match = re.search(r'status\s+(\d+)', description, re.IGNORECASE)
                    if status_match:
                        status_code = int(status_match.group(1))

                # Insert endpoint with English column names
                cursor.execute(
                    """INSERT INTO endpoints 
                    (asset_id, path, status_code, method, discovered_by, content, discovery_date) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        asset_id,
                        path,
                        status_code,
                        'GET',  # Default method for fuzzing
                        'HellFuzzer',
                        description,
                        discovery_date
                    )
                )
                endpoints_imported += 1

            conn.commit()
            conn.close()

            print(f"[+] HellFuzzer import completed:")
            print(f"    - Base URL: {base_url}")
            print(f"    - Findings processed: {len(findings)}")
            print(f"    - Endpoints imported: {endpoints_imported}")

            return True

        except Exception as e:
            print(f"[!] Error importing HellFuzzer data: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """Main function for command line execution"""
    parser = argparse.ArgumentParser(description='HellFuzzer to HellSsus Database Adapter')
    parser.add_argument('json_file', nargs='?', help='Path to HellFuzzer JSON output file')
    parser.add_argument('--project', help='Project name for this scan')
    parser.add_argument('--project-id', type=int, help='Existing project ID to use')
    
    args = parser.parse_args()
    
    adapter = HellFuzzerAdapter()
    
    print("[*] Starting HellFuzzer import...")
    success = adapter.import_scan(args.json_file, args.project, args.project_id)
    
    if success:
        print("[+] Import completed successfully!")
    else:
        print("[!] Import failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()