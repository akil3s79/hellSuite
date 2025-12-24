import sqlite3
import json
import os
import sys
import argparse
from datetime import datetime
from urllib.parse import urlparse

# Import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hellconfig  import DATABASE_PATH, get_latest_scan

class HellReconAdapter:
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
        Import HellRecon JSON results into database
        Accepts either project_name (creates new) or project_id (uses existing)
        """
        try:
            if not json_file_path:
                json_file_path = get_latest_scan("hellrecon")
                if not json_file_path:
                    print("[!] No HellRecon scan files found")
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
                project_id = self.create_project(project_name, f"HellRecon scan - {datetime.now().strftime('%Y-%m-%d')}")
                if not project_id:
                    return False
            else:
                print("[!] Either project_name or project_id must be provided")
                return False
            
            assets_imported = 0
            secrets_imported = 0
            discovery_date = datetime.now().isoformat()
            
            targets_data = scan_data.get('targets') or scan_data.get('results') or {}
            
            for target_url, target_data in targets_data.items():
                # Insert asset with English column names
                cursor.execute(
                    """INSERT INTO assets 
                    (project_id, url, technologies, open_ports, discovery_date) 
                    VALUES (?, ?, ?, ?, ?)""",
                    (
                        project_id,
                        target_url,
                        json.dumps(target_data.get('technologies', {})),
                        json.dumps(target_data.get('open_ports', [])),
                        discovery_date
                    )
                )
                asset_id = cursor.lastrowid
                assets_imported += 1
                
                # Handle secrets if present
                if 'secrets' in target_data:
                    for secret in target_data['secrets']:
                        cursor.execute(
                            """INSERT INTO endpoints 
                            (asset_id, path, discovered_by, content, discovery_date) 
                            VALUES (?, ?, ?, ?, ?)""",
                            (
                                asset_id,
                                secret.get('location', ''),
                                'HellRecon',
                                f"Secret found: {secret.get('type', 'unknown')} (confidence: {secret.get('confidence', 0)})",
                                discovery_date
                            )
                        )
                        secrets_imported += 1
            
            conn.commit()
            conn.close()
            
            print(f"[+] HellRecon import completed:")
            print(f"    - Assets imported: {assets_imported}")
            print(f"    - Secrets imported: {secrets_imported}")
            
            return True
            
        except Exception as e:
            print(f"[!] Error importing HellRecon data: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """Main function for command line execution"""
    parser = argparse.ArgumentParser(description='HellRecon to HellSsus Database Adapter')
    parser.add_argument('json_file', nargs='?', help='Path to HellRecon JSON output file')
    parser.add_argument('--project', help='Project name for this scan')
    parser.add_argument('--project-id', type=int, help='Existing project ID to use')
    
    args = parser.parse_args()
    
    adapter = HellReconAdapter()
    
    print("[*] Starting HellRecon import...")
    success = adapter.import_scan(args.json_file, args.project, args.project_id)
    
    if success:
        print("[+] Import completed successfully!")
    else:
        print("[!] Import failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()