import sqlite3
import json
import os
import sys
from datetime import datetime

# Import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hellconfig import DATABASE_PATH

class HellScannerAdapter:
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
    
    def connect_db(self):
        """Connect to SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            return conn
        except sqlite3.Error as e:
            print(f"[!] Database connection error: {e}")
            return None
    
    def save_scan_results(self, scan_data):
        """
        Save HellScanner results directly to database
        Uses scan_data dict instead of JSON file for better integration
        """
        try:
            conn = self.connect_db()
            if not conn:
                return False
            
            cursor = conn.cursor()
            vulnerabilities_imported = 0
            
            # Get or create project
            project_name = scan_data.get('project_name', 'Default Project')
            cursor.execute(
                "INSERT OR IGNORE INTO projects (name, created_date) VALUES (?, ?)",
                (project_name, datetime.now().isoformat())
            )
            
            # Get project ID
            cursor.execute("SELECT id FROM projects WHERE name = ?", (project_name,))
            project_result = cursor.fetchone()
            if project_result:
                project_id = project_result[0]
            else:
                print(f"[!] Failed to get project ID for: {project_name}")
                conn.close()
                return False
            
            # Get or create asset
            target_url = scan_data.get('target')
            cursor.execute(
                """INSERT OR IGNORE INTO assets 
                (url, technologies, open_ports, project_id) 
                VALUES (?, ?, ?, ?)""",
                (target_url, '[]', '[]', project_id)
            )
            
            # Get asset ID
            cursor.execute("SELECT id FROM assets WHERE url = ? AND project_id = ?", 
                          (target_url, project_id))
            asset_result = cursor.fetchone()
            asset_id = asset_result[0] if asset_result else None
            
            # Process vulnerabilities from scan data
            vulnerabilities = scan_data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                cursor.execute(
                    """INSERT INTO vulnerabilities 
                    (project_id, asset_id, type, severity, description, 
                     reference, proof_of_concept, recommendation, cve) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        project_id,
                        asset_id,
                        vuln.get('type'),
                        vuln.get('severity'),
                        vuln.get('description'),
                        vuln.get('reference', ''),
                        vuln.get('proof_of_concept'),
                        vuln.get('recommendation'),
                        vuln.get('cve', '')
                    )
                )
                vulnerabilities_imported += 1
            
            conn.commit()
            conn.close()
            
            print(f"[+] HellScanner import completed:")
            print(f"    - Project: {project_name}")
            print(f"    - Target: {target_url}")
            print(f"    - Vulnerabilities imported: {vulnerabilities_imported}")
            
            return True
            
        except Exception as e:
            print(f"[!] Error saving HellScanner data: {e}")
            import traceback
            traceback.print_exc()
            return False

    def import_scan(self, json_file_path, project_id, asset_id=None):
        """
        Import HellScanner JSON results into database
        Kept for backward compatibility
        """
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                scan_data = json.load(f)
            
            # Set project ID for the scan data
            scan_data['project_id'] = project_id
            scan_data['asset_id'] = asset_id
            
            return self.save_scan_results(scan_data)
            
        except Exception as e:
            print(f"[!] Error importing HellScanner data: {e}")
            import traceback
            traceback.print_exc()
            return False

# Global function for easy import
def save_scan_results(scan_data):
    """Global function to save scan results"""
    adapter = HellScannerAdapter()
    return adapter.save_scan_results(scan_data)

def main():
    # Basic test function
    adapter = HellScannerAdapter()
    print("[*] HellScanner adapter created successfully")

if __name__ == "__main__":
    main()