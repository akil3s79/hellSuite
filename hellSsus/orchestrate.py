#!/usr/bin/env python3
"""
HellSuite Orchestrator - Executes and coordinates all tools
"""
import argparse
import os
import subprocess
import sys

# Import config
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import *

def run_hellrecon(target, output_file):
    cmd = [
        sys.executable, HELLRECON_PATH,
        target,
        "--report-format", "json",
        "-o", output_file,
        "--silent"
    ]
    print(f"[*] Running HellRecon: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=os.environ.copy())
        
        if result.returncode == 0 and os.path.exists(output_file):
            print(f"[+] HellRecon output saved to: {output_file}")
            return output_file
        else:
            print(f"[!] HellRecon failed with code: {result.returncode}")
            return None
    except Exception as e:
        print(f"[!] HellRecon execution error: {e}")
        return None

def run_hellfuzzer(target, output_file, wordlist="common.txt"):
    wordlist_path = os.path.join(WORDLISTS_DIR, wordlist)
    
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found: {wordlist_path}")
        return None
    
    cmd = [
        sys.executable, HELLFUZZER_PATH,
        target,
        wordlist_path,
        "--format", "json",
        "--ci",
        "--silent"
    ]
    print(f"[*] Running HellFuzzer: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', timeout=120)
        
        import re
        json_match = re.search(r'exported to ([\w\._]+)', result.stdout)
        
        if json_match:
            json_filename = json_match.group(1)
            
            possible_paths = [
                os.path.join(os.path.dirname(HELLFUZZER_PATH), json_filename),
                os.path.join(os.getcwd(), json_filename),
                os.path.join(os.path.dirname(__file__), json_filename),
                os.path.join(SCANS_DIR, json_filename)
            ]
            
            for json_path in possible_paths:
                if os.path.exists(json_path):
                    import shutil
                    shutil.copy2(json_path, output_file)
                    print(f"[+] HellFuzzer output saved to: {output_file}")
                    return output_file
            
            print(f"[!] JSON file not found: {json_filename}")
            return None
        else:
            print("[!] Could not find JSON file path in HellFuzzer output")
            return None
            
    except subprocess.TimeoutExpired:
        print("[!] HellFuzzer timed out")
        return None
    except Exception as e:
        print(f"[!] HellFuzzer execution error: {e}")
        return None

def run_hellscanner(target, output_file, project_name, project_id):
    """Run HellScanner and import results"""
    try:
        from config import HELLSCANNER_PATH
        
        print(f"[*] Running HellScanner: {sys.executable} {HELLSCANNER_PATH} --project \"{project_name}\" --url {target} --silent")
        
        hellscanner_cmd = [
            sys.executable, 
            HELLSCANNER_PATH,
            "--project", project_name,
            "--url", target,
            "--silent"
        ]
        
        # Run HellScanner
        result = subprocess.run(hellscanner_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[+] HellScanner completed successfully")
            return True
        else:
            print(f"[!] HellScanner failed with code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"[!] Error running HellScanner: {e}")
        return False

def get_or_create_project(project_name):
    """Get existing project or create new one"""
    try:
        from integrations.hellrecon_adapter import HellReconAdapter
        adapter = HellReconAdapter()
        
        # check if it already exists
        conn = adapter.connect_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM projects WHERE name = ?', (project_name,))
        existing_project = cursor.fetchone()
        conn.close()
        
        if existing_project:
            print(f"[*] Using existing project: {project_name} (ID: {existing_project[0]})")
            return existing_project[0]
        else:
            project_id = adapter.create_project(project_name)
            print(f"[+] Project created: {project_name} (ID: {project_id})")
            return project_id
            
    except Exception as e:
        print(f"[!] Error with project: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='HellSuite Orchestrator')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--tools', help='Tools to run (recon,fuzz,all)', default='all')
    parser.add_argument('--project', help='Project name', required=True)
    
    args = parser.parse_args()
    print(f"[*] Starting HellSuite scan for: {args.target}")
    print(f"[*] Project: {args.project}")
    print(f"[*] Tools: {args.tools}")
    
    # Create project once
    project_id = get_or_create_project(args.project)
    
    if not project_id:
        print("[!] Failed to create project, exiting")
        return
    
    # Run tools with the same project_id
    if 'recon' in args.tools or 'all' in args.tools:
        recon_output = get_scan_path("hellrecon", args.target)
        if run_hellrecon(args.target, recon_output):
            print(f"[+] HellRecon completed: {recon_output}")
            try:
                from integrations.hellrecon_adapter import HellReconAdapter
                adapter = HellReconAdapter()
                if adapter.import_scan(recon_output, project_id=project_id):
                    print("[+] HellRecon data imported to database")
            except Exception as e:
                print(f"[!] Error importing HellRecon: {e}")
    
    if 'fuzz' in args.tools or 'all' in args.tools:
        fuzz_output = get_scan_path("hellfuzzer", args.target)
        if run_hellfuzzer(args.target, fuzz_output):
            print(f"[+] HellFuzzer completed: {fuzz_output}")
            try:
                import importlib.util
                adapter_path = os.path.join(os.path.dirname(__file__), 'integrations', 'hellfuzzer_adapter.py')
                spec = importlib.util.spec_from_file_location("hellfuzzer_adapter", adapter_path)
                hellfuzzer_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(hellfuzzer_module)
                
                adapter = hellfuzzer_module.HellFuzzerAdapter()
                if adapter.import_scan(fuzz_output, project_id=project_id):
                    print("[+] HellFuzzer data imported to database")
            except Exception as e:
                print(f"[!] Error importing HellFuzzer: {e}")

    if 'scanner' in args.tools or 'all' in args.tools:
        scanner_output = get_scan_path("hellscanner", args.target)
        if run_hellscanner(args.target, scanner_output, args.project, project_id):
            print(f"[+] HellScanner completed")
            print("[+] HellScanner data imported to database")
        else:
            print("[!] HellScanner failed")

    print("[+] HellSuite scan completed!")
    print(f"[+] Project ID: {project_id} - All data consolidated")

if __name__ == "__main__":
    main()