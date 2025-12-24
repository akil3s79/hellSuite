#!/usr/bin/env python3
"""
HellSuite Orchestrator - Executes and coordinates all tools
"""
import argparse
import os
import subprocess
import sys
import traceback
import sqlite3 
import re

# Import new logging and error handling
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import hellconfig
from config.logging_config import orchestrate_logger, setup_application_logging
from utils.error_handler import (
    HellSuiteError, TimeoutError, NetworkError,
    retry, validate_url, log_error_with_context
)
from utils.decorators import (
    log_execution, validate_target_url, cached
)

# Add tools directory to path for Nuclei scanner
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'tools', 'hellScanner'))

DATABASE_PATH = hellconfig.DATABASE_PATH
HELLSCANNER_PATH = hellconfig.HELLSCANNER_PATH
SCANS_DIR = hellconfig.SCANS_DIR
WORDLISTS_DIR = hellconfig.WORDLISTS_DIR
HELLRECON_PATH = hellconfig.HELLRECON_PATH
HELLFUZZER_PATH = hellconfig.HELLFUZZER_PATH
get_scan_path = hellconfig.get_scan_path
get_latest_scan = hellconfig.get_latest_scan

# Alias for backward compatibility
robust_scan = log_execution(log_args=True, log_time=True)

# Setup logging
setup_application_logging()

@log_execution(log_args=True, log_time=True)
@validate_target_url
def run_hellrecon(target, output_file):
    """Run HellRecon with improved error handling"""
    # ENSURE output_file is an absolute path to avoid HellRecon saving it in its own directory
    output_file = os.path.abspath(output_file)

    cmd = [
            sys.executable, HELLRECON_PATH,
            target,
            "--report-format", "json",
            "-o", output_file,
        ]
    
    orchestrate_logger.info(f"Running HellRecon: {' '.join(cmd)}")
    
    try:
        # Run with timeout
        result = subprocess.run(
            cmd, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.PIPE,
            timeout=300,  # 5 minute timeout
            env={**os.environ, 'PYTHONIOENCODING': 'utf-8'} 
        )
        
        if result.returncode == 0 and os.path.exists(output_file):
            orchestrate_logger.info(f"HellRecon completed: {output_file}")
            return output_file
        else:
            error_msg = result.stderr.decode('utf-8', errors='ignore') if result.stderr else "Unknown error"
            orchestrate_logger.error(f"HellRecon failed (code: {result.returncode}): {error_msg}")
            return None
            
    except subprocess.TimeoutExpired:
        orchestrate_logger.error(f"HellRecon timed out after 5 minutes")
        raise TimeoutError("HellRecon execution timed out")
    except Exception as e:
        orchestrate_logger.error(f"HellRecon execution error: {e}")
        log_error_with_context(e, {'target': target, 'tool': 'hellrecon'})
        return None

@log_execution(log_args=True, log_time=True)
@retry(max_attempts=2, delay=5.0, exceptions=(subprocess.TimeoutExpired,))
def run_hellfuzzer(target, output_file, wordlist="common.txt"):
    """
    Run HellFuzzer with retry logic.
    Fixed: removed --silent flag, improved JSON path detection.
    """
    wordlist_path = os.path.join(WORDLISTS_DIR, wordlist)
    
    if not os.path.exists(wordlist_path):
        orchestrate_logger.error(f"Wordlist not found: {wordlist_path}")
        return None
    
    # Command WITHOUT --silent flag
    cmd = [
        sys.executable, HELLFUZZER_PATH,
        target,
        wordlist_path,
        "--format", "json",
        "--ci"
    ]
    
    orchestrate_logger.info(f"Running HellFuzzer: {' '.join(cmd)}")
    
    try:
        # Run process
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            encoding='utf-8', 
            timeout=120
        )

        # IMPROVED: Search in both stdout and stderr, case-insensitive
        json_match = re.search(r'\[JSON\].*exported to ([\w\.\-_]+\.json)', 
                               result.stdout + result.stderr, 
                               re.IGNORECASE)
        
        if json_match:
            json_filename = json_match.group(1)
            orchestrate_logger.info(f"HellFuzzer created JSON file: {json_filename}")
            
            # First, try to find the file in the current working directory
            possible_paths = [
                os.path.join(os.getcwd(), json_filename),          # Current directory
                os.path.join(os.path.dirname(HELLFUZZER_PATH), json_filename),  # Tool directory
                os.path.join(SCANS_DIR, json_filename),            # Shared scans directory
                os.path.join(os.path.dirname(__file__), json_filename)  # Orchestrator directory
            ]
            
            json_found_path = None
            for json_path in possible_paths:
                if os.path.exists(json_path):
                    json_found_path = json_path
                    break
            
            if json_found_path:
                # Copy the found JSON to the designated output location
                import shutil
                try:
                    shutil.copy2(json_found_path, output_file)
                    orchestrate_logger.info(f"HellFuzzer output saved: {output_file}")
                    return output_file
                except Exception as copy_error:
                    orchestrate_logger.error(f"Failed to copy result file: {copy_error}")
                    return None
            else:
                orchestrate_logger.error(f"JSON file not found in any expected location: {json_filename}")
                orchestrate_logger.error(f"Searched in: {possible_paths}")
                return None
        else:
            orchestrate_logger.error("Could not find JSON export pattern in HellFuzzer output")
            if result.stderr:
                orchestrate_logger.error(f"HellFuzzer errors: {result.stderr[:500]}")
            return None
            
    except subprocess.TimeoutExpired:
        orchestrate_logger.error("HellFuzzer timed out after 2 minutes")
        raise TimeoutError("HellFuzzer execution timed out")
    except Exception as e:
        orchestrate_logger.error(f"HellFuzzer execution error: {e}")
        log_error_with_context(e, {'target': target, 'tool': 'hellfuzzer'})
        return None

@log_execution(log_args=True, log_time=True)
@retry(max_attempts=2, delay=3.0)
def run_hellscanner(target, output_file, project_name, project_id):
    """Run HellScanner with retry logic"""
    try:
        orchestrate_logger.info(f"Running HellScanner for project: {project_name} (ID: {project_id})")
        
        hellscanner_cmd = [
            sys.executable, 
            HELLSCANNER_PATH,
            "--project", project_name,
            "--url", target,
        ]
        
        orchestrate_logger.info(f"Command: {' '.join(hellscanner_cmd)}")
        
        # Run HellScanner
        result = subprocess.run(
            hellscanner_cmd, 
            capture_output=True, 
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        orchestrate_logger.info(f"HellScanner stdout: {result.stdout[:500]}...")
        if result.stderr:
            orchestrate_logger.warning(f"HellScanner stderr: {result.stderr[:500]}...")
        
        if result.returncode == 0:
            orchestrate_logger.info("HellScanner completed successfully")
            
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT COUNT(*) FROM vulnerabilities WHERE project_id = ?',
                (project_id,)
            )
            vuln_count = cursor.fetchone()[0]
            conn.close()
            
            orchestrate_logger.info(f"HellScanner found {vuln_count} vulnerabilities in database")
            return vuln_count > 0
            
        else:
            orchestrate_logger.error(f"HellScanner failed (code: {result.returncode})")
            return False
            
    except subprocess.TimeoutExpired:
        orchestrate_logger.error("HellScanner timed out after 5 minutes")
        raise TimeoutError("HellScanner execution timed out")
    except Exception as e:
        orchestrate_logger.error(f"Error running HellScanner: {e}")
        log_error_with_context(e, {'target': target, 'project': project_name})
        return False

@log_execution(log_args=True, log_time=True)
@retry(max_attempts=2, delay=3.0)
def run_nucleiscanner(target, output_file, project_id):
    """Run Nuclei scanner with retry logic"""
    try:
        orchestrate_logger.info(f"Running Nuclei scanner for project ID: {project_id}")
        
        # Import here to avoid circular imports
        from nucleiscanner import run_nuclei_scan
        
        # Run the scan
        result = run_nuclei_scan(target, output_file)
        
        if result.get('status') == 'success':
            findings_count = result.get('findings_count', 0)
            orchestrate_logger.info(f"Nuclei completed. Findings: {findings_count}")
            
            # Return the actual output file path
            return result.get('output_file')
        else:
            error_msg = result.get('error', 'Unknown error')
            orchestrate_logger.error(f"Nuclei scan failed: {error_msg}")
            return None
            
    except Exception as e:
        orchestrate_logger.error(f"Error running Nuclei scanner: {e}")
        log_error_with_context(e, {'target': target, 'tool': 'nuclei'})
        return None

@log_execution(log_args=True)
@cached(ttl=300)  # Cache project lookup for 5 minutes
def get_or_create_project(project_name):
    """Get existing project or create new one with caching"""
    try:
        from integrations.hellrecon_adapter import HellReconAdapter
        adapter = HellReconAdapter()
        
        # Check if it already exists
        conn = adapter.connect_db()
        if not conn:
            orchestrate_logger.error("Failed to connect to database")
            return None
            
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM projects WHERE name = ?', (project_name,))
        existing_project = cursor.fetchone()
        conn.close()
        
        if existing_project:
            orchestrate_logger.info(f"Using existing project: {project_name} (ID: {existing_project[0]})")
            return existing_project[0]
        else:
            project_id = adapter.create_project(project_name)
            if project_id:
                orchestrate_logger.info(f"Project created: {project_name} (ID: {project_id})")
            else:
                orchestrate_logger.error(f"Failed to create project: {project_name}")
            return project_id
            
    except Exception as e:
        orchestrate_logger.error(f"Error with project creation: {e}")
        log_error_with_context(e, {'project_name': project_name})
        return None

@log_execution(log_args=True, log_time=True)
def import_tool_results(tool_name, target, output_file, project_id):
    """Import tool results with standardized error handling"""
    try:
        if tool_name == "hellrecon":
            from integrations.hellrecon_adapter import HellReconAdapter
            adapter = HellReconAdapter()
            success = adapter.import_scan(output_file, project_id=project_id)
            
        elif tool_name == "hellfuzzer":
            # Dynamic import for HellFuzzer
            import importlib.util
            adapter_path = os.path.join(os.path.dirname(__file__), 'integrations', 'hellfuzzer_adapter.py')
            spec = importlib.util.spec_from_file_location("hellfuzzer_adapter", adapter_path)
            hellfuzzer_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hellfuzzer_module)
            
            adapter = hellfuzzer_module.HellFuzzerAdapter()
            success = adapter.import_scan(output_file, project_id=project_id)
            
        elif tool_name == "hellscanner":

            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT COUNT(*) FROM vulnerabilities WHERE project_id = ?',
                (project_id,)
            )
            vuln_count = cursor.fetchone()[0]
            conn.close()
            
            if vuln_count > 0:
                orchestrate_logger.info(f"HellScanner found {vuln_count} vulnerabilities")
                success = True
            else:

                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT COUNT(*) FROM assets WHERE project_id = ?',
                    (project_id,)
                )
                asset_count = cursor.fetchone()[0]
                conn.close()
                
                if asset_count > 0:
                    orchestrate_logger.info("HellScanner executed but found no vulnerabilities")
                    success = True
                else:
                    orchestrate_logger.warning("HellScanner may not have executed properly")
                    success = False
            
        elif tool_name == "nuclei":
            from integrations.nuclei_adapter import NucleiAdapter
            adapter = NucleiAdapter()
            success = adapter.import_scan(output_file, project_id=project_id)            
            
        else:
            orchestrate_logger.error(f"Unknown tool for import: {tool_name}")
            return False
        
        if success:
            orchestrate_logger.info(f"{tool_name} data imported successfully")
        else:
            orchestrate_logger.error(f"Failed to import {tool_name} data")
        
        return success
        
    except ImportError as e:
        orchestrate_logger.error(f"Failed to import {tool_name} adapter: {e}")
        return False
    except Exception as e:
        orchestrate_logger.error(f"Error importing {tool_name} results: {e}")
        log_error_with_context(e, {'tool': tool_name, 'project_id': project_id})
        return False

def main():
    parser = argparse.ArgumentParser(description='HellSuite Orchestrator')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--tools', help='Tools to run (recon,fuzz,scanner,nuclei,all)', default='all')
    parser.add_argument('--project', help='Project name', required=True)
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity (safe check)
    if hasattr(args, 'verbose') and args.verbose:
        from config.logging_config import get_logger
        logger = get_logger('orchestrate')
        logger.setLevel(10)  # DEBUG
    
    orchestrate_logger.info(f"Starting HellSuite scan for: {args.target}")
    orchestrate_logger.info(f"Project: {args.project}")
    orchestrate_logger.info(f"Tools: {args.tools}")
    
    # Validate URL
    try:
        validate_url(args.target)
    except Exception as e:
        orchestrate_logger.error(f"Invalid target URL: {e}")
        sys.exit(1)
    
    # Create project once
    project_id = get_or_create_project(args.project)
    
    if not project_id:
        orchestrate_logger.error("Failed to create project, exiting")
        sys.exit(1)
    
    # Run tools with the same project_id
    tools_run = 0
    tools_success = 0
    
    if 'recon' in args.tools or 'all' in args.tools:
        tools_run += 1
        recon_output = get_scan_path("hellrecon", args.target)
        
        recon_output = os.path.abspath(recon_output)
        
        if run_hellrecon(args.target, recon_output):
            orchestrate_logger.info(f"HellRecon completed: {recon_output}")
            if import_tool_results("hellrecon", args.target, recon_output, project_id):
                tools_success += 1
        else:
            orchestrate_logger.error("HellRecon failed or produced no output")
    
    if 'fuzz' in args.tools or 'all' in args.tools:
        tools_run += 1
        fuzz_output = get_scan_path("hellfuzzer", args.target)
        if run_hellfuzzer(args.target, fuzz_output):
            orchestrate_logger.info(f"HellFuzzer completed: {fuzz_output}")
            if import_tool_results("hellfuzzer", args.target, fuzz_output, project_id):
                tools_success += 1
        else:
            orchestrate_logger.error("HellFuzzer failed or produced no output")
    
    if 'scanner' in args.tools or 'all' in args.tools:
        tools_run += 1
        scanner_output = get_scan_path("hellscanner", args.target)
        
        orchestrate_logger.info("Executing HellScanner...")
        scanner_success = run_hellscanner(args.target, scanner_output, args.project, project_id)
        
        if scanner_success:

            if import_tool_results("hellscanner", args.target, scanner_output, project_id):
                tools_success += 1
                orchestrate_logger.info("HellScanner completed and data imported")
            else:
                orchestrate_logger.error("HellScanner import failed")
        else:
            orchestrate_logger.error("HellScanner execution failed")
    
    if 'nuclei' in args.tools or 'all' in args.tools:
        tools_run += 1
        nuclei_output = get_scan_path("nuclei", args.target)
        
        orchestrate_logger.info("Executing Nuclei scanner...")
        nuclei_result_file = run_nucleiscanner(args.target, nuclei_output, project_id)
        
        if nuclei_result_file and os.path.exists(nuclei_result_file):
            orchestrate_logger.info(f"Nuclei scanner completed: {nuclei_result_file}")
            tools_success += 1

        else:

            if nuclei_result_file is not None:
                orchestrate_logger.info("Nuclei completed with 0 findings")
                tools_success += 1
            else:
                orchestrate_logger.error("Nuclei scanner failed to execute")
    
    # Summary
    orchestrate_logger.info(f"HellSuite scan completed: {tools_success}/{tools_run} tools succeeded")
    if tools_success > 0:
        orchestrate_logger.info(f"Project ID: {project_id} - Data available in dashboard")
    else:
        orchestrate_logger.warning("No tools succeeded. Check logs for errors.")
    
    sys.exit(0 if tools_success > 0 else 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        orchestrate_logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        orchestrate_logger.critical(f"Unexpected error in orchestrator: {e}", exc_info=True)
        sys.exit(1)