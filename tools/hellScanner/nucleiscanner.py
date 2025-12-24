#!/usr/bin/env python3
"""
hellScanner Nuclei Module - hellSuite
Safely executes Nuclei scans with configurable templates and severity levels.
Designed for integration with the hellSuite orchestration system.
"""

import json
import subprocess
import sys
import os
from pathlib import Path

def run_nuclei_scan(target, output_file=None, templates=None, severity=None, rate_limit=150, timeout=3600):
    """
    Core function to execute a Nuclei scan. Safe and robust.

    Args:
        target (str): Single URL or host to scan (e.g., 'http://example.com').
        output_file (str, optional): Full path to save JSON results. If None, results are only returned.
        templates (str, optional): Path to specific template or directory.
        severity (str, optional): Filter by severity (info, low, medium, high, critical).
        rate_limit (int, optional): Requests per second limit.
        timeout (int, optional): Maximum execution time in seconds.

    Returns:
        dict: Standardized hellSuite result dict.
        Example: {'status': 'success', 'data': [...], 'output_file': '/path/file.json', 'error': None}
    """
    # 1. SECURITY & INPUT VALIDATION (Critical for OWASP Top 10 - Command Injection)
    if not isinstance(target, str) or not target.strip():
        return {'status': 'error', 'error': 'Invalid target provided. Must be a non-empty string.', 'data': []}
    
    target = target.strip()
    # Basic safety check - reject targets that could be part of a command injection attempt
    if any(char in target for char in [';', '&', '|', '`', '$', '>', '<', '\n']):
        return {'status': 'error', 'error': 'Target contains potentially dangerous characters.', 'data': []}

    # 2. COMMAND CONSTRUCTION (Using list for safety, NO shell=True)
    cmd = ["nuclei", "-u", target, "-j", "-silent", "-rl", str(rate_limit), "-timeout", str(timeout // 60)]
    
    # Add TAGS by default for faster, more relevant scans
    if not templates:  # Only add default tags if no custom templates specified
        cmd.extend(["-tags", "tech,network,vulnerability"])

    # Add severity filter if specified and valid
    valid_severities = ["info", "low", "medium", "high", "critical"]
    if severity and severity.lower() in valid_severities:
        cmd.extend(["-severity", severity.lower()])

    # Add custom templates with path validation
    if templates:
        template_path = Path(templates)
        if template_path.exists():
            cmd.extend(["-t", str(template_path.resolve())])  # Use absolute path
        else:
            # Log warning but proceed with default templates
            print(f"[!] WARNING: Custom template path not found: {templates}. Using default Nuclei templates.", file=sys.stderr)

    # 3. EXECUTION WITH ROBUST ERROR HANDLING
    print(f"[*] Starting Nuclei scan for: {target}", file=sys.stderr)
    
    try:
        # SECURITY: subprocess.run with list, timeout, and no shell
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        error_msg = f"Nuclei scan timed out after {timeout} seconds."
        print(f"[-] ERROR: {error_msg}", file=sys.stderr)
        return {'status': 'error', 'error': error_msg, 'data': []}
    except FileNotFoundError:
        error_msg = "Nuclei binary not found. Please ensure it's installed and in the system PATH."
        print(f"[-] ERROR: {error_msg}", file=sys.stderr)
        return {'status': 'error', 'error': error_msg, 'data': []}
    except Exception as e:
        error_msg = f"Unexpected error launching Nuclei: {str(e)}"
        print(f"[-] ERROR: {error_msg}", file=sys.stderr)
        return {'status': 'error', 'error': error_msg, 'data': []}

    # 4. OUTPUT PROCESSING
    findings = []
    if process.stdout:
        for line in process.stdout.strip().splitlines():
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # Skip malformed lines, log if needed

    # 5. SAVE RESULTS (if output path provided)
    saved_path = None
    if output_file:
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
            with open(output_path, 'w') as f:
                json.dump(findings, f, indent=4)
            saved_path = str(output_path.resolve())
            print(f"[+] Results saved to: {saved_path}", file=sys.stderr)
        except Exception as e:
            error_msg = f"Failed to save output file: {str(e)}"
            print(f"[-] WARNING: {error_msg}", file=sys.stderr)
            # Don't fail the scan just because of save error

    # 6. RETURN STANDARDIZED RESULT
    scan_successful = process.returncode == 0
    result = {
        'status': 'success' if scan_successful else 'error',
        'data': findings,
        'findings_count': len(findings),
        'output_file': saved_path,
        'target': target,
        'command_executed': ' '.join(cmd)  # Useful for debugging
    }
    
    if process.stderr and process.returncode != 0:
        result['error'] = process.stderr.strip()
        print(f"[-] Nuclei stderr: {process.stderr}", file=sys.stderr)
    
    print(f"[+] Nuclei scan finished. Status: {result['status']}. Findings: {len(findings)}", file=sys.stderr)
    return result

# --- Support function for orchestrate.py (scans multiple targets) ---
def run_nuclei_scan_bulk(targets, output_dir=None, **kwargs):
    """
    Scans multiple targets. Called by the orchestrator.
    
    Args:
        targets (list): List of target URLs/hosts.
        output_dir (str): Directory to save individual result files.
        **kwargs: Passed to run_nuclei_scan (templates, severity, etc.).
    
    Returns:
        list: List of result dicts for each target.
    """
    all_results = []
    for target in targets:
        print(f"\n[*] Processing target: {target}", file=sys.stderr)
        
        # Build output file path if directory is provided
        output_file = None
        if output_dir:
            # Create a safe filename from the target
            safe_name = target.replace('://', '_').replace('/', '_').replace(':', '_')
            # Limit length to avoid filesystem errors
            safe_name = safe_name[:150] if len(safe_name) > 150 else safe_name
            output_file = os.path.join(output_dir, f"nuclei_{safe_name}.json")
        
        result = run_nuclei_scan(target, output_file, **kwargs)
        all_results.append(result)
    
    return all_results


# --- Command-line execution (for direct testing) ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nucleiscanner.py <target> [output_file.json]", file=sys.stderr)
        print("Example: python nucleiscanner.py http://testphp.vulnweb.com results.json", file=sys.stderr)
        sys.exit(1)
    
    target = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    result = run_nuclei_scan(target, output_file)
    print(json.dumps(result, indent=2))