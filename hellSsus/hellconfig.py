import os
import glob
from datetime import datetime

# Root paths
HELLSUITE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELLSSUS_ROOT = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# Tool paths
TOOLS_DIR = os.path.join(HELLSUITE_ROOT, "tools")
HELLRECON_PATH = os.path.join(TOOLS_DIR, "hellRecon", "hellRecon.py")
HELLFUZZER_PATH = os.path.join(TOOLS_DIR, "hellFuzzer", "hellFuzzer.py")
HELLSCANNER_PATH = os.path.join(ROOT_DIR, '..', 'tools', 'hellScanner', 'hellScanner.py')
NUCLEISCANNER_PATH = os.path.join(TOOLS_DIR, "hellScanner", "nucleiscanner.py")

# Data paths
SHARED_DATA_DIR = os.path.join(HELLSUITE_ROOT, "shared_data")
SCANS_DIR = os.path.join(SHARED_DATA_DIR, "scans")
REPORTS_DIR = os.path.join(SHARED_DATA_DIR, "reports")
WORDLISTS_DIR = os.path.join(SHARED_DATA_DIR, "wordlists")

# Database
HELLSSUS_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hellSsus")
DATABASE_DIR = os.path.join(HELLSSUS_ROOT, "database")
DATABASE_PATH = os.path.join(DATABASE_DIR, "hellSsus.db")

# Ensure directories exist
for directory in [DATABASE_DIR, SCANS_DIR, REPORTS_DIR, WORDLISTS_DIR]:
    os.makedirs(directory, exist_ok=True)

def get_latest_scan(tool_name):
    """Find the most recent scan file for a tool"""
    pattern = os.path.join(SCANS_DIR, f"{tool_name}_scan_*.json")
    scan_files = glob.glob(pattern)
    if not scan_files:
        return None
    return max(scan_files, key=os.path.getctime)

def get_scan_path(tool_name, target):
    """Generate scan file path for a new scan"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_').replace('?', '_').replace('&', '_')
    filename = f"{tool_name}_scan_{safe_target}_{timestamp}.json"
    return os.path.join(SCANS_DIR, filename)

# Export all for easier imports
__all__ = [
    'DATABASE_PATH',
    'HELLSCANNER_PATH',
    'HELLRECON_PATH',
    'HELLFUZZER_PATH',
    'NUCLEISCANNER_PATH',
    'SCANS_DIR',
    'WORDLISTS_DIR',
    'REPORTS_DIR',
    'SHARED_DATA_DIR',
    'get_scan_path',
    'get_latest_scan'
]