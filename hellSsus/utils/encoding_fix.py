"""
Encoding fix for Windows Unicode issues
"""
import sys
import os

def setup_windows_encoding():
    if sys.platform == "win32":
        try:
            # Python 3.7+
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except AttributeError:
            # Fallback for older Python
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='ignore')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='ignore')
        
        os.environ['PYTHONIOENCODING'] = 'utf-8'

setup_windows_encoding()