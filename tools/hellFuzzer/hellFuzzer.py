#!/usr/bin/env python3
"""
hellFuzzer - Directory and file fuzzer for web pentesting  
Author: akil3s (Rober)
Version: 1.4
"""

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import sys
import threading
import time
import os
import queue
import re
import json
from datetime import datetime
from argparse import ArgumentParser
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

def show_banner():
    """
    Minimal banner for HellFuzzer.
    No Unicode characters to avoid encoding issues.
    """
    print("\n" + "="*60)
    print("HELLFUZZER - Directory and File Fuzzer")
    print("="*60 + "\n")

try:
    import colorama
    colorama.init()  # For Windows colours
    USE_COLORS = True
except ImportError:
    USE_COLORS = False

class Colors:
    """Color handling with colorama fallback"""
    if USE_COLORS:
        RED = colorama.Fore.RED
        GREEN = colorama.Fore.GREEN
        YELLOW = colorama.Fore.YELLOW
        BLUE = colorama.Fore.BLUE
        CYAN = colorama.Fore.CYAN
        MAGENTA = colorama.Fore.MAGENTA
        ORANGE = colorama.Fore.YELLOW
        END = colorama.Style.RESET_ALL
    else:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = ORANGE = END = ''
		
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

print_lock = threading.Lock()

USE_COLORS = sys.stdout.isatty()

class Colors:
    """Color handling with TTY detection"""
    RED = '\033[91m' if USE_COLORS else ''
    GREEN = '\033[92m' if USE_COLORS else ''
    YELLOW = '\033[93m' if USE_COLORS else ''
    BLUE = '\033[94m' if USE_COLORS else ''
    CYAN = '\033[96m' if USE_COLORS else ''
    MAGENTA = '\033[95m' if USE_COLORS else ''
    ORANGE = '\033[33m' if USE_COLORS else ''
    END = '\033[0m' if USE_COLORS else ''

def parse_code_list(s):
    """Converts '200,301-302,401' → set {200,301,302,401}"""
    codes = set()
    for piece in s.split(','):
        if '-' in piece:
            start, end = map(int, piece.split('-'))
            codes.update(range(start, end + 1))
        else:
            codes.add(int(piece))
    return codes
JS_PATH_RE = re.compile(r'''(?:"|')((?:\/|[a-zA-Z0-9\-._~%!$&'()*+,;=:@])[a-zA-Z0-9\-._~%!$&'()*+,;=:@\/]*)["']''')
# Patterns to detect fetch() and XMLHttpRequest usage inside JS/HTML
FETCH_RE = re.compile(r'fetch\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
XHR_RE   = re.compile(r'open\(\s*[\'"](?:GET|POST|PUT|DELETE)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)

def extract_words_from_content(content, base_url, current_path):
    """
    Extract potential paths and words from HTML/JS content for word mining
    Returns set of new words to fuzz
    """
    words = set()
    
    try:
        path_patterns = [
            r'[\'"](/[a-zA-Z0-9_\-./][^\'"]*?)[\'"]',
            r'href=[\'"](/[^\'"]*?)[\'"]',
            r'src=[\'"](/[^\'"]*?)[\'"]', 
            r'action=[\'"](/[^\'"]*?)[\'"]',
            r'url\([\'"]?/([^\'")]*?)[\'"]?\)',
            r'[\'"]([a-zA-Z0-9_\-./]+\.(php|html|js|json|xml|asp|jsp))[\'"]',
        ]
        
        for pattern in path_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) > 1 and ' ' not in match:
                    clean_path = match.split('?')[0].split('#')[0]
                    if not clean_path.endswith(('.css', '.jpg', '.png', '.gif', '.ico', '.woff', '.ttf')):
                        words.add(clean_path.lstrip('/'))
        
        identifier_patterns = [
            r'\b([a-zA-Z_][a-zA-Z0-9_]{2,25})\b',
            r'name=[\'"]([a-zA-Z0-9_\-]+)[\'"]',
            r'id=[\'"]([a-zA-Z0-9_\-]+)[\'"]', 
            r'class=[\'"]([a-zA-Z0-9_\-]+)[\'"]',
            r'[\?&]([a-zA-Z0-9_\-]+)=',
            r'data-[a-z-]+=[\'"]([a-zA-Z0-9_\-]+)[\'"]',
        ]
        
        for pattern in identifier_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and not match.isdigit():
                    words.add(match)
        
        # SPECIFIC PATTERNS FOR ENDPOINTS AND HIDDEN ROUTES
        web_patterns = [
            r'/(admin|api|user|auth|config|dashboard|login|register|profile|upload|download|export|import|delete|edit|create|update)[a-zA-Z0-9_\-/]*',
            r'/([a-zA-Z0-9_\-]+)\.(php|html|asp|jsp|py|js|json|xml)',
            r'/[a-z0-9_\-]+\.[a-z]{2,4}',
            r'/[a-z0-9_\-]+/[a-z0-9_\-]+',
            r'/[a-z0-9_\-]+/[a-z0-9_\-]+/[a-z0-9_\-]+',
        ]
        
        for pattern in web_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) > 2:
                    words.add(match)
                    
    except Exception:
        pass
    
    filtered_words = set()
    common_noise = {'the', 'and', 'for', 'with', 'this', 'that', 'have', 'from', 'they', 'what'}
    
    for word in words:
        word_lower = word.lower()

        reject = (
            word_lower in common_noise or
            len(word) < 2 or len(word) > 50 or
            word.startswith(('//', '\\', '#', 'javascript:')) or
            word.isdigit() or
            word.count('/') > 5
        )
        
        if not reject:
            filtered_words.add(word)
    
    return filtered_words

    filtered_words = set()
    common_noise = {'the', 'and', 'for', 'with', 'this', 'that', 'have', 'from'}
    
    for word in words:
        word_lower = word.lower()
        
        reject = (
            word_lower in common_noise or
            len(word) < 2 or len(word) > 40 or
            word.startswith(('//', '\\', '#')) or
            word.isdigit()
        )
        
        if not reject:
            filtered_words.add(word)
    
    return filtered_words
    
    filtered_words = set()
    common_noise = {'the', 'and', 'for', 'with', 'this', 'that', 'have', 'from', 'they', 'what', 'when', 'where', 'which'}
    
    for word in words:
        word_lower = word.lower()
        
        keep_patterns = [
            '/' in word,
            '_' in word,
            '-' in word,
            word.isalnum() and len(word) > 4,
            any(char.isdigit() for char in word),
            word_lower.startswith(('api', 'admin', 'user', 'auth', 'config')),
        ]
        
        if (word and 2 <= len(word) <= 40 and 
            not word.startswith(('//', '\\')) and
            word_lower not in common_noise and
            any(keep_patterns)):
            filtered_words.add(word)
      
    return filtered_words

def extract_js_paths(url, session, timeout):
    """
    Download a JS file (or any text resource) and extract paths found inside.
    Returns a set of normalized absolute-path style strings (starting with '/').
    """
    try:
        r = session.get(url, verify=False, timeout=timeout)
        if r.status_code != 200:
            return set()

        txt = r.text

        paths = set(JS_PATH_RE.findall(txt))

        try:
            paths.update(FETCH_RE.findall(txt))
            paths.update(XHR_RE.findall(txt))
        except Exception:
            pass

        normalized = set()
        for p in paths:
            if not p or p.lower().startswith(('javascript:', 'mailto:')):
                continue
            if p.startswith('http://') or p.startswith('https://'):
                from urllib.parse import urlparse
                parsed_base = urlparse(url)
                parsed_p = urlparse(p)
                if parsed_p.netloc == parsed_base.netloc:
                    normalized.add(parsed_p.path if parsed_p.path.startswith('/') else '/' + parsed_p.path)
            elif p.startswith('/'):
                normalized.add(p)
            else:
                normalized.add('/' + p.lstrip('/'))
        return normalized
    except Exception:
        return set()

class AuthManager:
    """Authentication manager for hellFuzzer"""
    
    def __init__(self, args):
        self.auth_config = self._parse_auth_args(args)
        self.session = requests.Session()
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        self._setup_authentication()
    
    def _parse_auth_args(self, args):
        """Convert auth arguments into config dict"""
        config = {}
        
        if args.auth_basic:
            config['type'] = 'basic'
            config['credentials'] = args.auth_basic
        elif args.auth_jwt:
            config['type'] = 'jwt' 
            config['token'] = args.auth_jwt
        elif args.auth_oauth2:
            config['type'] = 'oauth2'
            config['token'] = args.auth_oauth2
        elif args.auth_header:
            config['type'] = 'custom'
            config['header'] = args.auth_header
            
        return config
    
    def _setup_authentication(self):
        """Configure session with selected authentication"""
        if not self.auth_config:
            return
            
        auth_type = self.auth_config.get('type')
        
        if auth_type == 'basic':
            user, pwd = self.auth_config['credentials'].split(':', 1)
            self.session.auth = (user, pwd)
            print(f"{Colors.CYAN}[AUTH] Basic Auth configured for user: {user}{Colors.END}")
            
        elif auth_type in ['jwt', 'oauth2']:
            token = self.auth_config['token']
            self.session.headers.update({'Authorization': f'Bearer {token}'})
            print(f"{Colors.CYAN}[AUTH] {auth_type.upper()} Bearer Token configured{Colors.END}")
            
        elif auth_type == 'custom':
            header_parts = self.auth_config['header'].split(':', 1)
            if len(header_parts) == 2:
                key, value = header_parts
                self.session.headers.update({key.strip(): value.strip()})
                print(f"{Colors.CYAN}[AUTH] Custom header: {key}{Colors.END}")
    
    def get_session(self):
        """Return authenticated session"""
        return self.session
    
    def test_auth(self, test_url, timeout=5):
        """Test if authentication works"""
        try:
            response = self.session.get(test_url, timeout=timeout, verify=False)
            if response.status_code == 401:
                return False, f"{Colors.RED}❌ Authentication FAILED - Still getting 401{Colors.END}"
            return True, f"{Colors.GREEN}✅ Authentication SUCCESSFUL - Session established{Colors.END}"
        except Exception as e:
            return False, f"{Colors.YELLOW}⚠️ Error testing auth: {e}{Colors.END}"

class RecursionManager:
    """Recursion manager for discovering hidden content"""
    
    def __init__(self, max_depth=0):
        self.max_depth = max_depth
        self.visited_urls = set()
        self.lock = threading.Lock()
    
    def should_process(self, url, current_depth):
        """Decide whether to process URL based on depth and visited status"""
        if current_depth > self.max_depth:
            return False
        
        # Normalize URL to avoid duplicates
        normalized_url = url.lower().split('?')[0]
        normalized_url = normalized_url.rstrip('/')
        
        with self.lock:
            if normalized_url in self.visited_urls:
                return False
            self.visited_urls.add(normalized_url)
        
        return True
    
    def extract_links_from_html(self, html_content, base_url):
        """Extract links from HTML to add to queue"""
        links = set()
        
        # Improved patterns for finding URLs
        patterns = [
            r'href=[\'"]([^\'"]*?)[\'"]',
            r'src=[\'"]([^\'"]*?)[\'"]',  
            r'action=[\'"]([^\'"]*?)[\'"]',
            r'url\([\'"]?([^\'")]*)[\'"]?\)'
        ]
        
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', 
                          '.ico', '.svg', '.woff', '.ttf', '.pdf', '.zip']
        for pattern in patterns:
            found_links = re.findall(pattern, html_content, re.IGNORECASE)
            for link in found_links:
                if any(link.endswith(ext) for ext in skip_extensions):
                    continue
                if link.startswith(('javascript:', 'mailto:', 'tel:', '#', '//')):
                    continue
                    
                if link.startswith(('http://', 'https://')):
                    if base_url in link:
                        links.add(link)
                elif link.startswith('/'):
                    links.add(f"{base_url.rstrip('/')}{link}")
                elif not link.startswith(('#', 'javascript:', 'mailto:')):
                    links.add(f"{base_url.rstrip('/')}/{link}")

        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.IGNORECASE)
        for script in inline_scripts:

            for p in JS_PATH_RE.findall(script):
                if p.startswith('http://') or p.startswith('https://'):
                    if base_url in p:
                        links.add(p)
                elif p.startswith('/'):
                    links.add(f"{base_url.rstrip('/')}{p}")
                else:
                    links.add(f"{base_url.rstrip('/')}/{p.lstrip('/')}")

            for f in FETCH_RE.findall(script):
                if f.startswith('http://') or f.startswith('https://'):
                    if base_url in f:
                        links.add(f)
                elif f.startswith('/'):
                    links.add(f"{base_url.rstrip('/')}{f}")
                else:
                    links.add(f"{base_url.rstrip('/')}/{f.lstrip('/')}")

            for x in XHR_RE.findall(script):
                if x.startswith('http://') or x.startswith('https://'):
                    if base_url in x:
                        links.add(x)
                elif x.startswith('/'):
                    links.add(f"{base_url.rstrip('/')}{x}")
                else:
                    links.add(f"{base_url.rstrip('/')}/{x.lstrip('/')}")

        return links

    
    def process_discovered_links(self, new_links, target_queue, current_depth):
        """Add discovered links to queue for processing"""
        added_count = 0
        for link in new_links:

            if link.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(link)
                path = parsed.path
            else:
                path = link
            
            if path.startswith('/'):
                path = path[1:]
            
            if path and self.should_process(path, current_depth + 1):
                target_queue.put(RecursiveLink(path, current_depth + 1))
                added_count += 1
       
        return added_count

class AutoFilter:
    """Automatic response filtering to reduce noise"""
    
    def __init__(self):
        self.seen_responses = {}  # hash -> (size, count)
        self.error_patterns = [
            r'<title>404 Not Found</title>',
            r'<h1>Not Found</h1>',
            r'<title>403 Forbidden</title>',
            r'<h1>Forbidden</h1>',
            r'<title>500 Internal Server Error</title>',
            r'<h1>Internal Server Error</h1>',
            r'The page cannot be found',
            r'File not found',
            r'Page not found',
            r'Error 404',
            r'Error 403',
            r'Error 500'
        ]
    
    def should_filter(self, response, word, aggressiveness=3):
        """
        Determine if a response should be filtered out
        Returns: (should_filter, reason)
        """
        content = response.text
        content_hash = hash(content)
        size = len(content)
        
        if size < 10:
            return True, "too_small"
        
        aggressiveness_thresholds = {
            1: 20,
            2: 15,
            3: 10,
            4: 7,
            5: 5
        }
        
        threshold = aggressiveness_thresholds.get(aggressiveness, 10)
        
        if content_hash in self.seen_responses:
            count = self.seen_responses[content_hash][1] + 1
            self.seen_responses[content_hash] = (size, count)
            
            if count >= threshold:
                return True, f"common_error (seen {count} times, threshold: {threshold})"
            else:
                return False, None
        else:
            self.seen_responses[content_hash] = (size, 1)
            return False, None
        
class RecursiveLink:
    """Represents a link discovered during recursion"""
    def __init__(self, path, depth):
        self.path = path
        self.depth = depth
    
    def __str__(self):
        return self.path

# Interesting content patterns
INTERESTING_PATTERNS = {
    'backup': [
        r'backup', r'back_up', r'bak', r'\.bak$', r'\.old$', r'\.save$',
        r'backup\.zip', r'backup\.tar', r'backup\.sql', r'database\.bak'
    ],
    'config': [
        r'config', r'configuration', r'\.env', r'env\.', r'settings', 
        r'configuration', r'config\.php', r'config\.json', r'config\.xml',
        r'web\.config', r'\.htaccess', r'htpasswd'
    ],
    'admin': [
        r'admin', r'administrator', r'dashboard', r'panel', r'control',
        r'manager', r'login', r'log_in', r'signin', r'root', r'superuser'
    ],
    'credentials': [
        r'password', r'credential', r'secret', r'key', r'token', 
        r'passwd', r'pwd', r'id_rsa', r'id_dsa', r'\.pem$',
        r'oauth', r'jwt', r'api[_-]?key'
    ],
    'database': [
        r'database', r'db', r'mysql', r'postgres', r'sqlite',
        r'\.sql$', r'dump', r'schema', r'migration'
    ],
    'log': [
        r'log', r'debug', r'error', r'trace', r'audit',
        r'\.log$', r'logging', r'history'
    ],
    'git': [
        r'\.git', r'gitignore', r'gitkeep', r'gitlab'
    ]
}

def is_interesting_path(path):
    """
    Detect if a path is interesting based on patterns
    Returns: (is_interesting, category, confidence)
    """
    path_lower = path.lower()
    
    for category, patterns in INTERESTING_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                # Calculate confidence based on pattern specificity
                confidence = "HIGH" if pattern.startswith(r'\.') or r'\.' in pattern else "MEDIUM"
                return True, category.upper(), confidence
    
    return False, None, None

def validate_url(url):
    """
    Validate and normalize target URL
    Returns: (is_valid, normalized_url_or_error)
    """
    if not url.startswith(('http://', 'https://')):
        error_msg = f"{Colors.RED}[ERROR] URL must include protocol (http:// or https://){Colors.END}"
        return False, error_msg
    return True, url

def is_in_scope(url, scope_domain):
    """
    Check if a URL is within the specified scope domain
    """
    if not scope_domain:
        return True
    
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        url_domain = parsed_url.netloc.lower()
        scope_domain = scope_domain.lower()
        
        return url_domain == scope_domain or url_domain.endswith('.' + scope_domain)
    except Exception:
        return False

def is_in_scope(url, scope_domain):
    """
    Check if a URL is within the specified scope domain
    """
    if not scope_domain:
        return True
    
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        url_domain = parsed_url.netloc.lower()
        scope_domain = scope_domain.lower()
        
        return url_domain == scope_domain or url_domain.endswith('.' + scope_domain)
    except Exception:
        return False

def load_wordlist(wordlist_path):
    """
    Load wordlist file and return list of words
    """
    if not os.path.isfile(wordlist_path):
        print(f"{Colors.RED}[ERROR] Wordlist not found: {wordlist_path}{Colors.END}")
        return None
    
    try:
        encodings_to_try = ['utf-8-sig', 'utf-8', 'latin-1']
        words = None
        for enc in encodings_to_try:
            try:
                with open(wordlist_path, 'r', encoding=enc) as file:
                    words = [line.strip() for line in file if line.strip()]
                break
            except UnicodeDecodeError:
                continue

        if words is None:
            print(f"{Colors.RED}[ERROR] Reading wordlist: unsupported encoding{Colors.END}")
            return None

        if not words:
            print(f"{Colors.RED}[ERROR] Wordlist is empty{Colors.END}")
            return None

        return words
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Reading wordlist: {e}{Colors.END}")
        return None

def load_targets_file(targets_file):
    """
    Load targets from file (one per line)
    """
    if not os.path.isfile(targets_file):
        print(f"{Colors.RED}[ERROR] Targets file not found: {targets_file}{Colors.END}")
        return None
    
    try:
        with open(targets_file, 'r', encoding='utf-8') as file:
            targets = [line.strip() for line in file if line.strip()]
            if not targets:
                print(f"{Colors.RED}[ERROR] Targets file is empty{Colors.END}")
                return None
            
            valid_targets = []
            for target in targets:
                is_valid, result = validate_url(target)
                if is_valid:
                    valid_targets.append(target)
                else:
                    print(f"{Colors.YELLOW}[WARNING] Skipping invalid target: {target}{Colors.END}")
            
            return valid_targets
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Reading targets file: {e}{Colors.END}")
        return None

def parse_cookies(cookie_string):
    """
    Convert cookie string to dict for requests
    Example: 'session=abc123; user=admin' -> {'session': 'abc123', 'user': 'admin'}
    """
    if not cookie_string:
        return {}
    
    cookies = {}
    for cookie in cookie_string.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            key, value = cookie.split('=', 1)
            cookies[key] = value
    return cookies

def generate_all_targets(words, extensions=None):
    """
    Generate ALL combinations of words + extensions BEFORE starting
    """
    all_targets = []
    
    for word in words:
        all_targets.append(word)
        if extensions:
            for ext in extensions:
                all_targets.append(f"{word}.{ext}")
    
    return all_targets

def format_size(size):
    """Format size in bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.0f}{unit}" if unit == 'B' else f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"

def format_time():
    """Return current time in [HH:MM:SS] format"""
    return datetime.now().strftime("[%H:%M:%S]")

def check_endpoint(target_url, word, session, timeout, args, ignore_codes=None, 
                   recursion_manager=None, auto_filter=None, current_depth=0, target_queue=None, 
                   stats=None, pwndoc_findings=None):
    """
    Check an endpoint and show result if interesting
    """
    if ignore_codes is None:
        ignore_codes = []
    
    url = f"{target_url.rstrip('/')}/{word}"
        
    try:
        response = session.get(url, timeout=timeout, allow_redirects=False)
        status = response.status_code
        
        # NEW: AUTO-FILTER IMPLEMENTATION
        if auto_filter and args.auto_filter:
            should_filter, reason = auto_filter.should_filter(response, word, args.filter_aggressiveness)
            if should_filter:
                if stats:
                    stats['filtered_responses'] = stats.get('filtered_responses', 0) + 1
                return

        if status in ignore_codes:
            return
        ok_codes   = parse_code_list(args.ok_codes)
        hide_codes = parse_code_list(args.hide_codes)
        if status in hide_codes:
            return
        hit = status in ok_codes
        is_interesting, category, confidence = is_interesting_path(word)
        
        timestamp = format_time()
        size = format_size(len(response.content))
        path = f"/{word}"
        
        with print_lock:
            if args.ci:
                if is_interesting or status == 200:
                    print(f"{timestamp} {status} - {size:>6} - {path}")
            else:
                if is_interesting:
                    if confidence == "HIGH":
                        color = Colors.ORANGE
                        marker = "🔥"
                    else:
                        color = Colors.YELLOW  
                        marker = "⚡"
                    
                    print(f"{timestamp} {Colors.GREEN if status == 200 else Colors.BLUE}{status}{Colors.END} - {size:>6} - {path} {color}{marker} [{category}]{Colors.END}")
                
                elif status == 200:
                    print(f"{timestamp} {Colors.GREEN}200{Colors.END} - {size:>6} - {path}")
                elif status == 403:
                    print(f"{timestamp} {Colors.YELLOW}403{Colors.END} - {size:>6} - {path}")
                elif status in [301, 302]:
                    print(f"{timestamp} {Colors.BLUE}{status}{Colors.END} - {size:>6} - {path} -> {response.headers.get('Location', '')}")
                elif status == 401:
                    print(f"{timestamp} {Colors.CYAN}401{Colors.END} - {size:>6} - {path}")
                else:
                    print(f"{timestamp} {status} - {size:>6} - {path}")
        
        if stats:
            stats['total_requests'] += 1
            stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
        if args.spa:
            try:
                any_fetches = set(FETCH_RE.findall(response.text)) | set(XHR_RE.findall(response.text))
            except Exception:
                any_fetches = set()
            base = target_url.rstrip('/')
            for f in any_fetches:
                if f.startswith(('http://', 'https://')):
                    if base in f:
                        parsed = f.split('/', 3)
                        candidate = '/' + parsed[3] if len(parsed) > 3 else '/'
                    else:
                        continue
                elif f.startswith('/'):
                    candidate = f
                else:
                    candidate = '/' + f.lstrip('/')
                enqueue = candidate.lstrip('/')
                full = base + candidate
                if enqueue and full not in seen:
                    target_queue.put(enqueue)
                    seen.add(full)
                    stats['spa_js_paths'] = stats.get('spa_js_paths', 0) + 1
    
            if is_interesting:
                stats['interesting_finds'][category] = stats['interesting_finds'].get(category, 0) + 1
        
        if args.spa and 'text/html' in response.headers.get('content-type', '').lower():
            script_srcs = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', response.text, re.IGNORECASE)
            base = target_url.rstrip('/')
            for s in script_srcs:
                if s.startswith(('http://', 'https://')):
                    if base in s:
                        parsed = s.split('/', 3)
                        path_part = '/' + parsed[3] if len(parsed) > 3 else '/'
                        candidate = path_part
                    else:
                        continue
                elif s.startswith('/'):
                    candidate = s
                else:
                    candidate = '/' + s.lstrip('/')
                enqueue = candidate.lstrip('/')
                full = base + candidate
                if enqueue and full not in seen:
                    target_queue.put(enqueue)
                    seen.add(full)
                    stats['spa_js_paths'] = stats.get('spa_js_paths', 0) + 1

            inline_fetches = set(FETCH_RE.findall(response.text)) | set(XHR_RE.findall(response.text))
            for f in inline_fetches:
                if f.startswith(('http://', 'https://')):
                    if base in f:
                        parsed = f.split('/', 3)
                        candidate = '/' + parsed[3] if len(parsed) > 3 else '/'
                    else:
                        continue
                elif f.startswith('/'):
                    candidate = f
                else:
                    candidate = '/' + f.lstrip('/')
                enqueue = candidate.lstrip('/')
                full = base + candidate
                if enqueue and full not in seen:
                    target_queue.put(enqueue)
                    seen.add(full)
                    stats['spa_js_paths'] = stats.get('spa_js_paths', 0) + 1

        if args.spa and word.endswith('.js'):
            new_paths = extract_js_paths(url, session, timeout)
            base = target_url.rstrip('/')
            for p in new_paths:
                full = base + p
                if full not in seen:
                    target_queue.put(p)
                    seen.add(full)
                    stats['spa_js_paths'] = stats.get('spa_js_paths', 0) + 1

        if args.word_mine and status == 200 and len(response.content) > 0:
            try:
                content_type = response.headers.get('content-type', '').lower()
                if any(ct in content_type for ct in ['text/html', 'text/javascript', 'application/json', 'text/plain']):
                    
                    mined_words = extract_words_from_content(response.text, target_url, word)
                    
                    if mined_words and target_queue:
                        base = target_url.rstrip('/')
                        added_count = 0
                        
                        for mined_word in mined_words:
                            if len(mined_word) > 50 or '..' in mined_word:
                                continue
                                
                            full_url = f"{base}/{mined_word}"
                            if full_url not in seen:
                                target_queue.put(mined_word)
                                seen.add(full_url)
                                added_count += 1
                        
                        if added_count > 0:
                            with print_lock:
                                print(f"{Colors.GREEN}[WORD-MINE] Added {added_count} words from: /{word}{Colors.END}")
                            
                            if stats:
                                stats['mined_words'] = stats.get('mined_words', 0) + added_count
                                
            except Exception:
                pass

        if args.auto_recurse and status in [200, 301, 302]:
            global seen_directories
            if 'seen_directories' not in globals():
                seen_directories = set()
                
            is_directory = False
            current_path = word.rstrip('/')
            
            has_extension = '.' in current_path.split('/')[-1] and not current_path.endswith('/')
            if has_extension:
                is_directory = False
            elif word.endswith('/'):
                is_directory = True
            elif status in [301, 302] and 'Location' in response.headers:
                location = response.headers['Location']
                if location.endswith('/') and current_path in location:
                    is_directory = True
            elif '.' not in current_path.split('/')[-1] and current_path.count('/') < 3:
                suspicious_files = ['Entries', 'Repository', 'Root', 'config', 'README', 'LICENSE', 'Makefile']
                if current_path.split('/')[-1] not in suspicious_files:
                    is_directory = True
            elif 'text/html' in response.headers.get('content-type', '') and any(
                pattern in response.text for pattern in ['<title>Index of', '<h1>Directory', 'Parent Directory', '[To Parent Directory]']
            ):
                is_directory = True
            
            if is_directory and current_path not in seen_directories and target_queue:
                seen_directories.add(current_path)
                
                base = target_url.rstrip('/')
                dir_path = current_path
                
                new_paths = []
                dir_name = dir_path.lower().split('/')[-1]
                
                base_paths = [
                    f"{dir_path}/.git", f"{dir_path}/.env", f"{dir_path}/admin", 
                    f"{dir_path}/api", f"{dir_path}/config", f"{dir_path}/backup",
                    f"{dir_path}/database", f"{dir_path}/uploads", f"{dir_path}/test"
                ]
                new_paths.extend(base_paths)
                
                if 'image' in dir_name or 'picture' in dir_name or 'media' in dir_name:
                    new_paths.extend([f"{dir_path}/original", f"{dir_path}/thumbs", f"{dir_path}/large"])
                elif 'admin' in dir_name or 'secure' in dir_name or 'control' in dir_name:
                    new_paths.extend([f"{dir_path}/login.php", f"{dir_path}/dashboard", f"{dir_path}/users"])
                elif 'api' in dir_name or 'rest' in dir_name:
                    new_paths.extend([f"{dir_path}/v1", f"{dir_path}/v2", f"{dir_path}/users", f"{dir_path}/auth"])
                elif 'js' in dir_name or 'script' in dir_name:
                    new_paths.extend([f"{dir_path}/app.js", f"{dir_path}/main.js", f"{dir_path}/bundle.js"])
                elif 'css' in dir_name or 'style' in dir_name:
                    new_paths.extend([f"{dir_path}/style.css", f"{dir_path}/main.css", f"{dir_path}/theme.css"])
                elif 'vendor' in dir_name:
                    new_paths.extend([f"{dir_path}/composer.json", f"{dir_path}/package.json"])
                else:
                    new_paths.extend([
                        f"{dir_path}/index.php", f"{dir_path}/index.html",
                        f"{dir_path}/src", f"{dir_path}/lib", f"{dir_path}/inc"
                    ])
                
                added = 0
                for new_path in new_paths:
                    full_url = f"{base}/{new_path}"
                    if full_url not in seen:
                        target_queue.put(new_path)
                        seen.add(full_url)
                        added += 1
                
                if added > 0 and not args.ci:
                    with print_lock:
                        print(f"{Colors.CYAN}[AUTO-RECURSE] Added {added} paths inside directory: /{dir_path}{Colors.END}")
                    
                    if stats:
                        stats['auto_recurse_paths'] = stats.get('auto_recurse_paths', 0) + added

        if recursion_manager and recursion_manager.max_depth > 0:
            if status in [200, 301, 302] and 'text/html' in response.headers.get('content-type', ''):
                new_links = recursion_manager.extract_links_from_html(response.text, target_url)
        
                if new_links and target_queue:
                    added_count = recursion_manager.process_discovered_links(
                        new_links, target_queue, current_depth
                    )
                    if added_count > 0:
                        print(f"{Colors.CYAN}[RECURSION] Depth {current_depth+1}: Added {added_count} paths from {word}{Colors.END}")

        # SAVE FOR PWDOC JSON 
        if pwndoc_findings is not None and status not in ignore_codes:
            
            finding = {
                'url': f"{target_url.rstrip('/')}/{word}",
                'path': f"/{word}",
                'status': status,
                'size': len(response.content),
                'timestamp': datetime.now().isoformat()
            }
            
            if is_interesting:
                finding['category'] = category
                finding['confidence'] = confidence
                finding['marker'] = "🔥" if confidence == "HIGH" else "⚡"
            
            pwndoc_findings['findings'].append(finding)

    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.TooManyRedirects):
        return
    except Exception:
        return

def export_pwndoc_json(pwndoc_findings, output_file=None):
    """Export results in Pwndoc JSON format"""  
    # Format for Pwndoc
    pwndoc_output = {
        'name': f"hellFuzzer Scan - {pwndoc_findings['scan_info']['target']}",
        'scope': [pwndoc_findings['scan_info']['target']],
        'createdAt': datetime.now().isoformat(),
        'startDate': pwndoc_findings['scan_info']['timestamp'],
        'endDate': datetime.now().isoformat(),
        'findings': []
    }
    
    # Convert findings to Pwndoc format
    for finding in pwndoc_findings['findings']:
        severity = "info"
        if finding.get('category') in ['ADMIN', 'CREDENTIALS', 'CONFIG']:
            severity = "medium" if finding['status'] in [200, 301, 302] else "info"
        
        pwndoc_finding = {
            'name': f"Discovered {finding['path']}",
            'description': f"Path {finding['path']} returned status {finding['status']}",
            'severity': severity,
            'references': [finding['url']],
            'status': "open"
        }
        
        if finding.get('category'):
            pwndoc_finding['description'] += f" - Categorized as {finding['category']} ({finding.get('confidence', 'UNKNOWN')})"
        
        pwndoc_output['findings'].append(pwndoc_finding)
    
    # Save file
    if not output_file:
        output_file = f"hellfuzzer_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(output_file, 'w') as f:
        json.dump(pwndoc_output, f, indent=2)
    
    print(f"{Colors.GREEN}[JSON] Results exported to {output_file}{Colors.END}")
    return output_file

def show_summary(stats, total_time, args):
    """Show statistics summary table"""
    print(f"\n{Colors.MAGENTA}{'='*60}{Colors.END}")
    print(f"{Colors.MAGENTA}                  SCAN SUMMARY{Colors.END}")
    if args.spa and stats.get('spa_js_paths'):
        print(f"{Colors.CYAN}[SPA] New JS routes added: {stats['spa_js_paths']}{Colors.END}")
    print(f"{Colors.MAGENTA}{'='*60}{Colors.END}")
    
    print(f"{Colors.CYAN}Total Requests:{Colors.END} {stats['total_requests']}")
    print(f"{Colors.CYAN}Total Time:{Colors.END} {total_time:.2f}s")
    print(f"{Colors.CYAN}Requests/sec:{Colors.END} {stats['total_requests']/total_time:.1f}")
    if args.spa and stats.get('spa_js_paths'):
        print(f"  {Colors.CYAN}SPA JS routes added: {stats['spa_js_paths']}{Colors.END}")
    print(f"\n{Colors.CYAN}Status Codes:{Colors.END}")
    for code, count in sorted(stats['status_codes'].items()):
        color = Colors.GREEN if code == 200 else Colors.YELLOW if code in [301, 302] else Colors.BLUE
        print(f"  {color}{code}: {count}{Colors.END}")
    
    # Interesting finds
    if stats['interesting_finds']:
        print(f"\n{Colors.CYAN}Interesting Finds:{Colors.END}")
        for category, count in sorted(stats['interesting_finds'].items()):
            print(f"  {Colors.ORANGE}{category}: {count}{Colors.END}")
    
    # Recursion
    if stats.get('recursion_discovered', 0) > 0:
        print(f"\n{Colors.CYAN}Recursion Discovered:{Colors.END} {stats['recursion_discovered']} paths")
        
    # Auto-recursion
    if stats.get('auto_recurse_paths', 0) > 0:
        print(f"\n{Colors.CYAN}Auto-recursion:{Colors.END} {stats['auto_recurse_paths']} paths discovered")
        
    # Word mining
    if stats.get('mined_words', 0) > 0:
        print(f"\n{Colors.GREEN}Word mining:{Colors.END} {stats['mined_words']} words discovered")    
    # Auto-filter
    if stats.get('filtered_responses', 0) > 0:
        print(f"\n{Colors.BLUE}Auto-filter:{Colors.END} {stats['filtered_responses']} responses filtered")
        
    print(f"{Colors.MAGENTA}{'='*60}{Colors.END}")

def worker(target_url, target_queue, session, timeout, args, ignore_codes=None, delay=0, recursion_manager=None, auto_filter=None, stats=None, pwndoc_findings=None):
    """
    Function executed by each thread - WITH AUTHENTICATED SESSION AND RECURSION
    """
    while True:
        try:
            target = target_queue.get_nowait()
            
            current_depth = 0
            if recursion_manager and hasattr(target, 'depth'):
                current_depth = target.depth
                target_word = target.path
            else:
                target_word = target
            
            full_url = f"{target_url.rstrip('/')}/{target_word}"
            if not args.scope_lock or is_in_scope(full_url, args.scope_lock):
                check_endpoint(target_url, target_word, session, timeout, args, ignore_codes, recursion_manager, auto_filter, current_depth, target_queue, stats, pwndoc_findings)
                
                if delay > 0:
                    time.sleep(delay)
            else:
                pass
                
            target_queue.task_done()
        except queue.Empty:
            break

def signal_handler(sig, frame):
    """Handle Ctrl+C for graceful exit"""
    print(f"\n{Colors.RED}[!] Interrupt received. Closing threads...{Colors.END}")
    sys.exit(0)

def main():
    show_banner()
    
    parser = ArgumentParser(description='hellFuzzer - Web directory fuzzer for pentesting')
    parser.add_argument('url', help='Target URL (e.g., http://example.com or https://target.com)')
    parser.add_argument('wordlist', help='Path to wordlist file')
    parser.add_argument('--spa', action='store_true', help='Download JS and extract routes to the queue')
    parser.add_argument('-t', '--threads', type=int, default=30, 
                       help='Number of threads (default: 30)')
    parser.add_argument('--proxy', help='Proxy URL: socks5://127.0.0.1:9050  or  http://127.0.0.1:8080', default=None)
    parser.add_argument('--timeout', type=int, default=3, help='Timeout per request (seconds)')
    parser.add_argument('--ok-codes', default='200-299', help='Status codes counted as hit (e.g. 200,301-302,401)')
    parser.add_argument('--hide-codes', default='404', help='Hide these status codes (e.g. 404,500)')
    parser.add_argument('-c', '--cookies', help='Session cookies (e.g., "session=abc123; user=admin")')
    parser.add_argument('--ssl-verify', action='store_true',
                       help='Verify SSL certificates (disabled by default)')
    parser.add_argument('-x', '--extensions', nargs='+', 
                       help='File extensions to try (e.g., php html txt)')
    parser.add_argument('--ignore-status', type=int, nargs='+', default=[],
                       help='Status codes to ignore (e.g., 403 404)')
    parser.add_argument('--show-interesting', action='store_true', default=True,
                       help='Highlight interesting findings (enabled by default)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (anti-rate limiting)')
    parser.add_argument('-f', '--file', help='File with multiple targets (one per line)')
   
    parser.add_argument('--auto-recurse', action='store_true', help='Auto-recursion: when finding directories, fuzz inside them automatically')
    parser.add_argument('--word-mine', action='store_true', help='Word mining: extract words from HTML/JS responses and add to fuzzing queue')
    parser.add_argument('--scope-lock', help='Scope lock: only fuzz within this domain (e.g., example.com)')
    parser.add_argument('--ci', action='store_true', help='CI mode: clean output for pipelines (only findings + JSON)')
    parser.add_argument('--auto-filter', action='store_true', help='Auto-filter: automatically ignore duplicate responses and error pages')
    parser.add_argument('--filter-aggressiveness', type=int, default=3, choices=[1, 2, 3, 4, 5], 
                       help='Auto-filter aggressiveness: 1=low (20+ reps), 3=medium (10+ reps), 5=high (5+ reps)')
 
    # AUTHENTICATION OPTIONS
    parser.add_argument('--auth-basic', help='Basic Authentication: user:password')
    parser.add_argument('--auth-jwt', help='JWT Token for Bearer authentication')
    parser.add_argument('--auth-oauth2', help='OAuth2 Token for Bearer authentication') 
    parser.add_argument('--auth-header', help='Custom auth header (e.g., "X-API-Key: value")')
    parser.add_argument('--depth', type=int, default=0, help='Recursion depth (0=no recursion)')
    parser.add_argument('--format', choices=['default', 'json'], default='default', help='Output format')
    args = parser.parse_args()
    
    stats = {
        'total_requests': 0,
        'status_codes': {},
        'interesting_finds': {},
        'recursion_discovered': 0,
        'auto_recurse_paths': 0,
        'mined_words': 0,
        'filtered_responses': 0,
        'start_time': time.time()
    }

    if not args.url and not args.file:
        print(f"{Colors.RED}[ERROR] You must specify either a target URL or a targets file with -f{Colors.END}")
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.file:
        print(f"{Colors.CYAN}[*] Multiple targets mode: {args.file}{Colors.END}")
        targets = load_targets_file(args.file)
        if not targets:
            sys.exit(1)
        print(f"{Colors.CYAN}[*] Loaded {len(targets)} valid targets{Colors.END}")
    else:

        is_valid, result = validate_url(args.url)
        if not is_valid:
            print(result)
            sys.exit(1)
        targets = [args.url]
    
    auth_manager = AuthManager(args)
    session = auth_manager.get_session()
    
    pwndoc_findings = {
        'scan_info': {
            'tool': 'hellFuzzer',
            'version': '1.2',
            'target': args.url,
            'timestamp': datetime.now().isoformat(),
            'wordlist': args.wordlist,
            'threads': args.threads
        },
        'findings': []
    }
    
    recursion_manager = RecursionManager(max_depth=args.depth)
    
    auto_filter = AutoFilter() if args.auto_filter else None
    
    if any([args.auth_basic, args.auth_jwt, args.auth_oauth2, args.auth_header]):
        auth_ok, auth_msg = auth_manager.test_auth(args.url)
        print(auth_msg)
        if not auth_ok and "401" in auth_msg:
            print(f"{Colors.YELLOW}Check your credentials/token{Colors.END}")
    
    try:
        import signal
        signal.signal(signal.SIGINT, signal_handler)
    except ImportError:
        pass
    
    cookies_dict = parse_cookies(args.cookies) if args.cookies else {}
    
    print(f"{Colors.CYAN}[*] Loading wordlist: {args.wordlist}{Colors.END}")
    words = load_wordlist(args.wordlist)
    if not words:
        sys.exit(1)

    common_entries = ['index.html', 'index.php', 'main.js', 'app.js', 'bundle.js', 'app.min.js']
    for ce in common_entries:
        if ce not in words:
            words.append(ce)

    all_targets = generate_all_targets(words, args.extensions)
    
    print(f"{Colors.CYAN}[*] Target: {args.url}{Colors.END}")
    print(f"{Colors.CYAN}[*] Threads: {args.threads}{Colors.END}")
    print(f"{Colors.CYAN}[*] Timeout: {args.timeout}s{Colors.END}")
    print(f"{Colors.CYAN}[*] Wordlist: {len(words)} base words{Colors.END}")
    
    if args.extensions:
        print(f"{Colors.CYAN}[*] Extensions: {', '.join(args.extensions)}{Colors.END}")
    
    if args.ignore_status:
        print(f"{Colors.CYAN}[*] Ignoring status: {', '.join(map(str, args.ignore_status))}{Colors.END}")
    
    print(f"{Colors.CYAN}[*] Interesting content detection: ENABLED{Colors.END}")
    print(f"{Colors.CYAN}[*] Total requests: {len(all_targets)}{Colors.END}")
    print(f"{Colors.CYAN}[*] Starting...{Colors.END}")
    print("-" * 60)
    
    start_time = time.time()

    try:

        for target_url in targets:
            print(f"{Colors.MAGENTA}[*] Scanning: {target_url}{Colors.END}")

            target_stats = {
                'total_requests': 0,
                'status_codes': {},
                'interesting_finds': {},
                'recursion_discovered': 0
            }

            recursion_manager = RecursionManager(max_depth=args.depth)

            pwndoc_findings = {
                'scan_info': {
                    'tool': 'hellFuzzer',
                    'version': '1.2',
                    'target': target_url,
                    'timestamp': datetime.now().isoformat(),
                    'wordlist': args.wordlist,
                    'threads': args.threads
                },
                'findings': []
            }

            global seen
            seen = set()          
            if args.spa:
                try:
                    r_root = session.get(target_url.rstrip('/') + '/', timeout=args.timeout, allow_redirects=True)
                    if r_root.status_code == 200 and 'text/html' in r_root.headers.get('content-type',''):

                        script_srcs = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', r_root.text, re.IGNORECASE)
                        for s in script_srcs:
                            s_norm = s.lstrip('/')
                            if s_norm not in words:
                                words.append(s_norm)
                except Exception:
                    pass

            target_queue = queue.Queue()
            for target in all_targets:
                target_queue.put(target)

            threads = []
            for _ in range(args.threads):
                thread = threading.Thread(
                    target=worker,
                    args=(target_url, target_queue, session, args.timeout, args, args.ignore_status, args.delay, recursion_manager, auto_filter, target_stats, pwndoc_findings)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)

            initial_size = target_queue.qsize()
            if initial_size == 0:
                initial_size = 1
            last_update = time.time()

            while any(thread.is_alive() for thread in threads):
                remaining = target_queue.qsize()
                completed = initial_size - remaining

                if not args.ci and time.time() - last_update > 0.5:
                    progress = (completed / initial_size) * 100
                    rps = completed / (time.time() - start_time) if (time.time() - start_time) > 0 else 0
                    print(f"\r{Colors.CYAN}[*] Progress: {completed}/{initial_size} ({progress:.1f}%) | {rps:.1f} req/sec{Colors.END}",
                          end="", flush=True)
                    last_update = time.time()

                time.sleep(0.1)

            print()

            target_total_time = time.time() - start_time
            target_stats['total_requests'] = len(all_targets)
            show_summary(target_stats, target_total_time, args)

            if args.format == 'json':
                safe_target = target_url.replace('://', '_').replace('/', '_').replace(':', '_')
                output_file = f"hellfuzzer_scan_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                export_pwndoc_json(pwndoc_findings, output_file)

            print(f"{Colors.CYAN}{'='*60}{Colors.END}")

    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.END}")

    if len(targets) > 1:
        total_time = time.time() - start_time
        print(f"{Colors.MAGENTA}[*] All targets completed in {total_time:.2f} seconds{Colors.END}")

if __name__ == "__main__":
    main()