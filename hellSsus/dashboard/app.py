"""
HellSsus Dashboard - Simple Flask UI
"""
import os
import sys
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
from passlib.hash import pbkdf2_sha256
import sqlite3
import json
import io
from functools import wraps
from datetime import datetime

# Add parent directory to path for config import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from config.logging_config import dashboard_logger, setup_application_logging

# Load environment variables WITHOUT dotenv first
import os
from pathlib import Path

# Search .env in project root
project_root = Path(__file__).parent.parent.parent  
env_path = project_root / '.env'

if env_path.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
        dashboard_logger.info(f".env loaded from: {env_path}")
    except ImportError:
        print("[WARNING] python-dotenv not installed, using os.environ")
else:
    print(f"[WARNING] .env file not found at: {env_path}")
    print("[INIT] Using default configuration")

# Initialize Flask app
app = Flask(__name__)

DEFAULT_SECRET = 'default-secret-key-CHANGE-THIS-IN-PRODUCTION-123'

secret_key = os.getenv('HELLSUITE_SECRET_KEY', DEFAULT_SECRET)
debug_str = os.getenv('HELLSUITE_DEBUG', 'False')
allow_register_str = os.getenv('HELLSUITE_ALLOW_REGISTER', 'False')

# APP config
app.secret_key = secret_key
app.config['DEBUG'] = debug_str.lower() == 'true'
app.config['ALLOW_REGISTER'] = allow_register_str.lower() == 'true'

if app.config['DEBUG']:
    print(f"[DEBUG] Registration enabled: {app.config['ALLOW_REGISTER']}")

# ============================================================================
# TEMPLATE CONTEXT PROCESSORS
# ============================================================================

@app.context_processor
def inject_config():
    """Inject configuration variables into all templates"""
    return {
        'allow_register': app.config['ALLOW_REGISTER'],
        'debug_mode': app.config['DEBUG']
    }

try:
    from hellconfig import DATABASE_PATH
    dashboard_logger.debug(f"Database path: {DATABASE_PATH}")
except ImportError:
    dashboard_logger.warning("config.py not found or DATABASE_PATH not defined")

def get_db_connection():
    """Connect to SQLite database"""
    # Go up one level from the dashboard and enter the database.
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, 'database', 'hellSsus.db')
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_users_table():
    """Create users table if it doesn't exist"""
    conn = get_db_connection()
    
    try:
        # Check if role column exists, add it if not
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'role' not in columns:
            dashboard_logger.info("Adding 'role' column to users table")
            try:
                conn.execute('ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT "viewer"')
                conn.commit()
                print("[+] Role column added successfully")
            except Exception as e:
                dashboard_logger.error(f"Error adding role column: {e}", exc_info=True)
        
        # Create table if it doesn't exist
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) DEFAULT 'viewer',
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Ensure admin user has admin role
        admin_user = conn.execute(
            'SELECT * FROM users WHERE username = ?', ('admin',)
        ).fetchone()
        
        # CORREGIDO: Usar acceso por índice, no .get()
        if admin_user:
            # Convert Row to dict para acceso seguro
            admin_dict = dict(admin_user)
            if admin_dict.get('role') != 'admin':
                conn.execute(
                    'UPDATE users SET role = ? WHERE username = ?',
                    ('admin', 'admin')
                )
                print("[*] Updated admin user role to 'admin'")
        
        conn.commit()
        
    except Exception as e:
        print(f"[!] Error in init_users_table: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

def hash_password(password):
    """Hash password using pbkdf2_sha256"""
    return pbkdf2_sha256.hash(password)

def check_password(password, hashed):
    """Check password against hash"""
    return pbkdf2_sha256.verify(password, hashed)
    
def get_user_by_username(username):
    """Get user by username"""
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()
    conn.close()
    return user

def create_default_user():
    """Create default admin user if no users exist"""
    conn = get_db_connection()
    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    conn.close()
    
    if user_count == 0:
        default_password = os.getenv('HELLSUITE_DEFAULT_PASS', 'admin@2025_Nov')
        conn = get_db_connection()
        password_hash = hash_password(default_password)
        conn.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('admin', password_hash, 'admin')
        )
        conn.commit()
        conn.close()
        print(f"[+] Default admin user created: admin / {default_password} (role: admin)")
        print("[!] Change default password in production!")
    else:
        dashboard_logger.info(f"Users already exist: {user_count} users")

# ============================================================================
# ROLE-BASED ACCESS CONTROL SYSTEM
# ============================================================================

def role_required(required_role='viewer'):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Check session
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            # 2. Get current user with role
            conn = get_db_connection()
            user = conn.execute(
                'SELECT username, role FROM users WHERE id = ?',
                (session['user_id'],)
            ).fetchone()
            conn.close()
            
            # 3. If user doesn't exist, clear session
            if not user:
                session.clear()
                return redirect(url_for('login'))
            
            # 4. Role hierarchy check
            role_hierarchy = {'viewer': 1, 'analyst': 2, 'admin': 3}
            user_level = role_hierarchy.get(user['role'], 0)
            required_level = role_hierarchy.get(required_role, 0)
            
            # 5. Permission check
            if user_level < required_level:
                print(f"[SECURITY] Access denied: {user['username']} ({user['role']}) tried to access {request.path} (required: {required_role})")
                return render_template('error.html', 
                    error="Access denied",
                    details=f"Your role '{user['role']}' doesn't have permission for this action"
                ), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Backward compatibility decorator
def login_required(f):
    """Login decorator (alias for viewer role)"""
    return role_required('viewer')(f)

# ============================================================================
# USER REGISTRATION (DEBUG MODE ONLY)
# ============================================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    # Use app configuration
    if not app.config['ALLOW_REGISTER']:
        return "Registration disabled. Set HELLSUITE_ALLOW_REGISTER=True in .env file", 403
    
    if request.method == 'POST':
        username = request.form.get('username', '')[:50]
        password = request.form.get('password', '')[:100]
        role = request.form.get('role', 'viewer')
        
        if not username or not password:
            return render_template('register.html', error='Username and password required')
        
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters')
        
        # Validate role
        if role not in ['viewer', 'analyst', 'admin']:
            role = 'viewer'
        
        conn = get_db_connection()
        
        # Check if user exists
        existing = conn.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()
        
        if existing:
            conn.close()
            return render_template('register.html', error='Username already exists')
        
        # Create user
        password_hash = hash_password(password)
        conn.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (username, password_hash, role)
        )
        conn.commit()
        conn.close()
        
        print(f"[+] User created: {username} (role: {role})")
        return redirect(url_for('login'))
    
    # GET request - show registration form
    return render_template('register.html')

# ============================================================================
# APPLICATION ROUTES WITH ROLE-BASED PERMISSIONS
# ============================================================================

@app.route('/')
@role_required('viewer')
def index():
    """Main dashboard page - accessible to all authenticated users"""
    conn = get_db_connection()
    
    projects_count = conn.execute('SELECT COUNT(*) FROM projects').fetchone()[0]
    assets_count = conn.execute('SELECT COUNT(*) FROM assets').fetchone()[0]
    vulnerabilities_count = conn.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
    endpoints_count = conn.execute('SELECT COUNT(*) FROM endpoints').fetchone()[0]
    
    recent_projects = conn.execute(
        'SELECT id, name, created_date FROM projects ORDER BY created_date DESC LIMIT 5'
    ).fetchall()
    
    conn.close()
    
    return render_template('index.html', 
                         projects_count=projects_count,
                         assets_count=assets_count, 
                         endpoints_count=endpoints_count, 
                         vulnerabilities_count=vulnerabilities_count,
                         recent_projects=recent_projects)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '')[:50]
        password = request.form.get('password', '')[:100]
        
        if not username or not password:
            return render_template('login.html', error='Username and password required')
        
        user = get_user_by_username(username)
        if user and check_password(password, user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/projects')
@role_required('analyst')  # Only analysts and admins
def projects():
    """Projects list page"""
    conn = get_db_connection()
    projects = conn.execute(
        'SELECT * FROM projects ORDER BY created_date DESC'
    ).fetchall()
    conn.close()
    return render_template('projects.html', projects=projects)

@app.route('/assets')
@role_required('analyst')  # Only analysts and admins
def assets():
    """Assets list page - filter by project if specified"""
    project_id = request.args.get('project', type=int)
    
    conn = get_db_connection()
    
    if project_id:
        assets = conn.execute('''
            SELECT a.id, a.url, a.discovery_date, p.name as project_name 
            FROM assets a 
            LEFT JOIN projects p ON a.project_id = p.id 
            WHERE a.project_id = ?
            ORDER BY a.discovery_date DESC
        ''', (project_id,)).fetchall()
    else:
        assets = conn.execute('''
            SELECT a.id, a.url, a.discovery_date, p.name as project_name 
            FROM assets a 
            LEFT JOIN projects p ON a.project_id = p.id 
            ORDER BY a.discovery_date DESC
        ''').fetchall()
    
    conn.close()
    
    project_name = None
    if project_id:
        conn = get_db_connection()
        project = conn.execute('SELECT name FROM projects WHERE id = ?', (project_id,)).fetchone()
        conn.close()
        project_name = project['name'] if project else f"Project {project_id}"
    
    return render_template('assets.html', assets=assets, project_name=project_name, project_id=project_id)

@app.route('/vulnerabilities')
@role_required('analyst')  # Only analysts and admins
def vulnerabilities():
    """Vulnerabilities list page - filter by project if specified"""
    project_id = request.args.get('project', type=int)
    
    conn = get_db_connection()
    
    if project_id:
        vulnerabilities = conn.execute('''
            SELECT v.*, a.url as asset_url, p.name as project_name 
            FROM vulnerabilities v 
            LEFT JOIN assets a ON v.asset_id = a.id 
            LEFT JOIN projects p ON v.project_id = p.id 
            WHERE v.project_id = ?
            ORDER BY 
                CASE v.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                v.discovery_date DESC
        ''', (project_id,)).fetchall()
    else:
        vulnerabilities = conn.execute('''
            SELECT v.*, a.url as asset_url, p.name as project_name 
            FROM vulnerabilities v 
            LEFT JOIN assets a ON v.asset_id = a.id 
            LEFT JOIN projects p ON v.project_id = p.id 
            ORDER BY 
                CASE v.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                v.discovery_date DESC
        ''').fetchall()
    
    conn.close()
    project_name = None
    if project_id:
        conn = get_db_connection()
        project = conn.execute('SELECT name FROM projects WHERE id = ?', (project_id,)).fetchone()
        conn.close()
        project_name = project['name'] if project else f"Project {project_id}"
    
    return render_template('vulnerabilities.html', 
                         vulnerabilities=vulnerabilities, 
                         project_name=project_name, 
                         project_id=project_id)

@app.route('/api/stats')
@role_required('viewer')  # All authenticated users
def api_stats():
    """JSON API endpoint for dashboard stats"""
    conn = get_db_connection()
    
    stats = {
        'projects': conn.execute('SELECT COUNT(*) FROM projects').fetchone()[0],
        'assets': conn.execute('SELECT COUNT(*) FROM assets').fetchone()[0],
        'endpoints': conn.execute('SELECT COUNT(*) FROM endpoints').fetchone()[0],
        'vulnerabilities': conn.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
    }
    
    conn.close()
    return jsonify(stats)

@app.route('/asset/<int:asset_id>')
@role_required('analyst')  # Only analysts and admins
def asset_detail(asset_id):
    """Asset details page with all findings"""
    conn = get_db_connection()
    
    # Get basic asset info
    asset = conn.execute(
        'SELECT * FROM assets WHERE id = ?', (asset_id,)
    ).fetchone()
    
    if not asset:
        conn.close()
        return "Asset not found", 404
    
    # Get endpoints from HellFuzzer
    endpoints = conn.execute(
        'SELECT * FROM endpoints WHERE asset_id = ? ORDER BY path', (asset_id,)
    ).fetchall()
    
    # Get project name
    project = conn.execute(
        'SELECT name FROM projects WHERE id = ?', (asset['project_id'],)
    ).fetchone()
    
    conn.close()
    
    # Parse open ports JSON
    open_ports = []
    if asset['open_ports']:
        try:
            open_ports = json.loads(asset['open_ports'])
        except:
            open_ports = []
    
    # Parse technologies JSON
    technologies = []
    if asset['technologies']:
        try:
            technologies = json.loads(asset['technologies'])
        except:
            technologies = []

    return render_template('asset_detail.html', 
                         asset=asset,
                         endpoints=endpoints,
                         technologies=technologies,
                         open_ports=open_ports,
                         project_name=project['name'] if project else 'Unknown')

@app.route('/project/<int:project_id>/report')
@role_required('viewer')  # All authenticated users
def project_report(project_id):
    """Generate HTML report with unified dashboard design"""
    try:
        conn = get_db_connection()
        
        # Get project details
        project = conn.execute(
            'SELECT * FROM projects WHERE id = ?', (project_id,)
        ).fetchone()
        
        if not project:
            return "Project not found", 404
        
        # Get vulnerabilities count by severity
        severity_rows = conn.execute('''
            SELECT severity, COUNT(*) as count 
            FROM vulnerabilities 
            WHERE project_id = ? 
            GROUP BY severity
        ''', (project_id,)).fetchall()
        
        # Convert to dict for easy access
        severity_counts = {}
        for row in severity_rows:
            severity_counts[row['severity']] = row['count']
        
        # Get critical vulnerabilities for executive summary
        critical_vulns = conn.execute('''
            SELECT * FROM vulnerabilities 
            WHERE project_id = ? AND severity = 'critical'
            ORDER BY cvss_score DESC
            LIMIT 5
        ''', (project_id,)).fetchall()
        
        # Get all vulnerabilities with asset info
        vulnerabilities = conn.execute('''
            SELECT v.*, a.url as asset_url 
            FROM vulnerabilities v 
            LEFT JOIN assets a ON v.asset_id = a.id 
            WHERE v.project_id = ? 
            ORDER BY 
                CASE v.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                v.cvss_score DESC
        ''', (project_id,)).fetchall()
        
        conn.close()
        
        return render_template('report_html.html',
            project=project,
            current_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            severity_counts=severity_counts,
            critical_vulns=critical_vulns,
            vulnerabilities=vulnerabilities,
            project_id=project_id
        )
        
    except Exception as e:
        print(f"[!] Error generating HTML report: {e}")
        import traceback
        traceback.print_exc()
        return f"Error generating report: {str(e)}", 500

@app.route('/project/<int:project_id>/report/pdf')
@role_required('viewer')  # All authenticated users
def export_pdf(project_id):
    """Export PDF using dedicated PDF template"""
    try:
        from playwright.sync_api import sync_playwright
        
        pdf_html = generate_pdf_html(project_id)
        
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.set_content(pdf_html)
            pdf = page.pdf(
                format='A4',
                print_background=True,
                margin={'top': '1cm', 'right': '1cm', 'bottom': '1cm', 'left': '1cm'},
                prefer_css_page_size=True,
                scale=0.9
            )
            browser.close()
            
        return send_file(
            io.BytesIO(pdf),
            as_attachment=True,
            download_name=f"hellsuite_report_{project_id}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"[!] PDF export error: {e}")
        return "Error generating PDF", 500

@app.route('/endpoints')
@role_required('analyst')  # Only analysts and admins
def endpoints():
    """Endpoints management page"""
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    
    endpoints_data = conn.execute('''
        SELECT 
            e.id,
            e.method,
            e.path,
            e.status_code,
            e.asset_id,
            a.url as asset_url,
            p.name as project_name
        FROM endpoints e
        LEFT JOIN assets a ON e.asset_id = a.id
        LEFT JOIN projects p ON a.project_id = p.id
        ORDER BY e.id DESC
    ''').fetchall()
    
    conn.close()
    
    return render_template('endpoints.html',
                         endpoints=endpoints_data,
                         page_title='Endpoints Management',
                         stats_summary=f'Found {len(endpoints_data)} endpoints across all projects')

@app.route('/reports')
@role_required('viewer')  # All authenticated users
def reports_list():
    """List all projects with report links"""
    conn = get_db_connection()
    projects = conn.execute(
        'SELECT * FROM projects ORDER BY created_date DESC'
    ).fetchall()
    conn.close()
    
    return render_template('reports_list.html', projects=projects)

@app.route('/project/<int:project_id>/report/json')
@role_required('analyst')  # Only analysts and admins (sensitive data)
def export_pwndoc_json(project_id):
    """Export project data in Pwndoc-compatible JSON format"""
    try:
        conn = get_db_connection()
        
        # Get project details
        project = conn.execute(
            'SELECT * FROM projects WHERE id = ?', (project_id,)
        ).fetchone()
        
        if not project:
            return "Project not found", 404
        
        # Get all vulnerabilities with asset info
        vulnerabilities = conn.execute('''
            SELECT v.*, a.url as asset_url 
            FROM vulnerabilities v 
            LEFT JOIN assets a ON v.asset_id = a.id 
            WHERE v.project_id = ? 
            ORDER BY 
                CASE v.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                v.cvss_score DESC
        ''', (project_id,)).fetchall()
        
        # Get assets for this project
        assets = conn.execute('''
            SELECT * FROM assets WHERE project_id = ?
        ''', (project_id,)).fetchall()
        
        # First, find out what columns the assets table actually has
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(assets)")
        asset_columns = [col[1] for col in cursor.fetchall()]  # Column names
        
        print(f"[DEBUG] Columns in assets table: {asset_columns}")
        
        conn.close()
        
        # Transform to Pwndoc format
        pwndoc_data = {
            "name": project['name'],
            "version": "1.0",
            "exported_from": "HellSuite v4.1",
            "export_date": datetime.now().isoformat(),
            "project": {
                "name": project['name'],
                "description": project['description'] if 'description' in project.keys() else "",
                "created_date": project['created_date']
            },
            "vulnerabilities": [],
            "assets": []
        }
        
        # Helper function to safely get value from sqlite3.Row
        def safe_get(row, key, default=""):
            """Safely get value from sqlite3.Row or return default"""
            try:
                return row[key] if row[key] is not None else default
            except (KeyError, IndexError):
                return default
        
        # Process vulnerabilities for Pwndoc
        for vuln in vulnerabilities:
            # Map severity to CVSS base score
            severity_to_cvss = {
                'critical': 9.0,
                'high': 7.0,
                'medium': 5.0,
                'low': 3.0
            }
            
            # Convert sqlite3.Row to dict for easier access
            vuln_dict = dict(vuln)
            
            pwndoc_vuln = {
                "name": vuln_dict.get('type', 'unknown').replace('_', ' ').title(),
                "category": "security",
                "severity": vuln_dict.get('severity', 'medium').upper(),
                "cvss_score": vuln_dict.get('cvss_score') or severity_to_cvss.get(vuln_dict.get('severity', 'medium'), 5.0),
                "description": vuln_dict.get('description', ''),
                "remediation": vuln_dict.get('recommendation', ''),
                "proof_of_concept": vuln_dict.get('proof_of_concept', ''),
                "affected_asset": vuln_dict.get('asset_url', 'N/A'),
                "discovery_date": (vuln_dict.get('discovery_date', '')[:10] 
                                  if vuln_dict.get('discovery_date') 
                                  else datetime.now().strftime("%Y-%m-%d")),
                "references": vuln_dict.get('reference', ''),
                "cve": vuln_dict.get('cve', '')
            }
            pwndoc_data["vulnerabilities"].append(pwndoc_vuln)
        
        # Process assets for Pwndoc
        for asset in assets:
            # Convert sqlite3.Row to dict
            asset_dict = dict(asset)
            
            # Parse JSON fields safely
            technologies = []
            open_ports = []
            
            tech_str = asset_dict.get('technologies', '[]')
            if tech_str:
                try:
                    technologies = json.loads(tech_str)
                except:
                    technologies = []
            
            ports_str = asset_dict.get('open_ports', '[]')
            if ports_str:
                try:
                    open_ports = json.loads(ports_str)
                except:
                    open_ports = []
            
            pwndoc_asset = {
                "url": asset_dict.get('url', ''),
                "ip": asset_dict.get('ip', ''),  # This won't fail even if column doesn't exist
                "discovery_date": (asset_dict.get('discovery_date', '')[:10] 
                                  if asset_dict.get('discovery_date') 
                                  else ''),
                "technologies": technologies,
                "open_ports": open_ports
            }
            pwndoc_data["assets"].append(pwndoc_asset)
        
        # Create JSON response
        response = jsonify(pwndoc_data)
        response.headers.set('Content-Disposition', 'attachment', filename=f'hellsuite_pwndoc_export_{project_id}.json')
        response.headers.set('Content-Type', 'application/json')
        
        return response
        
    except Exception as e:
        print(f"[!] Error generating Pwndoc JSON: {e}")
        import traceback
        traceback.print_exc()
        return f"Error generating Pwndoc export: {str(e)}", 500

def generate_pdf_html(project_id):
    """Generate PDF report using the new unified template"""
    try:
        conn = get_db_connection()
        
        # Get project details
        project = conn.execute(
            'SELECT * FROM projects WHERE id = ?', (project_id,)
        ).fetchone()
        
        if not project:
            return "<html><body>Project not found</body></html>"
        
        # Get vulnerabilities count by severity
        severity_rows = conn.execute('''
            SELECT severity, COUNT(*) as count 
            FROM vulnerabilities 
            WHERE project_id = ? 
            GROUP BY severity
        ''', (project_id,)).fetchall()
        
        # Convert to dict
        severity_counts = {}
        for row in severity_rows:
            severity_counts[row['severity']] = row['count']
        
        # Get critical vulnerabilities
        critical_vulns = conn.execute('''
            SELECT * FROM vulnerabilities 
            WHERE project_id = ? AND severity = 'critical'
            ORDER BY cvss_score DESC
            LIMIT 5
        ''', (project_id,)).fetchall()
        
        # Get all vulnerabilities with asset info
        vulnerabilities = conn.execute('''
            SELECT v.*, a.url as asset_url 
            FROM vulnerabilities v 
            LEFT JOIN assets a ON v.asset_id = a.id 
            WHERE v.project_id = ? 
            ORDER BY 
                CASE v.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                v.cvss_score DESC
        ''', (project_id,)).fetchall()
        
        conn.close()
        
        # Render the PDF-specific template
        return render_template('report_pdf.html',
            project=project,
            current_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            severity_counts=severity_counts,
            critical_vulns=critical_vulns,
            vulnerabilities=vulnerabilities,
            project_id=project_id
        )
        
    except Exception as e:
        print(f"[!] Error generating PDF HTML: {e}")
        import traceback
        traceback.print_exc()
        return f"<html><body>Error generating PDF: {str(e)}</body></html>"

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin/users')
@role_required('admin')  # Only admins
def manage_users():
    """User management (admin only)"""
    conn = get_db_connection()
    users = conn.execute(
        'SELECT id, username, role, created_date FROM users ORDER BY created_date DESC'
    ).fetchall()
    conn.close()
    
    return render_template('admin_users.html', users=users)

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error="Access denied"), 403

@app.errorhandler(500)
def internal_error(error):
    print(f"[!] Internal server error: {error}")
    return render_template('error.html', error="Internal server error"), 500

# ============================================================================
# APPLICATION INITIALIZATION
# ============================================================================

# Initialize database on startup
init_users_table()
create_default_user()

setup_application_logging()  # Initialize logging system
dashboard_logger.info("HellSsus Dashboard starting")
dashboard_logger.info(f"Access at: http://localhost:5000")

if app.config['DEBUG']:
    dashboard_logger.warning("DEBUG mode is ENABLED - Disable in production!")
    if app.config['ALLOW_REGISTER']:
        dashboard_logger.warning("User registration is ENABLED")

# ============================================================================
# APPLICATION INITIALIZATION
# ============================================================================

# Setup logging first
setup_application_logging()

# Initialize database on startup
init_users_table()
create_default_user()

dashboard_logger.info("HellSsus Dashboard starting")
dashboard_logger.info(f"Access at: http://localhost:5000")

if app.config['DEBUG']:
    dashboard_logger.warning("DEBUG mode is ENABLED - Disable in production!")
    if app.config['ALLOW_REGISTER']:
        dashboard_logger.warning("User registration is ENABLED")

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=5000)