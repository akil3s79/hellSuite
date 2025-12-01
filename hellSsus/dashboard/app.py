"""
HellSsus Dashboard - Simple Flask UI
"""
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
from passlib.hash import pbkdf2_sha256
import sqlite3
import os
import sys
import json
import io
from functools import wraps
from datetime import datetime

# Add parent directory to path for config import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATABASE_PATH

app = Flask(__name__)
app.secret_key = 'hellsus-super-secret-key-change-in-production'

def get_db_connection():
    # Go up one level from the dashboard and enter the database.
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, 'database', 'hellSsus.db')
    print(f"📁 CONNECTING TO: {db_path}")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_users_table():
    """Create users table if it doesn't exist"""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
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
        conn = get_db_connection()
        password_hash = hash_password('admin@2025_Nov')
        conn.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            ('admin', password_hash)
        )
        conn.commit()
        conn.close()
        print("[+] Default user created: admin / admin@2025_Nov")

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
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
@login_required
def projects():
    """Projects list page"""
    conn = get_db_connection()
    projects = conn.execute(
        'SELECT * FROM projects ORDER BY created_date DESC'
    ).fetchall()
    conn.close()
    return render_template('projects.html', projects=projects)

@app.route('/assets')
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
def project_report(project_id):  # MISMO NOMBRE que la ruta vieja
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

@app.route('/project/<int:project_id>/report/json')
@login_required
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
        
        # Primero, averiguar qué columnas tiene realmente la tabla assets
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(assets)")
        asset_columns = [col[1] for col in cursor.fetchall()]  # Nombre de columnas
        
        print(f"[DEBUG] Columnas en tabla assets: {asset_columns}")
        
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
                "ip": asset_dict.get('ip', ''),  # Esto ya no fallará aunque no exista
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

@app.route('/endpoints')
def endpoints():
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

@app.route('/project/<int:project_id>/report')
@login_required
def project_report_html(project_id):
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

@app.route('/reports')
@login_required
def reports_list():
    """List all projects with report links"""
    conn = get_db_connection()
    projects = conn.execute(
        'SELECT * FROM projects ORDER BY created_date DESC'
    ).fetchall()
    conn.close()
    
    return render_template('reports_list.html', projects=projects)

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

# Initialize database on startup
with app.app_context():
    init_users_table()
    create_default_user()

if __name__ == '__main__':
    print("[*] Starting HellSsus Dashboard...")
    print("[*] Access at: http://localhost:5000")
    print("[*] Default credentials: admin / admin@2025_Nov")
    print("[!] Change default password in production!")
    app.run(debug=True, host='0.0.0.0', port=5000)