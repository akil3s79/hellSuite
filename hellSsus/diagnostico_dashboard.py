# diagnostico_dashboard.py
from app import app
import sqlite3

with app.app_context():
    # Ver cómo se calculan los stats del dashboard
    conn = sqlite3.connect('database/hellSsus.db')
    cursor = conn.cursor()
    
    # Contar proyectos reales
    cursor.execute('SELECT COUNT(*) FROM projects')
    projects_count = cursor.fetchone()[0]
    
    # Contar assets reales  
    cursor.execute('SELECT COUNT(*) FROM assets')
    assets_count = cursor.fetchone()[0]
    
    # Contar vulnerabilidades reales
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    vulns_count = cursor.fetchone()[0]
    
    print(f'Proyectos reales: {projects_count}')
    print(f'Assets reales: {assets_count}') 
    print(f'Vulnerabilidades reales: {vulns_count}')
    print('Secrets reales: ??? (no existe tabla/columna)')
    
    conn.close()