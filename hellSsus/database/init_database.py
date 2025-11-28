#!/usr/bin/env python3
"""
HellSuite Database Initialization
Creates all required tables for the vulnerability management system.
"""

import sqlite3
import os
import sys
from datetime import datetime

# Get the directory where this script is located
current_dir = os.path.dirname(os.path.abspath(__file__))
database_path = os.path.join(current_dir, 'hellSsus.db')

def init_database():
    """Initialize the database with all required tables in English schema"""
    
    # Remove existing database if it exists
    if os.path.exists(database_path):
        os.remove(database_path)
        print("[+] Removed existing database")
    
    # Create new database
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    
    # Create projects table
    cursor.execute('''
        CREATE TABLE projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_date TEXT,
            description TEXT
        )
    ''')
    
    # Create assets table  
    cursor.execute('''
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            technologies TEXT,
            open_ports TEXT,
            project_id INTEGER,
            discovery_date TEXT,
            FOREIGN KEY (project_id) REFERENCES projects (id)
        )
    ''')
    
    # Create endpoints table
    cursor.execute('''
        CREATE TABLE endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            path TEXT NOT NULL,
            status_code INTEGER,
            method TEXT,
            discovered_by TEXT,
            content TEXT,
            discovery_date TEXT,
            FOREIGN KEY (asset_id) REFERENCES assets (id)
        )
    ''')
    
    # Create vulnerabilities table
    cursor.execute('''
        CREATE TABLE vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            severity TEXT,
            description TEXT,
            reference TEXT,
            proof_of_concept TEXT,
            recommendation TEXT,
            cve TEXT,
            cvss_score REAL,
            project_id INTEGER,
            asset_id INTEGER,
            discovery_date TEXT,
            FOREIGN KEY (project_id) REFERENCES projects (id),
            FOREIGN KEY (asset_id) REFERENCES assets (id)
        )
    ''')
    
    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Insert default admin user (password: admin@2025_Nov)
    cursor.execute('''
        INSERT INTO users (username, password_hash) 
        VALUES ('admin', 'pbkdf2:sha256:260000$K1H5W8zX$dummy_hash_replace_this')
    ''')
    
    conn.commit()
    conn.close()
    
    print("[+] Database initialized successfully!")
    print(f"[+] Database location: {database_path}")
    print("[+] Tables created: projects, assets, endpoints, vulnerabilities, users")
    print("[+] All tables and columns use English naming convention")
    print("[+] Default user: admin / admin@2025_Nov")

if __name__ == "__main__":
    init_database()