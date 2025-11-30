-- HellSsus Database Schema for SQLite
-- Simple, file-based database for rapid prototyping

-- PROJECTS table
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active'
);

-- ASSETS table (what HellRecon finds)
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id),
    url TEXT NOT NULL,
    ip TEXT,
    technologies TEXT, -- JSON string
    open_ports TEXT, -- JSON string
    discovery_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ENDPOINTS table (what HellFuzzer finds)  
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER REFERENCES assets(id),
    path TEXT NOT NULL,
    status_code INTEGER,
    method TEXT,
    discovered_by TEXT, -- 'hellfuzzer' or 'hellrecon'
    content TEXT,
    discovery_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- VULNERABILITIES table (what HellScanner finds)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER REFERENCES assets(id),
    type TEXT, -- 'sql_injection', 'xss', 'missing_headers'
    severity TEXT, -- 'critical', 'high', 'medium', 'low'
    title TEXT,
    description TEXT,
    cve TEXT,
    cvss_score REAL,
    proof_of_concept TEXT,
    recommendation TEXT,
    discovery_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- USERS table for authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin user
INSERT OR IGNORE INTO users (username, password_hash) 
VALUES ('admin', 'pbkdf2:sha256:260000$8b6W1tE7Q3j2X9vL$...');