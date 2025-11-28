-- HellSsus Database Schema for SQLite
-- Simple, file-based database for rapid prototyping

-- PROJECTS table
CREATE TABLE IF NOT EXISTS proyectos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    descripcion TEXT,
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    estado TEXT DEFAULT 'activo'
);

-- ASSETS table (what HellRecon finds)
CREATE TABLE IF NOT EXISTS activos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER REFERENCES proyectos(id),
    url TEXT NOT NULL,
    ip TEXT,
    tecnologias TEXT, -- JSON string
    puertos_abiertos TEXT, -- JSON string
    fecha_descubrimiento DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ENDPOINTS table (what HellFuzzer finds)  
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activo_id INTEGER REFERENCES activos(id),
    ruta TEXT NOT NULL,
    codigo_estado INTEGER,
    metodo TEXT,
    descubierto_por TEXT, -- 'hellfuzzer' or 'hellrecon'
    contenido TEXT,
    fecha_descubrimiento DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- SECRETS table (your new awesome feature)
CREATE TABLE IF NOT EXISTS secretos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activo_id INTEGER REFERENCES activos(id),
    tipo TEXT, -- 'aws_key', 'github_token', 'slack_webhook'
    ubicacion TEXT, -- 'https://target.com/app.js:line_245'
    confianza INTEGER, -- 1-100
    verificado BOOLEAN DEFAULT FALSE,
    redactado TEXT, -- 'AKIA***************'
    fecha_descubrimiento DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- VULNERABILITIES table (for future HellScanner)
CREATE TABLE IF NOT EXISTS vulnerabilidades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activo_id INTEGER REFERENCES activos(id),
    tipo TEXT, -- 'sql_injection', 'xss'
    cve TEXT,
    cvss_score REAL,
    explotable BOOLEAN DEFAULT FALSE,
    ubicacion TEXT,
    fecha_descubrimiento DATETIME DEFAULT CURRENT_TIMESTAMP
);