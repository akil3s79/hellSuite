# diagnostico_secrets.py
import sqlite3

conn = sqlite3.connect('database/hellSsus.db')
cursor = conn.cursor()

# Ver tablas de secrets
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%secret%'")
tablas_secrets = cursor.fetchall()
print('Tablas de secrets:', tablas_secrets)

# Ver estructura de assets
cursor.execute('PRAGMA table_info(assets)')
columnas_assets = cursor.fetchall()
print('\nColumnas de assets:')
for col in columnas_assets:
    print(f'  - {col[1]}')

# Ver de dónde sale el contador de secrets
cursor.execute('SELECT COUNT(*) FROM assets WHERE secrets IS NOT NULL')
count_secrets = cursor.fetchone()[0]
print(f'\nSecrets en assets: {count_secrets}')

# Ver todos los nombres de tablas por si acaso
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
todas_tablas = cursor.fetchall()
print('\nTodas las tablas:')
for tabla in todas_tablas:
    print(f'  - {tabla[0]}')

conn.close()
