"""
Database migration script for HellSuite.
Run this after cloning to ensure database schema is up-to-date.
"""
import sqlite3
import os

def run_migrations():
    db_path = os.path.join(os.path.dirname(__file__), 'hellSsus.db')
    
    if not os.path.exists(db_path):
        print("Database not found. Run init_database.py first.")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    migrations = [
        # Migration 1: Add created_date to projects if missing
        """
        ALTER TABLE projects ADD COLUMN created_date DATETIME DEFAULT CURRENT_TIMESTAMP
        """,
        
        # Migration 2: Add role column to users if missing  
        """
        ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'viewer'
        """
    ]
    
    for i, migration in enumerate(migrations, 1):
        try:
            cursor.execute(migration)
            print(f"✅ Migration {i} applied successfully")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print(f"⚠️  Migration {i} already applied: {e}")
            else:
                print(f"❌ Migration {i} failed: {e}")
    
    conn.commit()
    conn.close()
    print("\n✅ All migrations completed")

if __name__ == "__main__":
    run_migrations()