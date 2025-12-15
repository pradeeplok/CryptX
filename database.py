import sqlite3
import datetime

DB_NAME = "cryptx.db"

def init_db():
    """Initialize the database and create tables if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            code_snippet TEXT,
            detection TEXT,
            issues_count INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def save_analysis(code, detection, issues_count):
    """Save an analysis result to the database."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Store only the first 100 chars of code for preview
    code_snippet = code[:100] + "..." if len(code) > 100 else code
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    c.execute('''
        INSERT INTO history (timestamp, code_snippet, detection, issues_count)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, code_snippet, detection, issues_count))
    
    conn.commit()
    conn.close()

def get_history(limit=20):
    """Retrieve the latest analysis history."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # To access columns by name
    c = conn.cursor()
    c.execute('''
        SELECT * FROM history 
        ORDER BY id DESC 
        LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    
    # Convert rows to list of dicts
    history = []
    for row in rows:
        history.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "code_snippet": row["code_snippet"],
            "detection": row["detection"],
            "issues_count": row["issues_count"]
        })
    return history

def get_analysis(id):
    """Retrieve a single analysis record by ID."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM history WHERE id = ?', (id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "code_snippet": row["code_snippet"],
            "detection": row["detection"],
            "issues_count": row["issues_count"]
        }
    return None
