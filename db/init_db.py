import sqlite3
import os
from pathlib import Path

db_path = Path(__file__).parent / 'bot_detection.db'
schema_path = Path(__file__).parent / 'schema.sql'

def init_db():
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema = f.read()
    
    conn = sqlite3.connect(db_path)
    conn.executescript(schema)
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == '__main__':
    init_db()
