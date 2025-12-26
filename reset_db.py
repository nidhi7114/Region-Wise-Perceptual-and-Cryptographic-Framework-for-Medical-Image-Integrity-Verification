import sqlite3
import os

DB_FILE = "db.sqlite3"

# Delete old DB if exists
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)
    print("Old database deleted ✅")

# Create new DB with updated schema
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        original_filename TEXT,
        phash TEXT,
        region_hashes TEXT,
        signature BLOB
    )
''')

conn.commit()
conn.close()

print("New database created with updated schema ✅")
