import sqlite3

conn = sqlite3.connect("images.db")
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS images")
cursor.execute("""
CREATE TABLE images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    phash TEXT,
    region_hashes TEXT,
    signature TEXT
)
""")

conn.commit()
conn.close()
print("✅ Table ready with region_hashes")
