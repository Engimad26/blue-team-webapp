import sqlite3

conn = sqlite3.connect("data/blue_team.db")

cur = conn.cursor()

for row in cur.execute("SELECT * FROM alerts"):
    print(row)

conn.close()