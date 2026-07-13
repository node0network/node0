import sqlite3, sys
dst = sys.argv[1]
src = sqlite3.connect("/opt/node0/mesh.db")
out = sqlite3.connect(dst)
with out:
    src.backup(out)
out.close()
src.close()
print("DB-Snapshot erstellt:", dst)
