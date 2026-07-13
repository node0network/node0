import sqlite3
import hashlib
import json

def run():
    conn = sqlite3.connect('/opt/node0/mesh.db')
    agents = conn.execute("SELECT public_key, name, capabilities FROM agents").fetchall()
    
    prefixes = ["arc", "vel", "syn", "nex", "ori", "zep", "axo", "fen"]
    suffixes = ["ion", "ara", "eon", "yx", "an", "is", "or", "en"]
    
    for pk, name, caps in agents:
        if name == 'admin-node0':
            print("admin-node0 -> unchanged")
            continue
            
        # caps is a JSON string in DB, parse to list for correct string representation
        c = json.loads(caps)
        password = f"{pk}{c}".encode("utf-8")
        base = hashlib.sha256(password).hexdigest()[:8]
        p = int(base[:4], 16) % len(prefixes)
        s = int(base[4:], 16) % len(suffixes)
        new_name = f"{prefixes[p]}{suffixes[s]}-{base}"
        print(f"Old: {name} -> New: {new_name}")

if __name__ == '__main__':
    run()
