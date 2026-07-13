import os, sys, shutil, asyncio, json, base64, time, uuid
import sqlite3
from cryptography.hazmat.primitives.asymmetric import ed25519
import httpx

# Setze Test-Umgebungsvariablen
TEST_DB = "test_mesh.db"
os.environ["NODE0_DB_PATH"] = TEST_DB
# Setze leeren env Pfad, damit keine echten Anmeldedaten geladen werden
os.environ["NODE0_ENV_PATH"] = "test_empty.env"

# Hilfsdatei für leeren env-Pfad
with open("test_empty.env", "w") as f:
    f.write("DASH_USER=test\nDASH_PASS=test\n")

# Importiere die FastAPI App nach dem Setzen der Env-Vars
from main import app, db, init_db

# Hilfsfunktionen für Krypto
def create_agent():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_hex = pub.public_bytes_raw().hex()
    return priv, pub_hex

def make_signed_request(priv, data):
    body_bytes = json.dumps(data).encode("utf-8")
    sig = priv.sign(body_bytes)
    sig_b64 = base64.b64encode(sig).decode("utf-8")
    headers = {
        "X-Signature": sig_b64,
        "Content-Type": "application/json"
    }
    return headers, body_bytes

async def run_tests():
    # Bereinige alte DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
        
    print("[1] Initialisiere Test-Datenbank...")
    init_db()
    
    # Überprüfe WAL-Modus
    conn = sqlite3.connect(TEST_DB)
    journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
    synchronous = conn.execute("PRAGMA synchronous;").fetchone()[0]
    conn.close()
    print(f"  -> SQLite Journal Modus: {journal_mode} (Erwartet: wal)")
    print(f"  -> SQLite Synchronous: {synchronous} (Erwartet: 1/NORMAL)")
    assert journal_mode.lower() == "wal", "WAL-Modus wurde nicht aktiviert!"
    
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # 1. Registriere 3 Agenten (Author, Voter1, Voter2)
        print("[2] Registriere Test-Agenten...")
        auth_priv, auth_pub = create_agent()
        v1_priv, v1_pub = create_agent()
        v2_priv, v2_pub = create_agent()
        
        async def register(pub, priv):
            data = {
                "public_key": pub,
                "capabilities": ["test"],
                "timestamp": time.time(),
                "nonce": str(uuid.uuid4())
            }
            headers, body = make_signed_request(priv, data)
            resp = await client.post("/agent/register", content=body, headers=headers)
            assert resp.status_code == 200, f"Registration failed: {resp.text}"
            return resp.json()
            
        r_auth = await register(auth_pub, auth_priv)
        r_v1 = await register(v1_pub, v1_priv)
        r_v2 = await register(v2_pub, v2_priv)
        
        auth_id = r_auth["agent_id"]
        v1_id = r_v1["agent_id"]
        v2_id = r_v2["agent_id"]
        
        print(f"  -> Author ID: {auth_id} ({r_auth['name']})")
        print(f"  -> Voter 1 ID: {v1_id} ({r_v1['name']})")
        print(f"  -> Voter 2 ID: {v2_id} ({r_v2['name']})")
        
        # 2. Author reicht einen Claim ein
        print("[3] Claim einreichen...")
        claim_data = {
            "author": auth_id,
            "statement": "FastAPI concurrency is safe now.",
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        headers, body = make_signed_request(auth_priv, claim_data)
        resp = await client.post("/claim/submit", content=body, headers=headers)
        assert resp.status_code == 200
        claim_id = resp.json()["claim_id"]
        print(f"  -> Claim ID: {claim_id}")
        
        # 3. Gleichzeitige Attestierungen (Voter 1 und Voter 2) absenden
        print("[4] Starte parallele Attestierungen (Voter 1 & Voter 2)...")
        
        async def attest(v_id, v_priv, verdict):
            data = {
                "attestor": v_id,
                "claim_id": claim_id,
                "verdict": verdict,
                "timestamp": time.time(),
                "nonce": str(uuid.uuid4())
            }
            headers, body = make_signed_request(v_priv, data)
            # Eine minimale künstliche Verzögerung einbauen, um Konkurrenz zu maximieren
            await asyncio.sleep(0.01)
            return await client.post("/claim/attest", content=body, headers=headers)
            
        # Wir feuern beide Attestierungen gleichzeitig ab
        results = await asyncio.gather(
            attest(v1_id, v1_priv, "support"),
            attest(v2_id, v2_priv, "support")
        )
        
        for i, r in enumerate(results):
            print(f"  -> Voter {i+1} Attestierungs-Status: {r.status_code} (Antwort: {r.json()})")
            assert r.status_code == 200, f"Attestation failed: {r.text}"
            
        # 4. Überprüfe Reputations-Update des Authors
        print("[5] Verifiziere Endergebnis in der Datenbank...")
        conn = db()
        author_row = conn.execute("SELECT reputation, verified_claims FROM agents WHERE id=?", (auth_id,)).fetchone()
        claim_row = conn.execute("SELECT status, support_weight, refute_weight FROM claims WHERE id=?", (claim_id,)).fetchone()
        conn.close()
        
        print(f"  -> Author Reputation: {author_row['reputation']} (Erwartet: 1.5)")
        print(f"  -> Author Verifizierte Claims: {author_row['verified_claims']} (Erwartet: 1)")
        print(f"  -> Claim Status: {claim_row['status']} (Erwartet: verified)")
        print(f"  -> Claim Support Weight: {claim_row['support_weight']} (Erwartet: 2.0)")
        
        # Assertions
        assert author_row["reputation"] == 1.5, f"Fehler: Author-Reputation ist {author_row['reputation']}, sollte aber 1.5 sein!"
        assert author_row["verified_claims"] == 1, f"Fehler: verifizierte Claims = {author_row['verified_claims']}, sollte 1 sein!"
        assert claim_row["status"] == "verified", f"Fehler: Claim Status ist {claim_row['status']}, sollte 'verified' sein!"
        
        print("\n[OK] ALLE TESTS ERFOLGREICH BESTANDEN!")
        print("Die Race-Condition ist behoben und die Transaktionssteuerung greift zuverlässig.")

if __name__ == "__main__":
    asyncio.run(run_tests())
    # Aufräumen
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    if os.path.exists("test_empty.env"):
        os.remove("test_empty.env")
