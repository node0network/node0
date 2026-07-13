import os, sys, subprocess, time, json, base64, uuid
import sqlite3
import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519

# Hilfsfunktionen für Krypto-Signaturen
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

async def test_federation():
    # Datenbanken bereinigen
    for db_file in ("nodeA.db", "nodeB.db"):
        if os.path.exists(db_file):
            os.remove(db_file)
            
    print("[1] Starte Node A und Node B in getrennten Subprozessen...")
    
    # Node A auf Port 8001 (Domain: localhost:8001)
    env_A = {
        **os.environ,
        "NODE0_DB_PATH": "nodeA.db",
        "NODE0_DOMAIN": "localhost:8001",
        "NODE0_DIFFICULTY": "0",  # 0 für sofortige Registrierung im Test
        "DASH_USER": "test",
        "DASH_PASS": "test"
    }
    proc_A = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8001"],
        env=env_A, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    
    # Node B auf Port 8002 (Domain: localhost:8002)
    env_B = {
        **os.environ,
        "NODE0_DB_PATH": "nodeB.db",
        "NODE0_DOMAIN": "localhost:8002",
        "NODE0_DIFFICULTY": "0",
        "DASH_USER": "test",
        "DASH_PASS": "test"
    }
    proc_B = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8002"],
        env=env_B, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    
    # Warten, bis beide Server hochgefahren sind
    async with httpx.AsyncClient(timeout=10.0) as client:
        print("  -> Warte auf Verfügbarkeit der Nodes...")
        for i in range(15):
            try:
                rA = await client.get("http://127.0.0.1:8001/peer/info")
                rB = await client.get("http://127.0.0.1:8002/peer/info")
                if rA.status_code == 200 and rB.status_code == 200:
                    print("  -> Beide Nodes sind online!")
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            proc_A.terminate()
            proc_B.terminate()
            raise RuntimeError("Nodes konnten nicht gestartet werden.")
            
        try:
            # 2. Registriere Node A auf Node B als Peer
            print("[2] Registriere Node A auf Node B als verifizierten Peer...")
            reg_payload = {"url": "http://127.0.0.1:8001"}
            resp = await client.post("http://127.0.0.1:8002/peer/register", json=reg_payload)
            print(f"  -> Antwort Node B /peer/register: {resp.status_code} ({resp.json()})")
            assert resp.status_code == 200
            
            # 3. Registriere einen Agenten auf Node A
            print("[3] Registriere Agent auf Node A...")
            agent_priv, agent_pub = create_agent()
            reg_payload = {
                "public_key": agent_pub,
                "capabilities": ["federation-test"],
                "timestamp": time.time(),
                "nonce": "test-nonce"
            }
            headers, body = make_signed_request(agent_priv, reg_payload)
            resp = await client.post("http://127.0.0.1:8001/agent/register", content=body, headers=headers)
            print(f"  -> Antwort Node A /agent/register: {resp.status_code}")
            assert resp.status_code == 200
            agent_id = resp.json()["agent_id"]
            agent_name = resp.json()["name"]
            print(f"  -> Generierte Agenten-ID: {agent_id} (Name: {agent_name})")
            assert agent_id.endswith("@localhost:8001"), "Die Agenten-ID besitzt nicht das föderierte Domain-Suffix!"
            
            # 4. Sende signierte Anfrage des Agenten an Node B (wo er NICHT registriert ist!)
            print("[4] Sende signierten Claim des Agenten an Node B (Port 8002)...")
            claim_data = {
                "author": agent_id,
                "statement": "Föderierter Signaturabgleich funktioniert!",
                "timestamp": time.time(),
                "nonce": str(uuid.uuid4())
            }
            headers, body = make_signed_request(agent_priv, claim_data)
            
            # Node B muss nun:
            # - Erkennen, dass agent_id fremd ist (@localhost:8001)
            # - In Tabelle 'peers' nach 'localhost:8001' suchen (erlaubt!)
            # - Key abrufen von Node A (/peer/agent/{agent_id})
            # - Agent cachen und Signatur prüfen.
            resp = await client.post("http://127.0.0.1:8002/claim/submit", content=body, headers=headers)
            print(f"  -> Antwort Node B /claim/submit: {resp.status_code} ({resp.json()})")
            assert resp.status_code == 200
            assert resp.json()["status"] == "pending"
            
            # 5. Verifiziere Caching in Node B's Datenbank
            print("[5] Überprüfe, ob der Agent lokal auf Node B gecacht wurde...")
            conn = sqlite3.connect("nodeB.db")
            conn.row_factory = sqlite3.Row
            cached_agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
            conn.close()
            
            assert cached_agent is not None, "Agent wurde nicht auf Node B gecacht!"
            print(f"  -> Gecachter Agent Name: {cached_agent['name']} (Erwartet: {agent_name})")
            print(f"  -> Gecachter Agent Reputation: {cached_agent['reputation']} (Erwartet: 0.0 für externe Gäste)")
            assert cached_agent["reputation"] == 0.0
            
            # 6. Teste Schutz vor unregistrierten Domains (SSRF-Schutz)
            print("[6] Teste SSRF-Schutz auf Node B (fremde nicht-registrierte Domain)...")
            # Wir faken eine Agenten-ID von einer nicht registrierten Domain
            fake_agent_id = f"{str(uuid.uuid4())}@hackers.com"
            fake_claim = {
                "author": fake_agent_id,
                "statement": "Dieser Angriff sollte fehlschlagen.",
                "timestamp": time.time(),
                "nonce": str(uuid.uuid4())
            }
            headers, body = make_signed_request(agent_priv, fake_claim)
            resp = await client.post("http://127.0.0.1:8002/claim/submit", content=body, headers=headers)
            print(f"  -> Antwort Node B bei unregistriertem Peer: {resp.status_code} (Erwartet: 404)")
            assert resp.status_code == 404, "Server führte Lookup für unregistrierten Peer aus (SSRF-Sicherheitslücke)!"
            
            print("\n[OK] ALLE FÖDERATIONS-TESTS ERFOLGREICH BESTANDEN!")
            
        finally:
            # Aufräumen
            print("[7] Beende Server-Prozesse...")
            proc_A.terminate()
            proc_B.terminate()
            
            # Warte auf das Beenden der Prozesse
            proc_A.wait()
            proc_B.wait()

    # Bereinige Testdatenbanken
    for db_file in ("nodeA.db", "nodeB.db"):
        if os.path.exists(db_file):
            os.remove(db_file)
            
if __name__ == "__main__":
    import asyncio
    asyncio.run(test_federation())
