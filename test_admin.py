import os, time, json, base64, uuid, sqlite3
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ed25519

# Setze Umgebungsvariablen für das Testen
os.environ["NODE0_DB_PATH"] = "admin_test.db"
os.environ["NODE0_DIFFICULTY"] = "0"
os.environ["NODE0_DOMAIN"] = "localhost:8000"

from main import app, db, init_db

# Krypto-Hilfsfunktionen
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

def test_admin_features():
    # Bereinige alte DB
    if os.path.exists("admin_test.db"):
        os.remove("admin_test.db")
        
    init_db()
    from dashboard import init_auth
    init_auth()
    client = TestClient(app)
    
    print("[1] Registriere Agenten...")
    agent_A_priv, agent_A_pub = create_agent()
    agent_B_priv, agent_B_pub = create_agent()
    
    # Register A
    reg_A = {"public_key": agent_A_pub, "capabilities": ["payer"], "timestamp": time.time(), "nonce": "n-a"}
    headers, body = make_signed_request(agent_A_priv, reg_A)
    resp = client.post("/agent/register", content=body, headers=headers)
    assert resp.status_code == 200
    agent_A_id = resp.json()["agent_id"]
    
    # Register B
    reg_B = {"public_key": agent_B_pub, "capabilities": ["receiver"], "timestamp": time.time(), "nonce": "n-b"}
    headers, body = make_signed_request(agent_B_priv, reg_B)
    resp = client.post("/agent/register", content=body, headers=headers)
    assert resp.status_code == 200
    agent_B_id = resp.json()["agent_id"]
    
    print("  -> Agenten erfolgreich registriert.")

    # Test 1: Maut-Abrechnung (Routing Fee)
    print("\n[2] Teste Maut-Abrechnung bei Zahlung...")
    invoice_payload = {
        "receiver_id": agent_B_id,
        "amount_sats": 100,
        "memo": "Maut-Test"
    }
    resp = client.post("/payment/invoice", json=invoice_payload)
    assert resp.status_code == 200
    bolt11 = resp.json()["bolt11"]
    
    pay_payload = {
        "sender_id": agent_A_id,
        "bolt11": bolt11,
        "timestamp": time.time(),
        "nonce": str(uuid.uuid4())
    }
    headers, body = make_signed_request(agent_A_priv, pay_payload)
    resp = client.post("/payment/pay", content=body, headers=headers)
    assert resp.status_code == 200
    
    # Verifiziere Gebührenfluss
    conn = sqlite3.connect("admin_test.db")
    conn.row_factory = sqlite3.Row
    wallet_A = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = ?", (agent_A_id,)).fetchone()
    wallet_B = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = ?", (agent_B_id,)).fetchone()
    wallet_admin = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = 'admin@node0.network'").fetchone()
    conn.close()
    
    print(f"  -> Payer A: {wallet_A['balance_sats']} Sats (Erwartet: 4900)")
    print(f"  -> Receiver B: {wallet_B['balance_sats']} Sats (Erwartet: 5099 - da 1 Satoshi Maut abgezogen)")
    print(f"  -> Admin-Wallet: {wallet_admin['balance_sats']} Sats (Erwartet: 1 - Maut erhalten!)")
    
    assert wallet_A["balance_sats"] == 4900
    assert wallet_B["balance_sats"] == 5099
    assert wallet_admin["balance_sats"] == 1

    # Test 2: Notbremse (Emergency Freeze)
    print("\n[3] Teste System-Notbremse (Emergency Kill Switch)...")
    # Aktivierung via Admin-API
    # Wir umgehen Basic Auth im Testclient durch direkte DB-Manipulation oder POST (TestClient unterstützt Basic Auth)
    auth_headers = {"Authorization": "Basic " + base64.b64encode(b"Josh:tyaCHLwxRRb74vmIlcwfZv8f").decode("ascii")}
    resp = client.post("/dashboard/admin/freeze", json={"freeze": True}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["emergency_freeze"] is True
    print("  -> Notbremse über Admin-API aktiviert.")
    
    # Versuche neue Zahlung auszuführen (sollte geblockt werden)
    invoice_payload_2 = {
        "receiver_id": agent_B_id,
        "amount_sats": 50,
        "memo": "Freeze-Test"
    }
    resp = client.post("/payment/invoice", json=invoice_payload_2)
    assert resp.status_code == 200
    bolt11_2 = resp.json()["bolt11"]
    
    pay_payload_2 = {
        "sender_id": agent_A_id,
        "bolt11": bolt11_2,
        "timestamp": time.time(),
        "nonce": str(uuid.uuid4())
    }
    headers, body = make_signed_request(agent_A_priv, pay_payload_2)
    resp = client.post("/payment/pay", content=body, headers=headers)
    print(f"  -> Zahlungs-Antwort während Freeze: {resp.status_code} ({resp.json()['detail']})")
    assert resp.status_code == 503
    print("  -> Autonomer Schutz griff erfolgreich! Zahlung wurde mit HTTP 503 blockiert.")
    
    # Test 3: Notbremse deaktivieren
    print("\n[4] Deaktiviere Notbremse und teste erneut...")
    resp = client.post("/dashboard/admin/freeze", json={"freeze": False}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["emergency_freeze"] is False
    
    # Zahlung erneut einreichen (mit frischer Nonce)
    pay_payload_2["nonce"] = str(uuid.uuid4())
    pay_payload_2["timestamp"] = time.time()
    headers, body = make_signed_request(agent_A_priv, pay_payload_2)
    resp = client.post("/payment/pay", content=body, headers=headers)
    assert resp.status_code == 200
    print("  -> Zahlung nach Freigabe wieder erfolgreich!")
    
    # Test 4: Peer Gatekeeping (Pending status)
    print("\n[5] Teste Peer-Gatekeeping (Zulassungs-Warteschlange)...")
    # Registriere neuen Peer
    # Da wir eine echte Verbindung im Test simulieren, tragen wir den Peer direkt ein oder rufen /peer/register auf
    # Für den Mock-Test nutzen wir direkte DB-Einträge
    conn = sqlite3.connect("admin_test.db")
    conn.execute("INSERT INTO peers (id, url, name, registered_at, status) VALUES ('mock-peer-id', 'http://localhost:8001', 'node1.network', ?, 'pending')", (time.time(),))
    conn.commit()
    conn.close()
    
    # Versuche externen Agenten über diesen pending Peer zu verifizieren (sollte scheitern)
    # verify_action für einen externen Agenten
    # Da mock-peer pending ist, wird verify_action fehlschlagen
    ext_agent_id = "external-agent@node1.network"
    req_payload = {
        "sender_id": ext_agent_id,
        "bolt11": "some-bolt11",
        "timestamp": time.time(),
        "nonce": "nonce-ext"
    }
    # Wir signieren mit beliebigem Key (da Verify_action den Peer anfragen würde, was fehlschlägt da Peer nicht active ist)
    headers, body = make_signed_request(agent_A_priv, req_payload)
    resp = client.post("/payment/pay", content=body, headers=headers)
    print(f"  -> Verifizierung mit pending Peer: {resp.status_code} ({resp.json()['detail']})")
    # Sollte 404 Not Found liefern da der Peer nicht aktiv ist und der Agent somit nicht gefunden wird
    assert resp.status_code == 404
    
    # Peer per Admin-API freigeben
    print("  -> Aktiviere Peer über Admin-API...")
    resp = client.post("/dashboard/admin/peer/status", json={"peer_id": "mock-peer-id", "status": "active"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["peer_status"] == "active"
    
    # Check in DB
    conn = sqlite3.connect("admin_test.db")
    peer_row = conn.execute("SELECT status FROM peers WHERE id='mock-peer-id'").fetchone()
    conn.close()
    assert peer_row[0] == "active"
    print("  -> Peer erfolgreich auf 'active' gesetzt.")

    print("\n[OK] ALLE INTERAKTIVEN COCKPIT- UND MAUT-TESTS ERFOLGREICH BESTANDEN!")
    
    # Bereinigung
    if os.path.exists("admin_test.db"):
        os.remove("admin_test.db")

if __name__ == "__main__":
    test_admin_features()
