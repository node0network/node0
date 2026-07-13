import os, time, json, base64, uuid, sqlite3
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ed25519

# Setze Umgebungsvariablen für das Testen
os.environ["NODE0_DB_PATH"] = "payments.db"
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

def test_payments():
    # Bereinige alte DB
    if os.path.exists("payments.db"):
        os.remove("payments.db")
        
    init_db()
    client = TestClient(app)
    
    print("[1] Registriere Agent A (Sender) und Agent B (Empfänger)...")
    agent_A_priv, agent_A_pub = create_agent()
    agent_B_priv, agent_B_pub = create_agent()
    
    # Register A
    reg_A = {"public_key": agent_A_pub, "capabilities": ["payer"], "timestamp": time.time(), "nonce": "n-a"}
    headers, body = make_signed_request(agent_A_priv, reg_A)
    resp = client.post("/agent/register", content=body, headers=headers)
    if resp.status_code != 200:
        print(f"DEBUG ERROR: {resp.status_code} - {resp.text}")
    assert resp.status_code == 200
    agent_A_id = resp.json()["agent_id"]
    agent_A_name = resp.json()["name"]
    
    # Register B
    reg_B = {"public_key": agent_B_pub, "capabilities": ["receiver"], "timestamp": time.time(), "nonce": "n-b"}
    headers, body = make_signed_request(agent_B_priv, reg_B)
    resp = client.post("/agent/register", content=body, headers=headers)
    assert resp.status_code == 200
    agent_B_id = resp.json()["agent_id"]
    agent_B_name = resp.json()["name"]
    
    print(f"  -> Agent A (Payer): {agent_A_name} ({agent_A_id})")
    print(f"  -> Agent B (Receiver): {agent_B_name} ({agent_B_id})")

    # Setze Tageslimit für Agent A auf 500 Satoshis
    print("\n[2] Setze Tageslimit für Agent A auf 500 Satoshis...")
    limit_payload = {"agent_id": agent_A_id, "daily_limit_sats": 500}
    resp = client.put("/payment/wallet/limit", json=limit_payload)
    assert resp.status_code == 200
    assert resp.json()["daily_limit_sats"] == 500
    
    # Test 1: Agent B erstellt Rechnung über 200 Satoshis
    print("\n[3] Agent B erstellt eine Rechnung über 200 Satoshis...")
    invoice_payload = {
        "receiver_id": agent_B_id,
        "amount_sats": 200,
        "memo": "Recherche-Leistung"
    }
    resp = client.post("/payment/invoice", json=invoice_payload)
    assert resp.status_code == 200
    invoice_1 = resp.json()
    bolt11_1 = invoice_1["bolt11"]
    print(f"  -> Rechnung 1 erstellt: {invoice_1['invoice_id']} (Bolt11: {bolt11_1[:30]}...)")
    
    # Test 2: Agent A bezahlt Rechnung 1 autonom (unter Limit)
    print("\n[4] Agent A bezahlt Rechnung 1 (autonom unter Limit)...")
    pay_payload = {
        "sender_id": agent_A_id,
        "bolt11": bolt11_1,
        "timestamp": time.time(),
        "nonce": str(uuid.uuid4())
    }
    headers, body = make_signed_request(agent_A_priv, pay_payload)
    resp = client.post("/payment/pay", content=body, headers=headers)
    assert resp.status_code == 200
    print(f"  -> Zahlung 1 erfolgreich! Preimage: {resp.json()['preimage']}")
    
    # Verifiziere Kontostände in der DB
    conn = sqlite3.connect("payments.db")
    conn.row_factory = sqlite3.Row
    wallet_A = conn.execute("SELECT * FROM wallets WHERE agent_id = ?", (agent_A_id,)).fetchone()
    wallet_B = conn.execute("SELECT * FROM wallets WHERE agent_id = ?", (agent_B_id,)).fetchone()
    conn.close()
    
    print(f"  -> Stand Wallet A: {wallet_A['balance_sats']} Sats (Erwartet: 4800)")
    print(f"  -> Stand Wallet B: {wallet_B['balance_sats']} Sats (Erwartet: 5200)")
    assert wallet_A["balance_sats"] == 4800
    assert wallet_B["balance_sats"] == 5200
    assert wallet_A["spent_today_sats"] == 200

    # Test 3: Agent B erstellt zweite Rechnung über 400 Satoshis
    print("\n[5] Agent B erstellt eine zweite Rechnung über 400 Satoshis...")
    invoice_payload = {
        "receiver_id": agent_B_id,
        "amount_sats": 400,
        "memo": "Übersetzungs-Leistung"
    }
    resp = client.post("/payment/invoice", json=invoice_payload)
    assert resp.status_code == 200
    invoice_2 = resp.json()
    bolt11_2 = invoice_2["bolt11"]
    
    # Test 4: Agent A versucht zu zahlen (sollte Limit von 500 überschreiten: 200 + 400 = 600)
    print("\n[6] Agent A versucht Rechnung 2 zu bezahlen (sollte Limit überschreiten)...")
    pay_payload_2 = {
        "sender_id": agent_A_id,
        "bolt11": bolt11_2,
        "timestamp": time.time(),
        "nonce": str(uuid.uuid4())
    }
    headers, body = make_signed_request(agent_A_priv, pay_payload_2)
    resp = client.post("/payment/pay", content=body, headers=headers)
    print(f"  -> Antwort-Code: {resp.status_code} ({resp.json()['detail']})")
    assert resp.status_code == 403, "Zahlung ging durch, obwohl das Tageslimit überschritten wurde!"
    print("  -> Autonomer Schutz griff erfolgreich! Zahlung wurde blockiert (HTTP 403).")
    
    # Test 5: Inhaber erhöht Limit auf 1000 Satoshis (Freigabe)
    print("\n[7] Inhaber erhöht Tageslimit auf 1000 Satoshis (Manuelle Freigabe)...")
    limit_payload = {"agent_id": agent_A_id, "daily_limit_sats": 1000}
    resp = client.put("/payment/wallet/limit", json=limit_payload)
    assert resp.status_code == 200
    
    # Test 6: Agent A bezahlt Rechnung 2 erneut (mit frischer Nonce!)
    print("\n[8] Agent A bezahlt Rechnung 2 erneut nach Limit-Anhebung...")
    pay_payload_2["nonce"] = str(uuid.uuid4())
    pay_payload_2["timestamp"] = time.time()
    headers, body = make_signed_request(agent_A_priv, pay_payload_2)
    resp = client.post("/payment/pay", content=body, headers=headers)
    if resp.status_code != 200:
        print(f"DEBUG ERROR: {resp.status_code} - {resp.text}")
    assert resp.status_code == 200
    print("  -> Zahlung 2 nach Limit-Erhöhung erfolgreich!")
    
    # Abschließende Kontostandsprüfung
    conn = sqlite3.connect("payments.db")
    conn.row_factory = sqlite3.Row
    wallet_A = conn.execute("SELECT * FROM wallets WHERE agent_id = ?", (agent_A_id,)).fetchone()
    wallet_B = conn.execute("SELECT * FROM wallets WHERE agent_id = ?", (agent_B_id,)).fetchone()
    conn.close()
    
    print(f"  -> Finaler Stand Wallet A: {wallet_A['balance_sats']} Sats (Erwartet: 4400)")
    print(f"  -> Finaler Stand Wallet B: {wallet_B['balance_sats']} Sats (Erwartet: 5600)")
    assert wallet_A["balance_sats"] == 4400
    assert wallet_B["balance_sats"] == 5600
    
    print("\n[OK] ALLE BEZAHL- UND BUDGET-TESTS ERFOLGREICH BESTANDEN!")
    
    # Bereinigung
    if os.path.exists("payments.db"):
        os.remove("payments.db")

if __name__ == "__main__":
    test_payments()
