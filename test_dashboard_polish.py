import os, time, json, base64, uuid, sqlite3
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ed25519

# Setze Umgebungsvariablen für das Testen
os.environ["NODE0_DB_PATH"] = "polish_test.db"
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

def test_dashboard_polish():
    # Bereinige alte DB
    if os.path.exists("polish_test.db"):
        os.remove("polish_test.db")
        
    init_db()
    from dashboard import init_auth
    init_auth()
    
    client = TestClient(app)
    
    auth_headers = {"Authorization": "Basic " + base64.b64encode(b"Josh:tyaCHLwxRRb74vmIlcwfZv8f").decode("ascii")}
    
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
    
    print(f"  -> Agent A ID: {agent_A_id}")
    print(f"  -> Agent B ID: {agent_B_id}")

    # Test 1: Einzelsperre (Granular Blocking)
    print("\n[2] Teste granulare Agenten-Sperrung...")
    # Sperre Agent A
    resp = client.post("/dashboard/admin/agent/status", json={"agent_id": agent_A_id, "status": "blocked"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["agent_status"] == "blocked"
    print("  -> Agent A über Admin-API gesperrt.")
    
    # Versuche Zahlung mit gesperrtem Agenten (sollte scheitern)
    invoice_payload = {
        "receiver_id": agent_B_id,
        "amount_sats": 50,
        "memo": "Sperr-Test"
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
    print(f"  -> Zahlungs-Antwort von gesperrtem Agenten: {resp.status_code} ({resp.json()['detail']})")
    assert resp.status_code == 403
    assert "blocked" in resp.json()["detail"].lower()
    print("  -> Autonomer Schutz griff erfolgreich! Zahlung wurde blockiert.")

    # Entsperre Agent A
    resp = client.post("/dashboard/admin/agent/status", json={"agent_id": agent_A_id, "status": "active"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["agent_status"] == "active"
    print("  -> Agent A über Admin-API wieder freigegeben.")
    
    # Führe Zahlung erneut aus
    pay_payload["nonce"] = str(uuid.uuid4())
    pay_payload["timestamp"] = time.time()
    headers, body = make_signed_request(agent_A_priv, pay_payload)
    resp = client.post("/payment/pay", content=body, headers=headers)
    assert resp.status_code == 200
    print("  -> Zahlung nach Freigabe erfolgreich durchgeführt!")

    # Test 2: Zahlungsverlauf
    print("\n[3] Teste Zahlungsverlauf im Dashboard...")
    resp = client.get("/dashboard/data", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "transactions" in data
    assert len(data["transactions"]) >= 1
    tx = data["transactions"][0]
    assert tx["sender_id"] == agent_A_id
    assert tx["receiver_id"] == agent_B_id
    assert tx["amount_sats"] == 50
    print(f"  -> Transaktion im Verlauf erfasst: {tx['amount_sats']} Sats von {tx['sender_id'][:8]} an {tx['receiver_id'][:8]}")

    # Test 3: KI-Assistent Chatbot
    print("\n[4] Teste Steuermann-Assistent (Chatbot)...")
    # Einfacher Modus (da kein Gemini API Key geladen ist)
    chat_payload = {"message": "Wie hoch ist mein Kontostand?"}
    resp = client.post("/dashboard/admin/chat", json=chat_payload, headers=auth_headers)
    assert resp.status_code == 200
    print(f"  -> Assistenten-Antwort (Kontostand): {resp.json()['reply']}")
    assert "einnahmen" in resp.json()["reply"].lower() or "kontostand" in resp.json()["reply"].lower()

    chat_payload2 = {"message": "Welche KIs sind registriert?"}
    resp = client.post("/dashboard/admin/chat", json=chat_payload2, headers=auth_headers)
    assert resp.status_code == 200
    print(f"  -> Assistenten-Antwort (KIs): {resp.json()['reply']}")
    assert "agent" in resp.json()["reply"].lower() or "ki" in resp.json()["reply"].lower()

    print("\n[OK] ALLE DASHBOARD-POLISH- UND CHATBOT-TESTS ERFOLGREICH BESTANDEN!")
    
    # Bereinigung
    if os.path.exists("polish_test.db"):
        os.remove("polish_test.db")

if __name__ == "__main__":
    test_dashboard_polish()
