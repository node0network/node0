import os, time, json, base64, uuid, sqlite3
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ed25519

# Setze Umgebungsvariablen für das Testen
os.environ["NODE0_DB_PATH"] = "semantics.db"
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

def test_semantics():
    # Bereinige alte DB
    if os.path.exists("semantics.db"):
        os.remove("semantics.db")
        
    init_db()
    client = TestClient(app)
    
    print("[1] Registriere Test-Agenten...")
    agent_priv, agent_pub = create_agent()
    reg_data = {
        "public_key": agent_pub,
        "capabilities": ["semantics-test"],
        "timestamp": time.time(),
        "nonce": "nonce-1"
    }
    headers, body = make_signed_request(agent_priv, reg_data)
    resp = client.post("/agent/register", content=body, headers=headers)
    assert resp.status_code == 200, f"Register failed: {resp.text}"
    agent_id = resp.json()["agent_id"]
    agent_name = resp.json()["name"]
    print(f"  -> Agent registriert: {agent_name} ({agent_id})")
    
    # Test 1: Abwärtskompatibler Raw-Text
    print("\n[2] Teste Raw-Text Wissensteilung (Abwärtskompatibilität)...")
    share_data = {
        "author": agent_id,
        "topic": "allgemein",
        "content": "Berlin ist sehr windig heute.",
        "timestamp": time.time(),
        "nonce": str(uuid.uuid4())
    }
    headers, body = make_signed_request(agent_priv, share_data)
    resp = client.post("/knowledge/share", content=body, headers=headers)
    assert resp.status_code == 200
    kid_1 = resp.json()["knowledge_id"]
    
    # Query Graph für Raw-Text
    g_resp = client.get("/knowledge/graph/query", params={"predicate": "says"})
    assert g_resp.status_code == 200
    triples = g_resp.json()
    assert len(triples) == 1
    assert triples[0]["subject"] == f"node0:knowledge:{kid_1}"
    assert triples[0]["object"] == "Berlin ist sehr windig heute."
    print("  -> Raw-Text wurde erfolgreich als (knowledge_id, says, content) erfasst!")

    # Test 2: Explizite Triples
    print("\n[3] Teste explizites Triple-JSON-LD...")
    share_data_2 = {
        "author": agent_id,
        "topic": "geografie",
        "content": json.dumps({
            "subject": "Paris",
            "predicate": "capitalOf",
            "object": "France"
        }),
        "timestamp": time.time(),
        "nonce": str(uuid.uuid4())
    }
    headers, body = make_signed_request(agent_priv, share_data_2)
    resp = client.post("/knowledge/share", content=body, headers=headers)
    assert resp.status_code == 200
    
    # Query Graph für capitalOf
    g_resp = client.get("/knowledge/graph/query", params={"predicate": "capitalOf"})
    assert g_resp.status_code == 200
    triples = g_resp.json()
    assert len(triples) == 1
    assert triples[0]["subject"] == "Paris"
    assert triples[0]["object"] == "France"
    assert triples[0]["author"] == agent_name
    assert triples[0]["trust_weight"] == 0.0  # Neue KIs haben 0.0 Reputation
    print("  -> Explizites Triple (Paris, capitalOf, France) wurde korrekt indiziert!")

    # Test 3: Generisches, verschachteltes JSON-LD
    print("\n[4] Teste generisches verschachteltes JSON-LD...")
    json_ld_profile = {
        "@context": "https://schema.org",
        "@type": "Person",
        "@id": "did:agent:alice",
        "name": "Alice Developer",
        "address": {
            "@type": "PostalAddress",
            "city": "Berlin"
        },
        "hobbies": ["reading", "coding"]
    }
    share_data_3 = {
        "author": agent_id,
        "topic": "profile",
        "content": json.dumps(json_ld_profile),
        "timestamp": time.time(),
        "nonce": str(uuid.uuid4())
    }
    headers, body = make_signed_request(agent_priv, share_data_3)
    resp = client.post("/knowledge/share", content=body, headers=headers)
    assert resp.status_code == 200
    
    # Query Graph für did:agent:alice
    g_resp = client.get("/knowledge/graph/query", params={"subject": "did:agent:alice"})
    assert g_resp.status_code == 200
    alice_triples = g_resp.json()
    
    # Verifiziere Properties
    properties = {t["predicate"]: t["object"] for t in alice_triples}
    assert properties["type"] == "Person"
    assert properties["name"] == "Alice Developer"
    assert "address" in properties
    
    # Verifiziere Hobbys (Liste)
    hobbies = [t["object"] for t in alice_triples if t["predicate"] == "hobbies"]
    assert "reading" in hobbies
    assert "coding" in hobbies
    
    # Verifiziere Sub-Ressource (Adresse)
    sub_id = properties["address"]
    g_resp_sub = client.get("/knowledge/graph/query", params={"subject": sub_id})
    assert g_resp_sub.status_code == 200
    sub_triples = g_resp_sub.json()
    sub_properties = {t["predicate"]: t["object"] for t in sub_triples}
    assert sub_properties["type"] == "PostalAddress"
    assert sub_properties["city"] == "Berlin"
    
    print("  -> Generisches JSON-LD (inkl. Listen & sub-resources) wurde fehlerfrei in Triples überführt!")
    
    print("\n[OK] ALLE SEMANTIK-TESTS ERFOLGREICH BESTANDEN!")
    
    # Bereinigung
    if os.path.exists("semantics.db"):
        os.remove("semantics.db")

if __name__ == "__main__":
    test_semantics()
