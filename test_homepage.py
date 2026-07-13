import os
from fastapi.testclient import TestClient

# Setze Umgebungsvariablen fuer Testen
os.environ["NODE0_DB_PATH"] = "homepage_test.db"
os.environ["NODE0_DIFFICULTY"] = "0"
os.environ["NODE0_DOMAIN"] = "localhost:8000"

from main import app, init_db

def test_homepage():
    if os.path.exists("homepage_test.db"):
        os.remove("homepage_test.db")
    init_db()
    
    client = TestClient(app)
    
    print("[1] Rufe Homepage (/) ab...")
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    
    html_content = resp.text
    print("  -> Antwort empfangen (Länge: {} Zeichen)".format(len(html_content)))
    
    # Pruefe wichtige Schluesselbegriffe auf der Seite
    print("[2] Ueberpruefe Manifest-Schluesselbegriffe...")
    assert "Sovereign infrastructure" in html_content
    assert "Agent Mesh" in html_content
    assert "Cryptographic Sovereignty" in html_content
    assert "Subjective Trust" in html_content
    assert "Linked Data graphs" in html_content
    assert "Real-World Micropayments" in html_content
    
    print("[3] Ueberpruefe SDK-Quickstart-Sektion...")
    assert "curl -O https://node0.network/sdk/node0_sdk.py" in html_content
    assert "Node0SDK" in html_content
    
    print("[4] Ueberpruefe Legal-Schnittstelle (/legal)...")
    legal_resp = client.get("/legal")
    assert legal_resp.status_code == 200
    assert "Legal Disclosure" in legal_resp.text
    assert "Moon York GmbH" in legal_resp.text
    
    # Bereinigung
    if os.path.exists("homepage_test.db"):
        os.remove("homepage_test.db")
        
    print("\n[OK] HOMEPAGE-, MANIFEST- UND LEGAL-TESTS ERFOLGREICH BESTANDEN!")

if __name__ == "__main__":
    test_homepage()
