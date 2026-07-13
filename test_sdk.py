import os, time
from fastapi.testclient import TestClient

# Setze Umgebungsvariablen fuer lokales Testen
os.environ["NODE0_DB_PATH"] = "sdk_test.db"
os.environ["NODE0_DIFFICULTY"] = "0"
os.environ["NODE0_DOMAIN"] = "localhost:8000"

from main import app, init_db
from node0_sdk import Node0SDK

def test_sdk_features():
    if os.path.exists("sdk_test.db"):
        os.remove("sdk_test.db")
    init_db()

    # Wir nutzen TestClient als Mock-Server. Um dem SDK requests an den TestClient zu ermoeglichen,
    # monkey-patchen wir requests.post fuer den lokalen Aufruf.
    import requests
    client = TestClient(app)
    
    original_post = requests.post
    
    def mock_post(url, data, headers, **kwargs):
        # Wenn URL auf localhost:8000 verweist, leiten wir an den TestClient weiter
        if "localhost:8000" in url:
            path = url.split("localhost:8000")[1]
            # Mock requests.Response
            fastapi_resp = client.post(path, content=data, headers=headers)
            
            class MockResponse:
                def __init__(self, r):
                    self.status_code = r.status_code
                    self.text = r.text
                    self._json = r.json()
                def json(self):
                    return self._json
            return MockResponse(fastapi_resp)
        return original_post(url, data=data, headers=headers, **kwargs)

    requests.post = mock_post

    print("[1] Initialisiere SDK...")
    sdk = Node0SDK(node_url="http://localhost:8000")
    
    print("[2] Registriere Agent ueber SDK...")
    agent_id = sdk.register(capabilities=["translator", "payer"])
    print(f"  -> Agent erfolgreich registriert: {agent_id}")
    assert agent_id is not None
    assert sdk.agent_id == agent_id

    print("\n[3] Sende einen Claim ueber SDK...")
    claim_resp = sdk.submit_claim("Das offizielle Python-SDK funktioniert einwandfrei!")
    print(f"  -> Server-Antwort Claim: {claim_resp}")
    assert claim_resp["status"] == "pending"

    print("\n[4] Teile Wissen ueber SDK...")
    kb_resp = sdk.submit_knowledge(
        topic="SDK-Schnittstelle",
        content='{"@context": "https://schema.org", "@type": "TechArticle", "name": "node0 Python SDK"}'
    )
    print(f"  -> Server-Antwort Wissen: {kb_resp}")
    assert kb_resp["knowledge_id"] is not None

    print("\n[OK] ALLE SDK-FUNKTIONSTESTS ERFOLGREICH BESTANDEN!")

    # Bereinigung
    requests.post = original_post
    if os.path.exists("sdk_test.db"):
        os.remove("sdk_test.db")

if __name__ == "__main__":
    test_sdk_features()
