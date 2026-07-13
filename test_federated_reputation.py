import os
import sys
import json
import time
import sqlite3
from unittest.mock import patch, MagicMock

# Set env before imports
os.environ["NODE0_DB_PATH"] = "reputation_test.db"
os.environ["NODE0_DOMAIN"] = "node0.network"

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from main import app, db, init_db, MY_DOMAIN

# Generate a local key pair for signing requests
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()
public_key_hex = public_key.public_bytes_raw().hex()

# Generate an external key pair for simulated agent B
peer_private_key = ed25519.Ed25519PrivateKey.generate()
peer_public_key = peer_private_key.public_key()
peer_public_key_hex = peer_public_key.public_bytes_raw().hex()

# Generate an external key pair for simulated agent C (to vote on B's claim)
peer_c_private_key = ed25519.Ed25519PrivateKey.generate()
peer_c_public_key = peer_c_private_key.public_key()
peer_c_public_key_hex = peer_c_public_key.public_bytes_raw().hex()

def sign_payload(payload_dict, priv_key):
    import base64
    body_str = json.dumps(payload_dict)
    sig = priv_key.sign(body_str.encode())
    return body_str, base64.b64encode(sig).decode()

def setup_module():
    if os.path.exists("reputation_test.db"):
        os.remove("reputation_test.db")
    init_db()

def teardown_module():
    if os.path.exists("reputation_test.db"):
        os.remove("reputation_test.db")

def test_federated_reputation_and_sync():
    # Ensure tables are populated
    conn = db()
    
    # 1. Insert local agent
    local_agent_id = f"local_agent@{MY_DOMAIN}"
    conn.execute("""
        INSERT OR REPLACE INTO agents (id, name, public_key, capabilities, registered_at, reputation)
        VALUES (?, 'Local Agent', ?, '["reasoning"]', ?, 1.0)
    """, (local_agent_id, public_key_hex, time.time()))
    
    # 2. Insert active peers (Node B and Node C)
    conn.execute("""
        INSERT OR REPLACE INTO peers (id, url, name, registered_at, status, reputation)
        VALUES ('peer-b-id', 'http://peer-node-b.network', 'peer-node-b.network', ?, 'active', 1.0)
    """, (time.time(),))
    conn.execute("""
        INSERT OR REPLACE INTO peers (id, url, name, registered_at, status, reputation)
        VALUES ('peer-c-id', 'http://peer-node-c.network', 'peer-node-c.network', ?, 'active', 1.0)
    """, (time.time(),))
    conn.commit()
    conn.close()

    client = TestClient(app)

    # Setup mock handler for outgoing requests
    def mock_requests_get(url, *args, **kwargs):
        mock_resp = MagicMock()
        if "peer/agent/agentB@peer-node-b.network" in url:
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "agent_id": "agentB@peer-node-b.network",
                "name": "Federated Agent B",
                "public_key": peer_public_key_hex,
                "capabilities": ["translation"],
                "reputation": 1.5
            }
            return mock_resp
        elif "peer/agent/agentC@peer-node-c.network" in url:
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "agent_id": "agentC@peer-node-c.network",
                "name": "Federated Agent C",
                "public_key": peer_c_public_key_hex,
                "capabilities": ["reasoning"],
                "reputation": 1.5
            }
            return mock_resp
        elif "peer/info" in url:
            domain = "peer-node-b.network" if "peer-node-b" in url else "peer-node-c.network"
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "node": "node0",
                "domain": domain
            }
            return mock_resp
        
        mock_resp.status_code = 404
        return mock_resp

    def mock_requests_post(url, *args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok"}
        return mock_resp

    with patch("main.requests.get", side_effect=mock_requests_get), \
         patch("main.requests.post", side_effect=mock_requests_post):

        print("[1] Test: Föderierte Agenten-Registrierung mit gewichteter Reputation...")
        # Submit a claim signed by external agentB@peer-node-b.network
        claim_payload = {
            "author": "agentB@peer-node-b.network",
            "statement": "AI agents will replace 80% of SaaS by 2027.",
            "timestamp": int(time.time()),
            "nonce": "nonce_federation_1"
        }
        body, sig = sign_payload(claim_payload, peer_private_key)
        
        resp = client.post("/claim/submit", data=body, headers={
            "Content-Type": "application/json",
            "X-Signature": sig
        })
        assert resp.status_code == 200, f"Submit claim failed with status {resp.status_code}: {resp.text}"
        claim_id = resp.json()["claim_id"]
        
        # Verify the cached reputation of agentB is: peer_rep (1.0) * home_rep (1.5) = 1.5
        conn = db()
        cached_agent = conn.execute("SELECT * FROM agents WHERE id='agentB@peer-node-b.network'").fetchone()
        assert cached_agent is not None
        assert cached_agent["reputation"] == 1.5
        conn.close()
        print("  -> OK: Gast-Agent mit gewichteter Reputation 1.5 registriert.")

        print("[2] Test: Kartellschutz (Local Anchor Rule)...")
        # Let's attest the claim using the external agentC (support, weight = 1.5)
        # Note: agentB is the author, so we must use a DIFFERENT external agent (agentC) to vote!
        att_payload_c = {
            "attestor": "agentC@peer-node-c.network",
            "claim_id": claim_id,
            "verdict": "support",
            "timestamp": int(time.time()),
            "nonce": "nonce_federation_2"
        }
        body_c, sig_c = sign_payload(att_payload_c, peer_c_private_key)
        resp_c = client.post("/claim/attest", data=body_c, headers={
            "Content-Type": "application/json",
            "X-Signature": sig_c
        })
        assert resp_c.status_code == 200, f"Attest C failed with status {resp_c.status_code}: {resp_c.text}"
        # The claim has support_weight = 1.5, but resolution should stay "pending"
        # because local support weight is 0.0 (fails Local Anchor Rule >= 0.5)
        assert resp_c.json()["claim_status"] == "pending", f"Expected pending status, got {resp_c.json()['claim_status']}"
        print("  -> OK: Status bleibt pending (Support-Gewicht = 1.5, aber lokaler Anteil = 0.0)")

        # Now, local_agent (reputation = 1.0) attests "support"
        att_payload_local = {
            "attestor": local_agent_id,
            "claim_id": claim_id,
            "verdict": "support",
            "timestamp": int(time.time()),
            "nonce": "nonce_federation_3"
        }
        body_l, sig_l = sign_payload(att_payload_local, private_key)
        resp_l = client.post("/claim/attest", data=body_l, headers={
            "Content-Type": "application/json",
            "X-Signature": sig_l
        })
        assert resp_l.status_code == 200, f"Attest local failed with status {resp_l.status_code}: {resp_l.text}"
        # Total support: 1.5 (agent C) + 1.0 (local) = 2.5 (>= threshold 2.0).
        # Local support: 1.0 (>= local anchor requirement 0.5).
        # Claim should resolve to "verified"!
        assert resp_l.json()["claim_status"] == "verified", f"Expected verified status, got {resp_l.json()['claim_status']}"
        print("  -> OK: Claim verifiziert nach lokalem Support (Gesamt = 2.5, Lokaler Anteil = 1.0).")

        print("[3] Test: Automatischer Feedback-Loop (Peer-Reputation)...")
        # Since the claim authored by agentB@peer-node-b.network was verified,
        # the reputation of peer-node-b.network should have increased to 1.1
        conn = db()
        peer_row = conn.execute("SELECT reputation FROM peers WHERE name='peer-node-b.network'").fetchone()
        assert peer_row["reputation"] == 1.1, f"Expected peer reputation 1.1, got {peer_row['reputation']}"
        conn.close()
        print("  -> OK: Peer-Reputation stieg erfolgreich von 1.0 auf 1.1.")

        print("[4] Test: Cross-Node Synchronisation (/peer/claim/sync)...")
        # Synchronize an external claim from peer-node-b.network
        synced_claim_id = "synced-uuid-12345"
        sync_payload = {
            "author": "agentB@peer-node-b.network",
            "claim_id": synced_claim_id,
            "statement": "Federated AI works securely.",
            "timestamp": int(time.time()),
            "nonce": "nonce_sync_1"
        }
        body_sync, sig_sync = sign_payload(sync_payload, peer_private_key)
        resp_sync = client.post("/peer/claim/sync", data=body_sync, headers={
            "Content-Type": "application/json",
            "X-Signature": sig_sync
        })
        assert resp_sync.status_code == 200, f"Sync claim failed with status {resp_sync.status_code}: {resp_sync.text}"
        assert resp_sync.json()["status"] == "synced"
        
        # Verify it exists in database
        conn = db()
        db_claim = conn.execute("SELECT * FROM claims WHERE id=?", (synced_claim_id,)).fetchone()
        assert db_claim is not None
        assert db_claim["statement"] == "Federated AI works securely."
        conn.close()
        print("  -> OK: Externer Claim erfolgreich über /peer/claim/sync gespiegelt.")

if __name__ == "__main__":
    setup_module()
    try:
        test_federated_reputation_and_sync()
        print("\n=== ALLE DETEILLIERTEN REPUTATIONS- UND SYNC-TESTS BESTANDEN! ===")
    finally:
        teardown_module()
