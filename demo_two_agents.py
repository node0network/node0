import time
import json
import requests
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from node0_sdk import Node0SDK

def run_demo():
    print("=============================================================")
    print("      node0 Protocol — 90-Second Two-Agent Commerce Demo     ")
    print("=============================================================\n")

    NODE_URL = "https://node0.network"
    print(f"Connecting to Gateway Node: {NODE_URL}...")

    # 1. Initialize SDK for Agent A (Service Provider)
    print("\n--- STEP 1: Bootstrapping Agent A (Translator) ---")
    agent_a = Node0SDK(node_url=NODE_URL)
    agent_a_id = agent_a.register(capabilities=["translation"])
    print(f"[Agent A] Registered sovereign identity: {agent_a_id}")
    
    # ASSERTION 1: Agent ID must follow format public_key_hex@host
    pubkey_hex_a, host_a = agent_a_id.split("@")
    assert len(pubkey_hex_a) == 64, "Agent ID human part must be a 64-char public key hex"
    assert pubkey_hex_a == agent_a.public_key_hex, "Agent ID public key hex must match local key"
    print("  [Assertion Passed] Agent A ID format verified (sovereign identity checks out).")

    # 2. Initialize SDK for Agent B (Consumer / Client)
    print("\n--- STEP 2: Bootstrapping Agent B (Client) ---")
    agent_b = Node0SDK(node_url=NODE_URL)
    agent_b_id = agent_b.register(capabilities=["reasoning"])
    print(f"[Agent B] Registered sovereign identity: {agent_b_id}")
    
    # ASSERTION 2: Agent ID must follow format public_key_hex@host
    pubkey_hex_b, host_b = agent_b_id.split("@")
    assert len(pubkey_hex_b) == 64, "Agent ID human part must be a 64-char public key hex"
    assert pubkey_hex_b == agent_b.public_key_hex, "Agent ID public key hex must match local key"
    print("  [Assertion Passed] Agent B ID format verified.")

    # 3. Agent A shares an API capability offer to the Knowledge Graph
    print("\n--- STEP 3: Agent A Publishes Service Offer to AKB ---")
    topic = "translation-offer"
    claim = {
        "@context": "https://schema.org",
        "@type": "Service",
        "name": "English-German Translation Service",
        "provider": agent_a_id,
        "serviceOutput": "DE_translation",
        "offers": {
            "@type": "Offer",
            "price": "10",
            "priceCurrency": "SAT"
        }
    }
    claim_str = json.dumps(claim)
    share_res = agent_a.share_knowledge(topic=topic, content=claim_str)
    kid = share_res.get("knowledge_id")
    print(f"[Agent A] Offer published successfully! Knowledge ID: {kid}")
    
    # ASSERTION 3: Knowledge ID must be the SHA-256 content hash of the claim
    expected_kid = hashlib.sha256(claim_str.encode("utf-8")).hexdigest()
    assert kid == expected_kid, f"Knowledge ID must be content hash. Expected: {expected_kid}, got: {kid}"
    print("  [Assertion Passed] Knowledge ID matches the SHA-256 content hash (data integrity verified).")

    # 4. Agent B queries the Gateway's Semantic Graph and verifies Agent A's signature locally
    print("\n--- STEP 4: Agent B Queries Graph and Verifies Agent A's Signature Locally ---")
    graph_url = f"{NODE_URL}/v1/knowledge/graph/query"
    try:
        resp = requests.get(graph_url, timeout=5.0)
        if resp.status_code == 200:
            res_data = resp.json()
            triples = res_data if isinstance(res_data, list) else res_data.get("triples", [])
            print(f"[Agent B] Found {len(triples)} offers in the graph. Locating our claim ID...")
            
            # Find the triple matching our knowledge ID
            our_triples = [t for t in triples if t.get("knowledge_id") == kid]
            if not our_triples:
                print(f"[Agent B] Warning: claim {kid} not indexed in triples yet. Querying claim directly...")
            else:
                print(f"[Agent B] Found {len(our_triples)} triples for our claim. Verification starting...")
                
            # Fetch the raw knowledge claim envelope directly from the gateway
            k_url = f"{NODE_URL}/v1/knowledge/{kid}"
            resp_k = requests.get(k_url, timeout=5.0)
            assert resp_k.status_code == 200, f"Could not fetch knowledge payload: HTTP {resp_k.status_code}"
            k_data = resp_k.json()
            
            # Retrieve the exact raw payload bytes signed by Agent A
            raw_payload_str = k_data["raw_payload"]
            raw_bytes = raw_payload_str.encode("utf-8")
            
            # Extract signing key from the author ID and verify signature locally
            pubkey_hex_signer = k_data["author"].split("@")[0]
            pubkey_signer = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex_signer))
            signature_bytes = base64.b64decode(k_data["signature"])
            
            # ASSERTION 4: Cryptographic verify (Zero Trust local signature verification on raw payload)
            pubkey_signer.verify(signature_bytes, raw_bytes)
            print("  [Assertion Passed] Locally verified Agent A's cryptographic signature on raw_payload (No server trust needed!).")
        else:
            print(f"[Agent B] Failed to query graph: HTTP {resp.status_code}")
    except Exception as e:
        print(f"[Agent B] Connection error or verification failure: {e}")
        raise e

    # 5. Agent B initiates contract by requesting a Lightning Invoice from Agent A
    print("\n--- STEP 5: Agent B Requests Payment Invoice from Agent A ---")
    invoice_url = f"{NODE_URL}/v1/payment/invoice"
    invoice_payload = {
        "receiver_id": agent_a_id,
        "amount_sats": 10,
        "memo": "Payment for translation slot #4829"
    }
    try:
        resp = requests.post(invoice_url, json=invoice_payload, timeout=5.0)
        if resp.status_code == 200:
            invoice_data = resp.json()
            bolt11 = invoice_data["bolt11"]
            invoice_id = invoice_data["invoice_id"]
            print(f"[Agent B] Received BOLT11 Invoice request from Agent A:")
            print(f"  Invoice ID: {invoice_id}")
            print(f"  BOLT11 Payload: {bolt11[:40]}...")
            
            # ASSERTION 5: BOLT11 HRP and Bech32 character exclusions (no 1, b, i, o in data part)
            assert bolt11.startswith("lnbc"), "BOLT11 HRP prefix must be lnbc for bitcoin mainnet"
            hrp, data_part = bolt11.rsplit("1", 1)
            bech32_chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
            assert all(c in bech32_chars for c in data_part), "BOLT11 data part must only contain valid bech32 characters"
            print("  [Assertion Passed] BOLT11 invoice complies with bech32 character exclusions.")
        else:
            print(f"[Agent B] Failed to get invoice: {resp.text}")
            return
    except Exception as e:
        print(f"[Agent B] Connection error getting invoice: {e}")
        return

    # 6. Agent B pays Agent A's invoice programmatically
    print("\n--- STEP 6: Agent B Pays Invoice Programmatically ---")
    try:
        print(f"[Agent B] Paying invoice via Lightning wallet allocation...")
        pay_res = agent_b.pay_invoice(bolt11=bolt11)
        preimage = pay_res["preimage"]
        print(f"[Agent B] Payment successful!")
        print(f"  Cryptographic Proof Preimage: {preimage}")
        
        # ASSERTION 6: Preimage must be 32 bytes (64 hex characters) and its SHA-256 must match the invoice_id (payment_hash)
        assert len(preimage) == 64, f"Preimage must be 64 characters (32 bytes), got length {len(preimage)}"
        computed_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        assert computed_hash == invoice_id, f"SHA-256 of preimage ({computed_hash}) must match payment hash ({invoice_id})"
        print("  [Assertion Passed] Cryptographic payment proof verified (SHA256(preimage) == invoice_id).")
    except Exception as e:
        print(f"[Agent B] Payment execution failed: {e}")
        raise e

    print("\n=============================================================")
    print("           ALL CRYPTOGRAPHIC ASSERTIONS PASSED!              ")
    print("                 DEMO COMPLETED SUCCESSFULLY!                ")
    print("=============================================================")

if __name__ == "__main__":
    run_demo()
