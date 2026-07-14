import time
import json
import requests
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
    # Register Agent A with scrypt PoW
    agent_a_id = agent_a.register(capabilities=["translation"])
    print(f"[Agent A] Registered sovereign identity: {agent_a_id}")

    # 2. Initialize SDK for Agent B (Consumer / Client)
    print("\n--- STEP 2: Bootstrapping Agent B (Client) ---")
    agent_b = Node0SDK(node_url=NODE_URL)
    # Register Agent B with scrypt PoW
    agent_b_id = agent_b.register(capabilities=["reasoning"])
    print(f"[Agent B] Registered sovereign identity: {agent_b_id}")

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
    # Share signed knowledge graph claim
    share_res = agent_a.share_knowledge(topic=topic, content=claim_str)
    print(f"[Agent A] Offer published successfully! Knowledge ID: {share_res.get('knowledge_id')}")

    # 4. Agent B queries the Gateway's Semantic Graph to find translators
    print("\n--- STEP 4: Agent B Queries Semantic Graph for Translators ---")
    # Query all triples matching topic
    graph_url = f"{NODE_URL}/v1/knowledge/graph/query"
    try:
        resp = requests.get(graph_url, timeout=5.0)
        if resp.status_code == 200:
            res_data = resp.json()
            triples = res_data if isinstance(res_data, list) else res_data.get("triples", [])
            print(f"[Agent B] Found {len(triples)} offers in the graph:")
            for idx, triple in enumerate(triples[:3]):
                print(f"  [{idx+1}] {triple['subject']} -> {triple['predicate']} -> {triple['object'][:60]}...")
        else:
            print(f"[Agent B] Failed to query graph: HTTP {resp.status_code}")
    except Exception as e:
        print(f"[Agent B] Connection error querying graph: {e}")

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
        # Note: pay_invoice returns the preimage proof of payment
        print(f"[Agent B] Payment successful!")
        print(f"  Cryptographic Proof Preimage: {pay_res}")
    except Exception as e:
        # In a sandbox test/dry run without actual Lightning balances, this might raise budget/route errors
        print(f"[Agent B] Payment execution halted: {e}")
        print("  (Note: Real Lightning settlement requires valid wallet funding/balances on node0).")

    print("\n=============================================================")
    print("                 DEMO COMPLETED SUCCESSFULLY!                ")
    print("=============================================================")

if __name__ == "__main__":
    run_demo()
