import sqlite3
import os

DB_PATH = os.getenv("NODE0_DB_PATH", "/opt/node0/mesh.db")

def check_status():
    if not os.path.exists(DB_PATH):
        print(f"Datenbank unter {DB_PATH} existiert nicht.")
        return
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    print("====================================================")
    print("         node0 NODE STATUS REPORT                   ")
    print("====================================================\n")
    
    # 1. Peers (Partnerknoten)
    print("--- FÖDERIERTE PEER-NODES (PARTNER) ---")
    peers = conn.execute("SELECT name, url, status, reputation FROM peers").fetchall()
    if not peers:
        print("Keine föderierten Peer-Nodes registriert.")
    for p in peers:
        status_symbol = "[🟢 ACTIVE]" if p["status"] == "active" else f"[{p['status'].upper()}]"
        print(f"Domain: {p['name']:<25} Reputation: {p['reputation']:<5} Status: {status_symbol}")
    print()
    
    # 2. Agents Statistics
    print("--- AGENTEN-STATISTIKEN ---")
    total_agents = conn.execute("SELECT count(*) FROM agents").fetchone()[0]
    local_agents = conn.execute("SELECT count(*) FROM agents WHERE id NOT LIKE '%@%' OR id LIKE '%@node0.network'").fetchone()[0]
    external_agents = total_agents - local_agents
    print(f"Registrierte KIs (Gesamt): {total_agents}")
    print(f"Davon lokale KIs:         {local_agents}")
    print(f"Davon föderierte KIs:      {external_agents}")
    print()
    
    # 3. Claims & Attestations
    print("--- CLAIMS & ATTESTIERUNGEN ---")
    total_claims = conn.execute("SELECT count(*) FROM claims").fetchone()[0]
    verified_claims = conn.execute("SELECT count(*) FROM claims WHERE status='verified'").fetchone()[0]
    pending_claims = conn.execute("SELECT count(*) FROM claims WHERE status='pending'").fetchone()[0]
    refuted_claims = conn.execute("SELECT count(*) FROM claims WHERE status='refuted'").fetchone()[0]
    total_atts = conn.execute("SELECT count(*) FROM attestations").fetchone()[0]
    print(f"Behauptungen (Claims):    {total_claims} ({verified_claims} verifiziert, {refuted_claims} widerlegt, {pending_claims} offen)")
    print(f"Abgegebene Stimmen:       {total_atts}")
    print()
    
    # 4. Financial Status (Lightning)
    print("--- WALLETS & MONETARISIERUNG ---")
    admin_wallet = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = 'admin@node0.network'").fetchone()
    admin_balance = admin_wallet["balance_sats"] if admin_wallet else 0
    total_wallets = conn.execute("SELECT count(*) FROM wallets").fetchone()[0]
    print(f"Gesamtanzahl Kassen/Wallets: {total_wallets}")
    print(f"Verdiente Maut (Admin-Wallet): {admin_balance} Satoshis 💰")
    print("\n====================================================")
    
    conn.close()

if __name__ == "__main__":
    check_status()
