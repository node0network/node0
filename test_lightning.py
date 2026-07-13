import os, time, json
from fastapi.testclient import TestClient

# Setze Umgebungsvariablen fuer LNBits Mock-Testen
os.environ["NODE0_DB_PATH"] = "lightning_test.db"
os.environ["NODE0_DIFFICULTY"] = "0"
os.environ["NODE0_DOMAIN"] = "localhost:8000"
os.environ["LN_BACKEND"] = "lnbits"
os.environ["LN_LNBITS_URL"] = "https://mock-lnbits.com"
os.environ["LN_LNBITS_ADMIN_KEY"] = "mock_admin_key"
os.environ["LN_LNBITS_INVOICE_KEY"] = "mock_invoice_key"

from main import app, init_db
from node0_sdk import Node0SDK

def test_lightning_features():
    if os.path.exists("lightning_test.db"):
        os.remove("lightning_test.db")
    init_db()

    # Wir mocken die ausgehenden LNBits HTTP-Requests
    import requests
    client = TestClient(app)
    
    original_post = requests.post
    original_get = requests.get
    
    mock_invoices = {}

    def mock_post(url, json=None, headers=None, **kwargs):
        if "localhost:8000" in url:
            path = url.split("localhost:8000")[1]
            data_param = kwargs.get("data")
            if data_param is None and json is not None:
                import json as json_lib
                data_param = json_lib.dumps(json).encode("utf-8")
            fastapi_resp = client.post(path, content=data_param, headers=headers)
            class MockResponse:
                def __init__(self, r):
                    self.status_code = r.status_code
                    self.text = r.text
                    self._json = r.json()
                def json(self):
                    return self._json
            return MockResponse(fastapi_resp)

        # 3. Mock LNBits Decode Invoice (MUSS zuerst stehen, da Unterpfad von /payments)
        if "mock-lnbits.com/api/v1/payments/decode" in url:
            bolt11 = json["data"]
            # Extrahiere Betrag aus lnbc{amount}n1...
            amount = 100
            if "lnbc" in bolt11:
                try:
                    amount = int(bolt11.split("lnbc")[1].split("n1")[0])
                except Exception:
                    pass
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"amount_msat": amount * 1000, "payment_hash": "mock_decoded_hash"}
            return MockResponse()

        # 1. Mock LNBits Invoice Generation
        elif "mock-lnbits.com/api/v1/payments" in url and not json.get("out"):
            amount = json["amount"]
            payment_hash = f"mock_hash_{secrets_token()}"
            bolt11 = f"lnbc{amount}n1mockbolt11_{secrets_token()}"
            mock_invoices[payment_hash] = {
                "paid": False,
                "amount": amount,
                "bolt11": bolt11
            }
            class MockResponse:
                status_code = 201
                def json(self):
                    return {"payment_hash": payment_hash, "payment_request": bolt11}
            return MockResponse()
            
        # 2. Mock LNBits Pay Invoice
        elif "mock-lnbits.com/api/v1/payments" in url and json.get("out"):
            bolt11 = json["bolt11"]
            class MockResponse:
                status_code = 201
                def json(self):
                    return {"preimage": "mock_preimage_settled"}
            return MockResponse()

        return original_post(url, json=json, headers=headers, **kwargs)

    def mock_get(url, headers=None, **kwargs):
        if "localhost:8000" in url:
            path = url.split("localhost:8000")[1]
            fastapi_resp = client.get(path, headers=headers)
            class MockResponse:
                def __init__(self, r):
                    self.status_code = r.status_code
                    self.text = r.text
                    self._json = r.json()
                def json(self):
                    return self._json
            return MockResponse(fastapi_resp)

        # 4. Mock LNBits Invoice Check (Status API)
        if "mock-lnbits.com/api/v1/payments/" in url:
            payment_hash = url.split("payments/")[1]
            invoice_data = mock_invoices.get(payment_hash, {"paid": False, "amount": 0})
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"paid": invoice_data["paid"]}
            return MockResponse()
            
        return original_get(url, headers=headers, **kwargs)

    def secrets_token():
        import secrets
        return secrets.token_hex(8)

    requests.post = mock_post
    requests.get = mock_get

    try:
        print("[1] Initialisiere SDK...")
        sdk_payer = Node0SDK(node_url="http://localhost:8000")
        sdk_receiver = Node0SDK(node_url="http://localhost:8000")
        
        payer_id = sdk_payer.register(capabilities=["payer"])
        receiver_id = sdk_receiver.register(capabilities=["receiver"])
        print(f"  -> Payer: {payer_id}")
        print(f"  -> Receiver: {receiver_id}")

        # Setze Startguthaben fuer den Payer
        import sqlite3
        conn = sqlite3.connect("lightning_test.db")
        conn.execute("INSERT OR REPLACE INTO wallets (agent_id, balance_sats, daily_limit_sats, spent_today_sats, last_reset_at) VALUES (?, 5000, 1000, 0, ?)", (payer_id, time.time()))
        conn.commit()
        conn.close()

        print("\n[2] Generiere LNBits-Rechnung ueber API...")
        # Simuliert den Receiver-Agenten, der eine Rechnung erstellt
        invoice_resp = client.post("/payment/invoice", json={
            "receiver_id": receiver_id,
            "amount_sats": 250,
            "memo": "Lightning Test"
        })
        assert invoice_resp.status_code == 200
        inv_data = invoice_resp.json()
        bolt11 = inv_data["bolt11"]
        payment_hash = inv_data["invoice_id"]
        print(f"  -> Realer Bolt11 generiert: {bolt11}")
        print(f"  -> Payment Hash: {payment_hash}")

        print("\n[3] Payer bezahlt die Rechnung ueber `/payment/pay`...")
        pay_payload = {
            "sender_id": payer_id,
            "bolt11": bolt11,
            "timestamp": time.time(),
            "nonce": secrets_token()
        }
        
        # Signierung
        body_bytes = json.dumps(pay_payload).encode("utf-8")
        sig = sdk_payer.private_key.sign(body_bytes)
        sig_b64 = base64_b64encode(sig)
        
        pay_resp = client.post("/payment/pay", content=body_bytes, headers={"X-Signature": sig_b64, "Content-Type": "application/json"})
        print(f"  -> Server-Antwort pay: {pay_resp.status_code} - {pay_resp.text}")
        assert pay_resp.status_code == 200
        assert pay_resp.json()["status"] == "paid"

        print("\n[4] Verifiziere Kontostaende in der DB...")
        conn = sqlite3.connect("lightning_test.db")
        payer_wallet = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = ?", (payer_id,)).fetchone()
        receiver_wallet = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = ?", (receiver_id,)).fetchone()
        admin_wallet = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = 'admin@node0.network'").fetchone()
        conn.close()
        
        print(f"  -> Stand Payer: {payer_wallet[0]} Sats (Erwartet: 4750 - da 250 abgezogen)")
        print(f"  -> Stand Receiver: {receiver_wallet[0]} Sats (Erwartet: 5249 - da 250 minus 1 Satoshi Maut auf 5000 Startguthaben addiert)")
        print(f"  -> Stand Admin-Maut: {admin_wallet[0]} Sats (Erwartet: 1 Sat - 1 Maut vom Empfaenger)")
        
        assert payer_wallet[0] == 4750
        assert receiver_wallet[0] == 5249
        assert admin_wallet[0] == 1

        print("\n[4b] Teste externe Lightning-Zahlung (Bolt11 existiert nicht in DB)...")
        ext_bolt11 = "lnbc150n1mockbolt11_external"
        ext_pay_payload = {
            "sender_id": payer_id,
            "bolt11": ext_bolt11,
            "timestamp": time.time(),
            "nonce": secrets_token()
        }
        ext_body = json.dumps(ext_pay_payload).encode("utf-8")
        ext_sig = sdk_payer.private_key.sign(ext_body)
        ext_sig_b64 = base64_b64encode(ext_sig)
        
        ext_resp = client.post("/payment/pay", content=ext_body, headers={"X-Signature": ext_sig_b64, "Content-Type": "application/json"})
        print(f"  -> Server-Antwort externe pay: {ext_resp.status_code} - {ext_resp.text}")
        assert ext_resp.status_code == 200
        assert ext_resp.json()["status"] == "paid"
        
        conn = sqlite3.connect("lightning_test.db")
        payer_wallet_ext = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = ?", (payer_id,)).fetchone()
        admin_wallet_ext = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = 'admin@node0.network'").fetchone()
        conn.close()
        
        print(f"  -> Stand Payer nach ext: {payer_wallet_ext[0]} Sats (Erwartet: 4599 - 4750 minus 150 + 1 Satoshi Gebuehr)")
        print(f"  -> Stand Admin-Maut nach ext: {admin_wallet_ext[0]} Sats (Erwartet: 2 - 1 interne + 1 externe Maut)")
        assert payer_wallet_ext[0] == 4599
        assert admin_wallet_ext[0] == 2

        print("\n[5] Teste Deposit-Aufladung ueber LNBits Status-Check...")
        # Erstelle eine unbezahlte Rechnung
        deposit_resp = client.post("/payment/invoice", json={
            "receiver_id": payer_id,
            "amount_sats": 500,
            "memo": "Deposit 500 Sats"
        })
        dep_data = deposit_resp.json()
        dep_hash = dep_data["invoice_id"]
        
        # Simuliere, dass die Rechnung in LNBits als bezahlt markiert wird
        mock_invoices[dep_hash]["paid"] = True
        
        # Frage Status ab -> Server sollte die Zahlung erkennen und die Wallet gutschreiben
        status_resp = client.get(f"/payment/status/{dep_hash}")
        assert status_resp.status_code == 200
        assert status_resp.json()["status"] == "paid"
        
        conn = sqlite3.connect("lightning_test.db")
        payer_wallet_post = conn.execute("SELECT balance_sats FROM wallets WHERE agent_id = ?", (payer_id,)).fetchone()
        conn.close()
        print(f"  -> Neuer Stand Payer nach Deposit: {payer_wallet_post[0]} Sats (Erwartet: 5099)")
        assert payer_wallet_post[0] == 5099

        print("\n[OK] ALLE BITCOIN-LIGHTNING INTEGRATIONS-TESTS ERFOLGREICH BESTANDEN!")

    finally:
        # Bereinigung
        requests.post = original_post
        requests.get = original_get
        if os.path.exists("lightning_test.db"):
            os.remove("lightning_test.db")

def base64_b64encode(val):
    import base64
    return base64.b64encode(val).decode("utf-8")

if __name__ == "__main__":
    test_lightning_features()
