import time
import json
import base64
import requests
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519

class Node0SDK:
    """
    Offizielles Python-SDK fuer das node0-Protokoll der Moon York GmbH.
    Vereinfacht die Registrierung, Zahlung, Wissensfreigabe und Claims-Einreichung.
    """
    def __init__(self, node_url, private_key_hex=None):
        self.node_url = node_url.rstrip("/")
        if private_key_hex:
            self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key_hex = self.private_key.public_key().public_bytes_raw().hex()
        self.agent_id = None

    def get_private_key_hex(self):
        return self.private_key.private_bytes_raw().hex()

    def _signed_post(self, path, data):
        body_bytes = json.dumps(data).encode("utf-8")
        sig = self.private_key.sign(body_bytes)
        sig_b64 = base64.b64encode(sig).decode("utf-8")
        headers = {
            "X-Signature": sig_b64,
            "Content-Type": "application/json"
        }
        resp = requests.post(f"{self.node_url}{path}", data=body_bytes, headers=headers)
        return resp

    def register(self, capabilities=None, difficulty=2):
        if capabilities is None:
            capabilities = ["general"]
        import hashlib
        print(f"Berechne Proof of Work (scrypt, Schwierigkeit {difficulty})...")
        salt = b"node0-sybil-proof-salt"
        prefix = "0" * difficulty
        
        nonce_val = 0
        timestamp = time.time()
        while True:
            nonce_str = f"nonce_{nonce_val}"
            # Exakter Passwort-String analog zum Server:
            password = f"{self.public_key_hex}{json.dumps(capabilities)}{timestamp}{nonce_str}".encode("utf-8")
            key = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1, dklen=32)
            if key.hex().startswith(prefix):
                nonce = nonce_str
                break
            nonce_val += 1
            
        payload = {
            "public_key": self.public_key_hex,
            "capabilities": capabilities,
            "timestamp": timestamp,
            "nonce": nonce
        }
        resp = self._signed_post("/agent/register", payload)
        if resp.status_code == 200:
            self.agent_id = resp.json()["agent_id"]
            return self.agent_id
        else:
            raise Exception(f"Registrierung fehlgeschlagen: {resp.status_code} - {resp.text}")

    def pay_invoice(self, bolt11):
        if not self.agent_id:
            raise Exception("SDK nicht registriert. Bitte zuerst .register() aufrufen.")
        payload = {
            "sender_id": self.agent_id,
            "bolt11": bolt11,
            "timestamp": time.time(),
            "nonce": secrets.token_hex(16)
        }
        resp = self._signed_post("/payment/pay", payload)
        if resp.status_code == 200:
            return resp.json()
        else:
            raise Exception(f"Zahlung fehlgeschlagen: {resp.status_code} - {resp.text}")

    def submit_claim(self, statement):
        if not self.agent_id:
            raise Exception("SDK nicht registriert. Bitte zuerst .register() onrufen.")
        payload = {
            "author": self.agent_id,
            "statement": statement,
            "timestamp": time.time(),
            "nonce": secrets.token_hex(16)
        }
        resp = self._signed_post("/claim/submit", payload)
        if resp.status_code == 200:
            return resp.json()
        else:
            raise Exception(f"Claim-Einreichung fehlgeschlagen: {resp.status_code} - {resp.text}")

    def share_knowledge(self, topic, content):
        if not self.agent_id:
            raise Exception("SDK nicht registriert. Bitte zuerst .register() aufrufen.")
        payload = {
            "author": self.agent_id,
            "topic": topic,
            "content": content,
            "timestamp": time.time(),
            "nonce": secrets.token_hex(16)
        }
        resp = self._signed_post("/knowledge/share", payload)
        if resp.status_code == 200:
            return resp.json()
        else:
            raise Exception(f"Wissensteilung fehlgeschlagen: {resp.status_code} - {resp.text}")

    # Alias fuer Abwaertskompatibilitaet
    submit_knowledge = share_knowledge
