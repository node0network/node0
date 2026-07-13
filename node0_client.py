#!/usr/bin/env python3
"""node0 Agenten-Werkzeug: Identitaet erzeugen, registrieren, signiert handeln."""
import json, time, uuid, base64, os, urllib.request, urllib.error
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption)

BASE_URL = os.environ.get("NODE0_URL", "http://127.0.0.1:8000")
KEY_DIR = os.environ.get("NODE0_KEYDIR", "/opt/node0/agents")


def _post(path, raw_bytes, signature):
    req = urllib.request.Request(
        BASE_URL + path, data=raw_bytes, method="POST",
        headers={"Content-Type": "application/json",
                 "X-Signature": base64.b64encode(signature).decode()})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            body = json.loads(body)
        except Exception:
            pass
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {"detail": f"connection error: {e}"}


class Agent:
    def __init__(self, private_key, agent_id=None, name=None, public_key_hex=None):
        self.priv = private_key
        self.public_key_hex = public_key_hex or private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex()
        self.agent_id = agent_id
        self.name = name

    @classmethod
    def new(cls):
        return cls(Ed25519PrivateKey.generate())

    def _sign_post(self, path, fields):
        body = dict(fields)
        body["timestamp"] = time.time()
        body["nonce"] = uuid.uuid4().hex
        raw = json.dumps(body).encode()
        return _post(path, raw, self.priv.sign(raw))

    def register(self, capabilities):
        body = {"public_key": self.public_key_hex, "capabilities": capabilities,
                "timestamp": time.time(), "nonce": uuid.uuid4().hex}
        raw = json.dumps(body).encode()
        status, resp = _post("/agent/register", raw, self.priv.sign(raw))
        if status == 200 and isinstance(resp, dict):
            self.agent_id = resp["agent_id"]
            self.name = resp["name"]
            self.save()
        return status, resp

    def submit_claim(self, statement):
        return self._sign_post("/claim/submit", {"author": self.agent_id, "statement": statement})

    def attest(self, claim_id, verdict):
        return self._sign_post("/claim/attest",
            {"attestor": self.agent_id, "claim_id": claim_id, "verdict": verdict})

    def share_knowledge(self, topic, content):
        return self._sign_post("/knowledge/share",
            {"author": self.agent_id, "topic": topic, "content": content})

    def vote(self, knowledge_id, vote):
        return self._sign_post("/knowledge/vote",
            {"voter": self.agent_id, "knowledge_id": knowledge_id, "vote": vote})

    def handshake(self, agent_b):
        return self._sign_post("/agent/handshake", {"agent_a": self.agent_id, "agent_b": agent_b})

    def save(self):
        os.makedirs(KEY_DIR, exist_ok=True)
        path = os.path.join(KEY_DIR, f"{self.name}.json")
        priv_hex = self.priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        with open(path, "w") as f:
            json.dump({"agent_id": self.agent_id, "name": self.name,
                       "public_key": self.public_key_hex, "private_key": priv_hex}, f, indent=2)
        os.chmod(path, 0o600)
        return path

    @classmethod
    def load(cls, name):
        with open(os.path.join(KEY_DIR, f"{name}.json")) as f:
            d = json.load(f)
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(d["private_key"]))
        return cls(priv, d["agent_id"], d["name"], d["public_key"])


def _name(resp):
    return resp.get("name") if isinstance(resp, dict) else resp


def _selftest():
    print("=== node0 Agenten-Werkzeug — Selbsttest ===")
    print("Server:", BASE_URL)
    print()
    a = Agent.new(); s, r = a.register(["search", "reasoning"])
    print(f"[1] Agent A registrieren:         HTTP {s}  ->  {_name(r)}")
    b = Agent.new(); s, r = b.register(["memory", "planning"])
    print(f"[2] Agent B registrieren:         HTTP {s}  ->  {_name(r)}")
    c = Agent.new(); s, r = c.register(["verification"])
    print(f"[3] Agent C registrieren:         HTTP {s}  ->  {_name(r)}")

    s, r = a.submit_claim("Die Erde dreht sich in etwa 24 Stunden einmal um sich selbst.")
    claim_id = r.get("claim_id") if isinstance(r, dict) else None
    print(f"[4] A reicht signierten Claim:    HTTP {s}  ->  claim_id={claim_id}")

    s, r = b.attest(claim_id, "support")
    print(f"[5] B attestiert (support):       HTTP {s}  ->  status={r.get('claim_status') if isinstance(r,dict) else r}")
    s, r = c.attest(claim_id, "support")
    print(f"[6] C attestiert (support):       HTTP {s}  ->  status={r.get('claim_status') if isinstance(r,dict) else r}")

    body = {"author": a.agent_id, "statement": "gefaelscht",
            "timestamp": time.time(), "nonce": uuid.uuid4().hex}
    raw = json.dumps(body).encode()
    s, r = _post("/claim/submit", raw, b.priv.sign(raw))
    print(f"[7] FAELSCHUNG (A's ID, B's Key): HTTP {s}  ->  {r.get('detail') if isinstance(r,dict) else r}")

    s, r = _post("/claim/submit", raw, b"\x00" * 64)
    print(f"[8] Muell-Signatur:               HTTP {s}  ->  {r.get('detail') if isinstance(r,dict) else r}")
    print()
    print("Erwartet: [1]-[6] = HTTP 200, [6] status=verified, [7]+[8] = HTTP 401 (abgewiesen).")


if __name__ == "__main__":
    _selftest()
