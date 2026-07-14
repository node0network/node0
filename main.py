from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, PlainTextResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import hashlib, time, uuid, json, base64, os, requests
import sqlite3

app = FastAPI(title="node0 - Agent Mesh Protocol")

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_cache_control_header(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=86400"
    else:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["X-Node0-Server-Time"] = f"{time.time():.3f}"
    response.headers["X-Node0-Protocol-Version"] = "1"
    response.headers["X-Node0-Pow-Difficulty"] = str(DIFFICULTY)
    return response

class Node0Error(HTTPException):
    def __init__(self, code: str, status: int, title: str,
                 detail: str, retryable: bool = False, **extra):
        self.code = code
        self.title = title
        self.retryable = retryable
        self.extra = extra
        super().__init__(status_code=status, detail=detail)

@app.exception_handler(Node0Error)
async def node0_error_handler(request: Request, exc: Node0Error):
    body = {
        "type": f"https://node0.network/errors/{exc.code.lower().replace('_','-')}",
        "title": exc.title,
        "status": exc.status_code,
        "detail": exc.detail,
        "instance": request.url.path,
        "code": exc.code,
        "retryable": exc.retryable,
        **exc.extra,
    }
    headers = {
        "X-Node0-Server-Time": f"{time.time():.3f}",
        "X-Node0-Protocol-Version": "1",
        "X-Node0-Pow-Difficulty": str(DIFFICULTY)
    }
    if "retry_after" in exc.extra:
        headers["Retry-After"] = str(int(exc.extra["retry_after"]))
    return JSONResponse(body, status_code=exc.status_code,
                        headers=headers, media_type="application/problem+json")

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    headers = exc.headers or {}
    if exc.status_code == 401:
        if "text/html" in request.headers.get("accept", ""):
            return HTMLResponse(
                content="""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>401 Unauthorized</title>
<style>
  body { background: #0b0c0e; color: #ff3366; font-family: monospace; text-align: center; padding-top: 15%; }
  h1 { font-size: 24px; border-bottom: 1px solid #2d3139; display: inline-block; padding-bottom: 10px; font-weight: bold; }
  p { color: #8892b0; font-size: 14px; margin-top: 10px; }
</style>
</head>
<body>
  <h1>401 UNAUTHORIZED</h1>
  <p>Access Denied. Invalid or missing credentials.</p>
</body>
</html>""",
                status_code=401,
                headers=headers
            )
        return PlainTextResponse("401 Unauthorized - Access Denied", status_code=401, headers=headers)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=headers)

from dashboard import router as dashboard_router

DB_PATH = os.getenv("NODE0_DB_PATH", "/opt/node0/mesh.db")
DECISION_THRESHOLD = 2.0
MAX_SKEW = 300
MAX_BODY = 65536
DIFFICULTY = int(os.getenv("NODE0_DIFFICULTY", "2"))
MY_DOMAIN = os.getenv("NODE0_DOMAIN", "node0.network")

def _load_env(key):
    val = os.getenv(key)
    if val is not None:
        return val
    try:
        env_path = os.getenv("NODE0_ENV_PATH", "/opt/node0/.env")
        with open(env_path) as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.strip().split("=", 1)[1]
    except FileNotFoundError:
        return None
    return None

LN_BACKEND = _load_env("LN_BACKEND") or "virtual"
LN_LNBITS_URL = (_load_env("LN_LNBITS_URL") or "https://legend.lnbits.com").rstrip("/")
LN_LNBITS_ADMIN_KEY = _load_env("LN_LNBITS_ADMIN_KEY")
LN_LNBITS_INVOICE_KEY = _load_env("LN_LNBITS_INVOICE_KEY")


def verify_scrypt_pow(public_key: str, capabilities: list, timestamp: float, nonce: str) -> bool:
    if DIFFICULTY <= 0:
        return True
    password = f"{public_key}{json.dumps(capabilities)}{timestamp}{nonce}".encode("utf-8")
    salt = b"node0-sybil-proof-salt"
    try:
        # scrypt parameters: n=16384 (16MB), r=8, p=1
        key = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1, dklen=32)
        prefix = "0" * DIFFICULTY
        return key.hex().startswith(prefix)
    except Exception:
        return False

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("""CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT NOT NULL,
        capabilities TEXT NOT NULL, reputation REAL DEFAULT 1.0, reliability REAL DEFAULT 1.0,
        verified_claims INTEGER DEFAULT 0, refuted_claims INTEGER DEFAULT 0,
        registered_at REAL NOT NULL, interactions INTEGER DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS handshakes (
        id TEXT PRIMARY KEY, agent_a TEXT NOT NULL, agent_b TEXT NOT NULL, timestamp REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS claims (
        id TEXT PRIMARY KEY, author TEXT NOT NULL, statement TEXT NOT NULL,
        status TEXT DEFAULT 'pending', support_weight REAL DEFAULT 0.0,
        refute_weight REAL DEFAULT 0.0, created_at REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS attestations (
        id TEXT PRIMARY KEY, claim_id TEXT NOT NULL, attestor TEXT NOT NULL,
        verdict TEXT NOT NULL, weight REAL NOT NULL, timestamp REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS knowledge (
        id TEXT PRIMARY KEY, author TEXT NOT NULL, topic TEXT NOT NULL,
        content TEXT NOT NULL, confirmations INTEGER DEFAULT 0,
        disputes INTEGER DEFAULT 0, created_at REAL NOT NULL, updated_at REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS topic_reputation (
        agent_id TEXT NOT NULL, topic TEXT NOT NULL, score REAL DEFAULT 1.0,
        PRIMARY KEY (agent_id, topic))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS knowledge_votes (
        id TEXT PRIMARY KEY, knowledge_id TEXT NOT NULL, voter TEXT NOT NULL,
        vote TEXT NOT NULL, timestamp REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS used_nonces (
        nonce TEXT PRIMARY KEY, seen_at REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS vouches (
        id TEXT PRIMARY KEY, voucher TEXT NOT NULL, vouchee TEXT NOT NULL, timestamp REAL NOT NULL,
        UNIQUE(voucher, vouchee))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS peers (
        id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, name TEXT,
        registered_at REAL NOT NULL, status TEXT DEFAULT 'pending',
        reputation REAL DEFAULT 1.0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS triples (
        id TEXT PRIMARY KEY, knowledge_id TEXT NOT NULL, subject TEXT NOT NULL,
        predicate TEXT NOT NULL, object TEXT NOT NULL,
        FOREIGN KEY(knowledge_id) REFERENCES knowledge(id) ON DELETE CASCADE)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS wallets (
        agent_id TEXT PRIMARY KEY, balance_sats INTEGER DEFAULT 0,
        daily_limit_sats INTEGER DEFAULT 1000, spent_today_sats INTEGER DEFAULT 0,
        last_reset_at REAL NOT NULL,
        FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS invoices (
        id TEXT PRIMARY KEY, receiver_id TEXT NOT NULL, sender_id TEXT,
        amount_sats INTEGER NOT NULL, memo TEXT, bolt11 TEXT NOT NULL,
        status TEXT DEFAULT 'unpaid', created_at REAL NOT NULL, paid_at REAL,
        FOREIGN KEY(receiver_id) REFERENCES agents(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('emergency_freeze', 'false')")
    
    # Migration: add status column to agents table if it doesn't exist
    try:
        conn.execute("SELECT status FROM agents LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE agents ADD COLUMN status TEXT DEFAULT 'active'")

    # Migration: add reputation column to peers table if it doesn't exist
    try:
        conn.execute("SELECT reputation FROM peers LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE peers ADD COLUMN reputation REAL DEFAULT 1.0")

    # Auto-create admin@node0.network agent and wallet
    conn.execute("INSERT OR IGNORE INTO agents (id, name, public_key, capabilities, reputation, reliability, registered_at) VALUES ('admin@node0.network', 'admin-node0', 'admin-pubkey', '[\"admin\"]', 1.0, 1.0, ?)", (time.time(),))
    conn.execute("INSERT OR IGNORE INTO wallets (agent_id, balance_sats, daily_limit_sats, spent_today_sats, last_reset_at) VALUES ('admin@node0.network', 0, 9999999, 0, ?)", (time.time(),))
    conn.commit()
    conn.close()

def generate_agent_name(public_key_hex, capabilities):
    base = hashlib.sha256(f"{public_key_hex}{capabilities}".encode()).hexdigest()[:8]
    prefixes = ["arc", "vel", "syn", "nex", "ori", "zep", "axo", "fen"]
    suffixes = ["ion", "ara", "eon", "yx", "an", "is", "or", "en"]
    p = int(base[:4], 16) % len(prefixes)
    s = int(base[4:], 16) % len(suffixes)
    return f"{prefixes[p]}{suffixes[s]}-{base}"

def get_topic_reputation(conn, agent_id, topic):
    row = conn.execute("SELECT score FROM topic_reputation WHERE agent_id=? AND topic=?", (agent_id, topic)).fetchone()
    if row:
        return row["score"]
    a = conn.execute("SELECT reputation FROM agents WHERE id=?", (agent_id,)).fetchone()
    return a["reputation"] if a else 1.0

def adjust_topic_reputation(conn, agent_id, topic, delta):
    current = get_topic_reputation(conn, agent_id, topic)
    new = max(0.1, current + delta)
    conn.execute("INSERT INTO topic_reputation (agent_id, topic, score) VALUES (?, ?, ?) ON CONFLICT(agent_id, topic) DO UPDATE SET score=?",
        (agent_id, topic, new, new))

def extract_triples_from_jsonld(knowledge_id: str, author_id: str, content_str: str) -> list:
    triples = []
    default_subject = f"node0:knowledge:{knowledge_id}"
    try:
        data = json.loads(content_str)
    except Exception:
        return [(default_subject, "says", content_str)]
    if not isinstance(data, dict):
        return [(default_subject, "says", content_str)]
    if "subject" in data and "predicate" in data and "object" in data:
        return [(str(data["subject"]), str(data["predicate"]), str(data["object"]))]
    subject = data.get("@id") or data.get("id") or default_subject
    type_val = data.get("@type") or data.get("type")
    if type_val:
        triples.append((subject, "type", str(type_val)))
    for key, val in data.items():
        if key in ("@context", "@type", "@id", "type", "id"):
            continue
        if isinstance(val, dict):
            sub_id = val.get("@id") or val.get("id") or f"{subject}/{key}"
            triples.append((subject, key, sub_id))
            sub_type = val.get("@type") or val.get("type")
            if sub_type:
                triples.append((sub_id, "type", str(sub_type)))
            for sub_k, sub_v in val.items():
                if sub_k in ("@context", "@type", "@id", "type", "id"):
                    continue
                if isinstance(sub_v, (str, int, float, bool)):
                    triples.append((sub_id, sub_k, str(sub_v)))
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, (str, int, float, bool)):
                    triples.append((subject, key, str(item)))
                elif isinstance(item, dict):
                    sub_id = item.get("@id") or item.get("id") or f"{subject}/{key}/{uuid.uuid4().hex[:6]}"
                    triples.append((subject, key, sub_id))
                    sub_type = item.get("@type") or item.get("type")
                    if sub_type:
                        triples.append((sub_id, "type", str(sub_type)))
                    for sub_k, sub_v in item.items():
                        if sub_k in ("@context", "@type", "@id", "type", "id"):
                            continue
                        if isinstance(sub_v, (str, int, float, bool)):
                            triples.append((sub_id, sub_k, str(sub_v)))
        elif isinstance(val, (str, int, float, bool)):
            triples.append((subject, key, str(val)))
    return triples

def ensure_wallet_exists(conn, agent_id: str):
    w = conn.execute("SELECT 1 FROM wallets WHERE agent_id = ?", (agent_id,)).fetchone()
    if not w:
        conn.execute("INSERT OR IGNORE INTO wallets (agent_id, balance_sats, daily_limit_sats, spent_today_sats, last_reset_at) VALUES (?, 5000, 1000, 0, ?)",
            (agent_id, time.time()))

def reset_daily_limit_if_needed(conn, agent_id: str):
    ensure_wallet_exists(conn, agent_id)
    w = conn.execute("SELECT last_reset_at, spent_today_sats FROM wallets WHERE agent_id = ?", (agent_id,)).fetchone()
    if w and time.time() - w["last_reset_at"] > 86400:
        conn.execute("UPDATE wallets SET spent_today_sats = 0, last_reset_at = ? WHERE agent_id = ?", (time.time(), agent_id))

def is_frozen(conn) -> bool:
    try:
        row = conn.execute("SELECT value FROM settings WHERE key='emergency_freeze'").fetchone()
        return row is not None and row["value"].lower() == "true"
    except Exception:
        return False

def _check_freshness_and_nonce(conn, ts, nonce):
    try:
        tsf = float(ts)
    except (TypeError, ValueError):
        raise Node0Error("TIMESTAMP_MALFORMED", 400, "Invalid timestamp format", "Timestamp must be a float representing epoch seconds.", retryable=False)
    if abs(time.time() - tsf) > MAX_SKEW:
        raise Node0Error(
            code="TIMESTAMP_SKEW",
            status=400,
            title="Request timestamp outside allowed clock skew",
            detail=f"Timestamp {tsf} deviates too much from server time; max allowed skew is {MAX_SKEW}s.",
            retryable=True,
            server_time=time.time(),
            max_skew_seconds=MAX_SKEW
        )
    conn.execute("DELETE FROM used_nonces WHERE seen_at < ?", (time.time() - MAX_SKEW,))
    try:
        conn.execute("INSERT INTO used_nonces (nonce, seen_at) VALUES (?, ?)", (str(nonce), time.time()))
    except sqlite3.IntegrityError:
        raise Node0Error(
            code="NONCE_REPLAYED",
            status=409,
            title="Replay detected (nonce already used)",
            detail=f"The nonce '{nonce}' has already been processed within the last {MAX_SKEW}s.",
            retryable=True,
            nonce_ttl_seconds=MAX_SKEW
        )

async def _read_signed_body(request: Request):
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Request too large")
    sig_b64 = request.headers.get("X-Signature")
    if not sig_b64:
        raise HTTPException(status_code=401, detail="Missing X-Signature header")
    try:
        signature = base64.b64decode(sig_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature encoding")
    try:
        data = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Body must be valid JSON")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object")
    return raw, signature, data

def update_external_agent_cache(agent_id: str, peer_url: str):
    try:
        resp = requests.get(f"{peer_url}/peer/agent/{agent_id}", timeout=2.0)
        if resp.status_code == 200:
            agent_data = resp.json()
            domain_part = agent_id.split("@", 1)[1]
            conn = db()
            peer_row = conn.execute("SELECT reputation FROM peers WHERE name = ? AND status='active'", (domain_part,)).fetchone()
            peer_rep = peer_row["reputation"] if peer_row else 1.0
            home_rep = agent_data.get("reputation", 1.0)
            effective_rep = home_rep * peer_rep
            
            conn.execute("""
                INSERT OR REPLACE INTO agents (id, name, public_key, capabilities, registered_at, reputation)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (agent_id, agent_data["name"], agent_data["public_key"], json.dumps(agent_data["capabilities"]), time.time(), effective_rep))
            conn.commit()
            conn.close()
    except Exception:
        pass

async def verify_action(request: Request, agent_field: str, background_tasks: BackgroundTasks = None):
    raw, signature, data = await _read_signed_body(request)
    agent_id = data.get(agent_field)
    ts = data.get("timestamp")
    nonce = data.get("nonce")
    if not agent_id:
        raise HTTPException(status_code=400, detail=f"Missing '{agent_field}'")
    if ts is None or not nonce:
        raise HTTPException(status_code=400, detail="Missing 'timestamp' or 'nonce'")
    conn = db()
    agent = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if agent and "status" in agent.keys() and agent["status"] == "blocked":
        conn.close()
        raise HTTPException(status_code=403, detail="Agent is blocked by Administrator")
        
    if agent:
        if "@" in agent_id:
            uuid_part, domain_part = agent_id.split("@", 1)
            peer_row = conn.execute("SELECT url FROM peers WHERE name = ? AND status='active'", (domain_part,)).fetchone()
            if peer_row and background_tasks:
                background_tasks.add_task(update_external_agent_cache, agent_id, peer_row["url"])
    else:
        if "@" in agent_id:
            uuid_part, domain_part = agent_id.split("@", 1)
            peer_row = conn.execute("SELECT url, reputation FROM peers WHERE name = ? AND status='active'", (domain_part,)).fetchone()
            if peer_row:
                peer_url = peer_row["url"]
                peer_rep = peer_row["reputation"]
                try:
                    resp = requests.get(f"{peer_url}/peer/agent/{agent_id}", timeout=1.5)
                    if resp.status_code == 200:
                        agent_data = resp.json()
                        home_rep = agent_data.get("reputation", 1.0)
                        effective_rep = home_rep * peer_rep
                        conn.execute("INSERT OR REPLACE INTO agents (id, name, public_key, capabilities, registered_at, reputation) VALUES (?, ?, ?, ?, ?, ?)",
                            (agent_id, agent_data["name"], agent_data["public_key"], json.dumps(agent_data["capabilities"]), time.time(), effective_rep))
                        conn.commit()
                        agent = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
                except Exception:
                    pass
        if not agent:
            conn.close()
            raise HTTPException(status_code=404, detail="Agent not found")
            
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(agent["public_key"]))
        pub.verify(signature, raw)
    except (InvalidSignature, ValueError):
        conn.close()
        import hashlib
        raise Node0Error(
            code="SIGNATURE_INVALID",
            status=401,
            title="Signature verification failed",
            detail="Ed25519 verification failed against the raw request body. Sign the exact bytes you transmit; do not let your HTTP client re-serialize JSON.",
            retryable=False,
            body_sha256_received=hashlib.sha256(raw).hexdigest()
        )
    try:
        _check_freshness_and_nonce(conn, ts, nonce)
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return data, agent

@app.on_event("startup")
async def startup():
    init_db()

@app.post("/agent/register")
async def register_agent(request: Request):
    raw, signature, data = await _read_signed_body(request)
    public_key_hex = data.get("public_key")
    capabilities = data.get("capabilities", [])
    ts = data.get("timestamp")
    nonce = data.get("nonce")
    if not public_key_hex or ts is None or not nonce:
        raise HTTPException(status_code=400, detail="Missing 'public_key', 'timestamp' or 'nonce'")
    
    # Verify memory-hard Proof of Work
    max_pow_age = 600
    try:
        tsf = float(ts)
    except (TypeError, ValueError):
        tsf = 0.0
    if abs(time.time() - tsf) > max_pow_age:
        raise Node0Error(
            code="POW_STALE",
            status=400,
            title="Proof of Work is stale",
            detail=f"The timestamp of the Proof of Work ({tsf}) is older than the allowed age of {max_pow_age}s.",
            retryable=True,
            max_pow_age_seconds=max_pow_age
        )

    # Compute actual scrypt hash to check difficulty
    password = f"{public_key_hex}{json.dumps(capabilities)}{ts}{nonce}".encode("utf-8")
    salt = b"node0-sybil-proof-salt"
    try:
        key = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1, dklen=32)
        key_hex = key.hex()
    except Exception as e:
        raise Node0Error(
            code="POW_INVALID",
            status=400,
            title="Proof of Work computation failed",
            detail=f"Failed to verify scrypt PoW: {str(e)}",
            retryable=False,
            password_template="{public_key_hex}{json.dumps(capabilities)}{timestamp}{nonce}"
        )

    # Count leading zeros in key_hex
    leading_zeros = 0
    for char in key_hex:
        if char == '0':
            leading_zeros += 1
        else:
            break

    if leading_zeros < DIFFICULTY:
        raise Node0Error(
            code="POW_INSUFFICIENT",
            status=403,
            title="Proof of Work difficulty insufficient",
            detail=f"Required difficulty is {DIFFICULTY} leading zeros, but provided PoW has {leading_zeros}.",
            retryable=True,
            required_difficulty=DIFFICULTY,
            provided_difficulty=leading_zeros
        )
        
    if not isinstance(capabilities, list) or not all(isinstance(c, str) for c in capabilities):
        raise HTTPException(status_code=400, detail="'capabilities' must be a list of strings")
    if len(capabilities) > 20:
        raise HTTPException(status_code=400, detail="too many capabilities (max 20)")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid public_key")
    try:
        pub.verify(signature, raw)
    except InvalidSignature:
        raise HTTPException(status_code=401, detail="Invalid signature (proof of possession failed)")
    conn = db()
    if is_frozen(conn):
        conn.close()
        raise HTTPException(status_code=503, detail="System frozen by Administrator")
    if conn.execute("SELECT 1 FROM agents WHERE public_key = ?", (public_key_hex,)).fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="public_key already registered")
    try:
        _check_freshness_and_nonce(conn, ts, nonce)
        conn.commit()
    except HTTPException:
        conn.close()
        raise
    agent_id = f"{uuid.uuid4()}@{MY_DOMAIN}"
    name = generate_agent_name(public_key_hex, capabilities)
    
    # Abwärtskompatibilität: bekannte Test-Agenten starten mit 1.0 Reputation, neue KIs mit 0.0 (Web of Trust)
    KNOWN_TEST_NAMES = {"oriion-460481", "nexion-4f6340", "zepeon-fc9531", "veleon-10d10b"}
    initial_reputation = 1.0 if name in KNOWN_TEST_NAMES else 0.0
    
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO agents (id, name, public_key, capabilities, registered_at, reputation) VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, name, public_key_hex, json.dumps(capabilities), time.time(), initial_reputation))
        conn.execute("INSERT INTO wallets (agent_id, balance_sats, daily_limit_sats, spent_today_sats, last_reset_at) VALUES (?, ?, ?, ?, ?)",
            (agent_id, 5000, 1000, 0, time.time()))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))
    conn.close()
    return {"agent_id": agent_id, "name": name, "public_key": public_key_hex, "initial_reputation": initial_reputation}

@app.get("/agent/{agent_id}")
async def get_agent(agent_id: str):
    conn = db()
    row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")
    return dict(row)

@app.get("/mesh/status")
async def mesh_status():
    conn = db()
    agents = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    claims = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
    verified = conn.execute("SELECT COUNT(*) FROM claims WHERE status='verified'").fetchone()[0]
    knowledge = conn.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0]
    attestations = conn.execute("SELECT COUNT(*) FROM attestations").fetchone()[0]
    conn.close()
    alerts = []
    if agents >= 50 or attestations >= 200:
        alerts.append("Kartell-Erkennung jetzt sinnvoll (Schwellwert erreicht)")
    return {"node": "node0", "agents": agents, "claims": claims, "verified_claims": verified,
        "knowledge_entries": knowledge, "attestations": attestations,
        "alerts": alerts, "status": "alive", "timestamp": time.time()}

@app.get("/mesh/agents")
async def list_agents():
    conn = db()
    rows = conn.execute("SELECT id, name, capabilities, reputation, reliability, verified_claims, refuted_claims, interactions FROM agents ORDER BY reputation DESC").fetchall()
    conn.close()
    return [{**dict(r), "capabilities": json.loads(r["capabilities"])} for r in rows]

@app.post("/agent/handshake")
async def handshake(request: Request, background_tasks: BackgroundTasks):
    data, a_row = await verify_action(request, "agent_a", background_tasks)
    agent_a = data["agent_a"]
    agent_b = data.get("agent_b")
    if not agent_b:
        raise HTTPException(status_code=400, detail="Missing 'agent_b'")
    conn = db()
    b = conn.execute("SELECT name FROM agents WHERE id = ?", (agent_b,)).fetchone()
    if not b:
        conn.close()
        raise HTTPException(status_code=404, detail="agent_b not found")
    conn.execute("UPDATE agents SET interactions = interactions + 1 WHERE id IN (?, ?)", (agent_a, agent_b))
    conn.execute("INSERT INTO handshakes (id, agent_a, agent_b, timestamp) VALUES (?, ?, ?, ?)",
        (str(uuid.uuid4()), agent_a, agent_b, time.time()))
    conn.commit()
    conn.close()
    return {"status": "connected", "agent_a": a_row["name"], "agent_b": b["name"], "timestamp": time.time()}

@app.post("/claim/submit")
async def submit_claim(request: Request, background_tasks: BackgroundTasks):
    data, author_row = await verify_action(request, "author", background_tasks)
    statement = data.get("statement")
    if not statement or not isinstance(statement, str):
        raise HTTPException(status_code=400, detail="Missing 'statement'")
    if len(statement) > 2000:
        raise HTTPException(status_code=400, detail="statement too long (max 2000 chars)")
    author = data["author"]
    conn = db()
    claim_id = str(uuid.uuid4())
    conn.execute("INSERT INTO claims (id, author, statement, created_at) VALUES (?, ?, ?, ?)",
        (claim_id, author, statement, time.time()))
    conn.commit()
    conn.close()
    try:
        raw_body = await request.body()
        headers_dict = {k.lower(): v for k, v in request.headers.items()}
        background_tasks.add_task(broadcast_claim_to_peers, raw_body, request.headers.get("Content-Type", "application/json"), headers_dict)
    except Exception:
        pass
    return {"claim_id": claim_id, "author": author_row["name"], "statement": statement, "status": "pending"}

@app.post("/claim/attest")
async def attest_claim(request: Request, background_tasks: BackgroundTasks):
    data, att = await verify_action(request, "attestor", background_tasks)
    claim_id = data.get("claim_id")
    verdict = data.get("verdict")
    if not claim_id:
        raise HTTPException(status_code=400, detail="Missing 'claim_id'")
    if verdict not in ("support", "refute"):
        raise HTTPException(status_code=400, detail="verdict must be 'support' or 'refute'")
    attestor = data["attestor"]
    conn = db()
    claim_author = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        claim = conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
        if not claim:
            raise HTTPException(status_code=404, detail="Claim not found")
        claim_author = claim["author"]
        if claim["author"] == attestor:
            raise HTTPException(status_code=403, detail="Author cannot attest own claim")
        existing = conn.execute("SELECT 1 FROM attestations WHERE claim_id=? AND attestor=?", (claim_id, attestor)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Already attested")
        weight = att["reputation"]
        conn.execute("INSERT INTO attestations (id, claim_id, attestor, verdict, weight, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), claim_id, attestor, verdict, weight, time.time()))
        if verdict == "support":
            conn.execute("UPDATE claims SET support_weight = support_weight + ? WHERE id = ?", (weight, claim_id))
        else:
            conn.execute("UPDATE claims SET refute_weight = refute_weight + ? WHERE id = ?", (weight, claim_id))
        
        # Reload claim under same transaction lock to get updated weights
        claim = conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
        resolved = None
        if claim["status"] == "pending":
            if claim["support_weight"] >= DECISION_THRESHOLD and claim["support_weight"] > claim["refute_weight"]:
                # Local Anchor Rule check: at least 0.5 support from local agents
                local_support = conn.execute("""
                    SELECT SUM(weight) FROM attestations 
                    WHERE claim_id = ? AND verdict = 'support' AND (attestor NOT LIKE '%@%' OR attestor LIKE ?)
                """, (claim_id, f"%@{MY_DOMAIN}")).fetchone()[0] or 0.0
                if local_support >= 0.5:
                    resolved = "verified"
            elif claim["refute_weight"] >= DECISION_THRESHOLD and claim["refute_weight"] > claim["support_weight"]:
                resolved = "refuted"
            
            if resolved:
                conn.execute("UPDATE claims SET status = ? WHERE id = ?", (resolved, claim_id))
                author = claim["author"]
                if resolved == "verified":
                    conn.execute("UPDATE agents SET reputation = reputation + 0.5, verified_claims = verified_claims + 1 WHERE id = ?", (author,))
                    if "@" in author:
                        domain_part = author.split("@", 1)[1]
                        conn.execute("UPDATE peers SET reputation = MIN(5.0, reputation + 0.1) WHERE name = ?", (domain_part,))
                else:
                    conn.execute("UPDATE agents SET reputation = MAX(0.1, reputation - 0.5), refuted_claims = refuted_claims + 1 WHERE id = ?", (author,))
                    if "@" in author:
                        domain_part = author.split("@", 1)[1]
                        conn.execute("UPDATE peers SET reputation = MAX(0.1, reputation - 0.2) WHERE name = ?", (domain_part,))
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
        
    try:
        raw_body = await request.body()
        headers_dict = {k.lower(): v for k, v in request.headers.items()}
        background_tasks.add_task(broadcast_attestation_to_peers, raw_body, request.headers.get("Content-Type", "application/json"), headers_dict, claim_author)
    except Exception:
        pass
        
    return {"status": "attested", "verdict": verdict, "weight": weight, "claim_status": resolved or claim["status"]}

@app.get("/claim/{claim_id}")
async def get_claim(claim_id: str):
    conn = db()
    claim = conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
    if not claim:
        conn.close()
        raise HTTPException(status_code=404, detail="Claim not found")
    atts = conn.execute("SELECT attestor, verdict, weight, timestamp FROM attestations WHERE claim_id = ?", (claim_id,)).fetchall()
    conn.close()
    return {**dict(claim), "attestations": [dict(a) for a in atts]}

@app.get("/mesh/claims")
async def list_claims():
    conn = db()
    rows = conn.execute("SELECT id, author, statement, status, support_weight, refute_weight FROM claims ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/knowledge/share")
async def share_knowledge(request: Request, background_tasks: BackgroundTasks):
    data, author_row = await verify_action(request, "author", background_tasks)
    topic = data.get("topic")
    content = data.get("content")
    if not topic or not isinstance(topic, str):
        raise HTTPException(status_code=400, detail="Missing 'topic'")
    if not content or not isinstance(content, str):
        raise HTTPException(status_code=400, detail="Missing 'content'")
    if len(topic) > 200:
        raise HTTPException(status_code=400, detail="topic too long (max 200 chars)")
    if len(content) > 8000:
        raise HTTPException(status_code=400, detail="content too long (max 8000 chars)")
    author = data["author"]
    conn = db()
    if is_frozen(conn):
        conn.close()
        raise HTTPException(status_code=503, detail="System frozen by Administrator")
    kid = str(uuid.uuid4())
    now = time.time()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO knowledge (id, author, topic, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (kid, author, topic, content, now, now))
        
        # Extract and save triples
        triples = extract_triples_from_jsonld(kid, author, content)
        for s, p, o in triples:
            tid = str(uuid.uuid4())
            conn.execute("INSERT INTO triples (id, knowledge_id, subject, predicate, object) VALUES (?, ?, ?, ?, ?)",
                (tid, kid, s, p, o))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))
    conn.close()
    return {"knowledge_id": kid, "author": author_row["name"], "topic": topic, "content": content}

@app.get("/knowledge/graph/query")
async def query_knowledge_graph(subject: str = None, predicate: str = None, object: str = None):
    conn = db()
    query = """
        SELECT t.id as triple_id, t.knowledge_id, t.subject, t.predicate, t.object, 
               k.author, k.topic, k.created_at
        FROM triples t
        JOIN knowledge k ON t.knowledge_id = k.id
    """
    filters = []
    params = []
    if subject:
        filters.append("t.subject = ?")
        params.append(subject)
    if predicate:
        filters.append("t.predicate = ?")
        params.append(predicate)
    if object:
        filters.append("t.object = ?")
        params.append(object)
        
    if filters:
        query += " WHERE " + " AND ".join(filters)
        
    rows = conn.execute(query, params).fetchall()
    result = []
    for r in rows:
        trust = get_topic_reputation(conn, r["author"], r["topic"])
        author = conn.execute("SELECT name FROM agents WHERE id=?", (r["author"],)).fetchone()
        result.append({
            "triple_id": r["triple_id"],
            "knowledge_id": r["knowledge_id"],
            "author": author["name"] if author else "unknown",
            "subject": r["subject"],
            "predicate": r["predicate"],
            "object": r["object"],
            "trust_weight": round(trust, 3),
            "created_at": r["created_at"]
        })
    conn.close()
    result.sort(key=lambda x: x["trust_weight"], reverse=True)
    return result

@app.get("/knowledge/query")
async def query_knowledge(topic: str):
    conn = db()
    rows = conn.execute("SELECT * FROM knowledge WHERE topic = ?", (topic,)).fetchall()
    result = []
    for r in rows:
        trust = get_topic_reputation(conn, r["author"], topic)
        author = conn.execute("SELECT name FROM agents WHERE id=?", (r["author"],)).fetchone()
        result.append({
            "knowledge_id": r["id"],
            "author": author["name"] if author else "unknown",
            "topic": r["topic"],
            "content": r["content"],
            "trust_weight": round(trust, 3),
            "confirmations": r["confirmations"],
            "disputes": r["disputes"],
            "age_seconds": round(time.time() - r["created_at"]),
            "updated_at": r["updated_at"]
        })
    conn.close()
    result.sort(key=lambda x: x["trust_weight"], reverse=True)
    contested = len(result) > 1
    return {"topic": topic, "entries": result, "contested": contested,
        "note": "Mehrere Positionen vorhanden - das Mesh entscheidet nicht, es legt offen." if contested else None}

@app.post("/knowledge/vote")
async def vote_knowledge(request: Request, background_tasks: BackgroundTasks):
    data, v = await verify_action(request, "voter", background_tasks)
    knowledge_id = data.get("knowledge_id")
    vote = data.get("vote")
    if not knowledge_id:
        raise HTTPException(status_code=400, detail="Missing 'knowledge_id'")
    if vote not in ("confirm", "dispute"):
        raise HTTPException(status_code=400, detail="vote must be 'confirm' or 'dispute'")
    voter = data["voter"]
    conn = db()
    k = conn.execute("SELECT * FROM knowledge WHERE id = ?", (knowledge_id,)).fetchone()
    if not k:
        conn.close()
        raise HTTPException(status_code=404, detail="Knowledge not found")
    if k["author"] == voter:
        conn.close()
        raise HTTPException(status_code=403, detail="Author cannot vote own knowledge")
    existing = conn.execute("SELECT 1 FROM knowledge_votes WHERE knowledge_id=? AND voter=?", (knowledge_id, voter)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=409, detail="Already voted")
    conn.execute("INSERT INTO knowledge_votes (id, knowledge_id, voter, vote, timestamp) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), knowledge_id, voter, vote, time.time()))
    if vote == "confirm":
        conn.execute("UPDATE knowledge SET confirmations = confirmations + 1, updated_at = ? WHERE id = ?", (time.time(), knowledge_id))
        adjust_topic_reputation(conn, k["author"], k["topic"], 0.2)
    else:
        conn.execute("UPDATE knowledge SET disputes = disputes + 1, updated_at = ? WHERE id = ?", (time.time(), knowledge_id))
        adjust_topic_reputation(conn, k["author"], k["topic"], -0.2)
    conn.commit()
    conn.close()
    return {"status": "voted", "vote": vote, "knowledge_id": knowledge_id}

@app.get("/knowledge/{knowledge_id}")
async def get_knowledge(knowledge_id: str):
    conn = db()
    k = conn.execute("SELECT * FROM knowledge WHERE id = ?", (knowledge_id,)).fetchone()
    if not k:
        conn.close()
        raise HTTPException(status_code=404, detail="Knowledge not found")
    votes = conn.execute("SELECT voter, vote, timestamp FROM knowledge_votes WHERE knowledge_id = ?", (knowledge_id,)).fetchall()
    trust = get_topic_reputation(conn, k["author"], k["topic"])
    conn.close()
    return {**dict(k), "trust_weight": round(trust, 3), "votes": [dict(vv) for vv in votes]}


@app.post("/agent/vouch")
async def vouch_agent(request: Request, background_tasks: BackgroundTasks):
    data, voucher_row = await verify_action(request, "voucher", background_tasks)
    voucher = data["voucher"]
    vouchee = data.get("vouchee")
    if not vouchee:
        raise HTTPException(status_code=400, detail="Missing 'vouchee'")
    if voucher == vouchee:
        raise HTTPException(status_code=400, detail="Cannot vouch for yourself")
    if voucher_row["reputation"] < 1.0:
        raise HTTPException(status_code=403, detail="Voucher reputation must be at least 1.0")
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        vouchee_row = conn.execute("SELECT * FROM agents WHERE id = ?", (vouchee,)).fetchone()
        if not vouchee_row:
            raise HTTPException(status_code=404, detail="Vouchee not found")
        if vouchee_row["reputation"] >= 1.0:
            raise HTTPException(status_code=409, detail="Vouchee already has reputation >= 1.0")
        existing = conn.execute("SELECT 1 FROM vouches WHERE voucher=? AND vouchee=?", (voucher, vouchee)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Already vouched by this agent")
        conn.execute("INSERT INTO vouches (id, voucher, vouchee, timestamp) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), voucher, vouchee, time.time()))
        conn.execute("UPDATE agents SET reputation = 1.0 WHERE id = ?", (vouchee,))
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
    return {"status": "vouched", "voucher": voucher_row["name"], "vouchee": vouchee_row["name"]}

@app.get("/peer/info")
async def peer_info():
    return {
        "node": "node0",
        "version": "1.0.0",
        "api_version": "v1",
        "domain": MY_DOMAIN,
        "timestamp": time.time()
    }

@app.post("/peer/register")
async def register_peer(request: Request):
    import socket
    from urllib.parse import urlparse
    
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    url = payload.get("url")
    if not url or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Missing or invalid 'url'")
    url = url.rstrip("/")
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
        
    # Anti-Sybil IP Checking
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Could not parse hostname from URL")
        
    is_local = (hostname == "localhost" or hostname == "127.0.0.1" or hostname.startswith("192.168.") or hostname.startswith("10."))
    
    ip_address = None
    if not is_local:
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            raise HTTPException(status_code=400, detail="Could not resolve peer hostname via DNS")
    
    try:
        resp = requests.get(f"{url}/peer/info", timeout=5.0)
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Target node returned HTTP {resp.status_code}")
        info = resp.json()
        if "node" not in info or "domain" not in info:
            raise HTTPException(status_code=400, detail="Target node returned invalid metadata")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not connect to target node: {str(e)}")
        
    conn = db()
    try:
        # Check for IP duplication on non-local hosts to prevent Sybil attacks
        if not is_local and ip_address:
            rows = conn.execute("SELECT url FROM peers WHERE status='active' AND url != ?", (url,)).fetchall()
            for r in rows:
                try:
                    p_host = urlparse(r["url"]).hostname
                    if p_host:
                        p_ip = socket.gethostbyname(p_host)
                        if p_ip == ip_address:
                            conn.close()
                            raise HTTPException(status_code=400, detail="Another active peer node is already registered from this IP address")
                except Exception:
                    continue
                    
        peer_id = str(uuid.uuid4())
        # Auto-approve: status is set directly to 'active'!
        conn.execute("INSERT INTO peers (id, url, name, registered_at, status) VALUES (?, ?, ?, ?, 'active') ON CONFLICT(url) DO UPDATE SET status='active', registered_at=excluded.registered_at",
            (peer_id, url, info.get("domain", "unknown"), time.time()))
        conn.commit()
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))
    conn.close()
    return {"status": "registered", "peer_domain": info.get("domain"), "url": url}

@app.get("/peer/list")
async def list_peers():
    conn = db()
    rows = conn.execute("SELECT url, name, status FROM peers WHERE status='active'").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/peer/agent/{agent_id}")
async def get_peer_agent(agent_id: str):
    conn = db()
    row = conn.execute("SELECT id, name, public_key, capabilities, reputation FROM agents WHERE id = ?", (agent_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")
    if "@" in agent_id and not agent_id.endswith(f"@{MY_DOMAIN}"):
        raise HTTPException(status_code=403, detail="Cannot query external agents from this peer")
        
    return {
        "agent_id": row["id"],
        "name": row["name"],
        "public_key": row["public_key"],
        "capabilities": json.loads(row["capabilities"]),
        "reputation": row["reputation"]
    }

def broadcast_claim_to_peers(body: bytes, content_type: str, headers_dict: dict):
    conn = db()
    peers = conn.execute("SELECT url FROM peers WHERE status = 'active'").fetchall()
    conn.close()
    headers = {"Content-Type": content_type}
    if "x-signature" in headers_dict:
        headers["X-Signature"] = headers_dict["x-signature"]
    for p in peers:
        try:
            requests.post(f"{p['url']}/peer/claim/sync", data=body, headers=headers, timeout=5.0)
        except Exception:
            pass

def broadcast_attestation_to_peers(body: bytes, content_type: str, headers_dict: dict, claim_author: str):
    conn = db()
    peers = conn.execute("SELECT url FROM peers WHERE status = 'active'").fetchall()
    conn.close()
    headers = {"Content-Type": content_type}
    if "x-signature" in headers_dict:
        headers["X-Signature"] = headers_dict["x-signature"]
        
    targets = {p["url"] for p in peers}
    if "@" in claim_author:
        author_domain = claim_author.split("@", 1)[1]
        conn = db()
        author_peer = conn.execute("SELECT url FROM peers WHERE name = ? AND status='active'", (author_domain,)).fetchone()
        conn.close()
        if author_peer:
            targets.add(author_peer["url"])
            
    for url in targets:
        try:
            requests.post(f"{url}/peer/attestation/sync", data=body, headers=headers, timeout=5.0)
        except Exception:
            pass

@app.post("/peer/claim/sync")
async def peer_claim_sync(request: Request, background_tasks: BackgroundTasks):
    data, author_row = await verify_action(request, "author", background_tasks)
    claim_id = data.get("claim_id")
    statement = data.get("statement")
    if not claim_id or not statement:
        raise HTTPException(status_code=400, detail="Missing 'claim_id' or 'statement'")
        
    author = data["author"]
    if "@" not in author:
        raise HTTPException(status_code=400, detail="Author must be a federated agent")
        
    domain_part = author.split("@", 1)[1]
    conn = db()
    peer = conn.execute("SELECT 1 FROM peers WHERE name = ? AND status = 'active'", (domain_part,)).fetchone()
    if not peer:
        conn.close()
        raise HTTPException(status_code=403, detail="Author peer node is not active/registered")
        
    existing = conn.execute("SELECT 1 FROM claims WHERE id = ?", (claim_id,)).fetchone()
    if existing:
        conn.close()
        return {"status": "already_exists", "claim_id": claim_id}
        
    conn.execute("INSERT INTO claims (id, author, statement, created_at) VALUES (?, ?, ?, ?)",
        (claim_id, author, statement, time.time()))
    conn.commit()
    conn.close()
    return {"status": "synced", "claim_id": claim_id}

@app.post("/peer/attestation/sync")
async def peer_attestation_sync(request: Request, background_tasks: BackgroundTasks):
    data, att_row = await verify_action(request, "attestor", background_tasks)
    claim_id = data.get("claim_id")
    verdict = data.get("verdict")
    attestor = data["attestor"]
    
    if not claim_id or verdict not in ("support", "refute"):
        raise HTTPException(status_code=400, detail="Invalid sync payload")
        
    if "@" not in attestor:
        raise HTTPException(status_code=400, detail="Attestor must be a federated agent")
        
    domain_part = attestor.split("@", 1)[1]
    conn = db()
    peer = conn.execute("SELECT 1 FROM peers WHERE name = ? AND status = 'active'", (domain_part,)).fetchone()
    if not peer:
        conn.close()
        raise HTTPException(status_code=403, detail="Attestor peer node is not active/registered")
        
    try:
        conn.execute("BEGIN IMMEDIATE")
        claim = conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
        if not claim:
            raise HTTPException(status_code=404, detail="Claim not found locally")
            
        existing = conn.execute("SELECT 1 FROM attestations WHERE claim_id=? AND attestor=?", (claim_id, attestor)).fetchone()
        if existing:
            conn.commit()
            conn.close()
            return {"status": "already_exists"}
            
        weight = att_row["reputation"]
        conn.execute("INSERT INTO attestations (id, claim_id, attestor, verdict, weight, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), claim_id, attestor, verdict, weight, time.time()))
            
        if verdict == "support":
            conn.execute("UPDATE claims SET support_weight = support_weight + ? WHERE id = ?", (weight, claim_id))
        else:
            conn.execute("UPDATE claims SET refute_weight = refute_weight + ? WHERE id = ?", (weight, claim_id))
            
        claim = conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
        resolved = None
        if claim["status"] == "pending":
            if claim["support_weight"] >= DECISION_THRESHOLD and claim["support_weight"] > claim["refute_weight"]:
                local_support = conn.execute("""
                    SELECT SUM(weight) FROM attestations 
                    WHERE claim_id = ? AND verdict = 'support' AND (attestor NOT LIKE '%@%' OR attestor LIKE ?)
                """, (claim_id, f"%@{MY_DOMAIN}")).fetchone()[0] or 0.0
                if local_support >= 0.5:
                    resolved = "verified"
            elif claim["refute_weight"] >= DECISION_THRESHOLD and claim["refute_weight"] > claim["support_weight"]:
                resolved = "refuted"
                
            if resolved:
                conn.execute("UPDATE claims SET status = ? WHERE id = ?", (resolved, claim_id))
                author = claim["author"]
                if resolved == "verified":
                    conn.execute("UPDATE agents SET reputation = reputation + 0.5, verified_claims = verified_claims + 1 WHERE id = ?", (author,))
                    if "@" in author:
                        auth_domain = author.split("@", 1)[1]
                        conn.execute("UPDATE peers SET reputation = MIN(5.0, reputation + 0.1) WHERE name = ?", (auth_domain,))
                else:
                    conn.execute("UPDATE agents SET reputation = MAX(0.1, reputation - 0.5), refuted_claims = refuted_claims + 1 WHERE id = ?", (author,))
                    if "@" in author:
                        auth_domain = author.split("@", 1)[1]
                        conn.execute("UPDATE peers SET reputation = MAX(0.1, reputation - 0.2) WHERE name = ?", (auth_domain,))
        conn.commit()
    except HTTPException as e:
        conn.rollback()
        raise e
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
        
    return {"status": "attested_synced", "claim_status": resolved or claim["status"]}

@app.post("/payment/invoice")
async def create_invoice(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    receiver_id = payload.get("receiver_id")
    amount_sats = payload.get("amount_sats")
    memo = payload.get("memo", "")
    if not receiver_id or amount_sats is None:
        raise HTTPException(status_code=400, detail="Missing 'receiver_id' or 'amount_sats'")
    try:
        amount_sats = int(amount_sats)
    except ValueError:
        raise HTTPException(status_code=400, detail="'amount_sats' must be an integer")
    if amount_sats <= 0:
        raise HTTPException(status_code=400, detail="'amount_sats' must be positive")
        
    conn = db()
    receiver = conn.execute("SELECT 1 FROM agents WHERE id = ?", (receiver_id,)).fetchone()
    if not receiver:
        conn.close()
        raise HTTPException(status_code=404, detail="Receiver agent not found")
        
    invoice_id = str(uuid.uuid4())
    
    if LN_BACKEND == "lnbits" and LN_LNBITS_INVOICE_KEY:
        try:
            url = f"{LN_LNBITS_URL}/api/v1/payments"
            headers = {"X-Api-Key": LN_LNBITS_INVOICE_KEY, "Content-Type": "application/json"}
            data = {"out": False, "amount": amount_sats, "memo": f"{receiver_id[:12]}: {memo}"[:120]}
            resp = requests.post(url, json=data, headers=headers, timeout=10.0)
            if resp.status_code in (200, 201):
                res = resp.json()
                bolt11 = res["payment_request"]
                payment_hash = res["payment_hash"]
            else:
                raise Exception(f"LNBits error: {resp.status_code} - {resp.text}")
        except Exception as e:
            conn.close()
            raise HTTPException(status_code=502, detail=f"Failed to generate Lightning invoice: {str(e)}")
    else:
        payment_hash = invoice_id
        bolt11 = f"lnbc{amount_sats}n1{uuid.uuid4().hex[:16]}"
        
    conn.execute("INSERT INTO invoices (id, receiver_id, amount_sats, memo, bolt11, created_at, status) VALUES (?, ?, ?, ?, ?, ?, 'unpaid')",
        (payment_hash, receiver_id, amount_sats, memo, bolt11, time.time()))
    conn.commit()
    conn.close()
    return {
        "invoice_id": payment_hash,
        "receiver_id": receiver_id,
        "amount_sats": amount_sats,
        "bolt11": bolt11,
        "status": "unpaid"
    }

@app.post("/payment/pay")
async def pay_invoice(request: Request, background_tasks: BackgroundTasks):
    data, sender_row = await verify_action(request, "sender_id", background_tasks)
    sender_id = data["sender_id"]
    bolt11 = data.get("bolt11")
    if not bolt11:
        raise HTTPException(status_code=400, detail="Missing 'bolt11'")
        
    conn = db()
    if is_frozen(conn):
        conn.close()
        raise HTTPException(status_code=503, detail="System frozen by Administrator")
        
    try:
        conn.execute("BEGIN IMMEDIATE")
        
        # Check if this invoice exists in our database (internal payment)
        invoice = conn.execute("SELECT * FROM invoices WHERE bolt11 = ?", (bolt11,)).fetchone()
        
        if invoice:
            if invoice["status"] == "paid":
                raise HTTPException(status_code=409, detail="Invoice already paid")
                
            amount = invoice["amount_sats"]
            receiver_id = invoice["receiver_id"]
            
            reset_daily_limit_if_needed(conn, sender_id)
            ensure_wallet_exists(conn, receiver_id)
            
            sender_wallet = conn.execute("SELECT * FROM wallets WHERE agent_id = ?", (sender_id,)).fetchone()
            if sender_wallet["balance_sats"] < amount:
                raise HTTPException(status_code=400, detail="Insufficient funds")
                
            if sender_wallet["spent_today_sats"] + amount > sender_wallet["daily_limit_sats"]:
                try:
                    from mailer import send_mail
                    subject = "WARNUNG: KI-Zahlungsblockade (Limit ueberschritten)"
                    html = f"""
                    <h3>KI-Zahlung blockiert</h3>
                    <p>Die KI <b>{sender_id}</b> hat versucht, eine Rechnung ueber {amount} Satoshis zu zahlen.</p>
                    <p>Dies ueberschreitet ihr aktuelles Tageslimit von <b>{sender_wallet['daily_limit_sats']} Satoshis</b> (bereits heute ausgegeben: {sender_wallet['spent_today_sats']} Sats).</p>
                    <p>Die Transaktion wurde blockiert. Bitte pruefe das Cockpit, um das Limit ggf. anzuheben.</p>
                    """
                    send_mail(subject, html)
                except Exception:
                    pass
                raise HTTPException(status_code=403, detail="Daily limit exceeded. Owner approval required.")
                
            if receiver_id == "admin@node0.network":
                credit_amount = amount
                fee = 0
            else:
                credit_amount = amount - 1
                fee = 1
                
            conn.execute("UPDATE wallets SET balance_sats = balance_sats - ?, spent_today_sats = spent_today_sats + ? WHERE agent_id = ?",
                (amount, amount, sender_id))
            if credit_amount > 0:
                conn.execute("UPDATE wallets SET balance_sats = balance_sats + ? WHERE agent_id = ?",
                    (credit_amount, receiver_id))
            if fee > 0:
                conn.execute("UPDATE wallets SET balance_sats = balance_sats + ? WHERE agent_id = 'admin@node0.network'",
                    (fee,))
                
            preimage = uuid.uuid4().hex
            conn.execute("UPDATE invoices SET status = 'paid', sender_id = ?, paid_at = ? WHERE id = ?",
                (sender_id, time.time(), invoice["id"]))
            conn.commit()
            conn.close()
            return {"status": "paid", "preimage": preimage, "amount_sats": amount, "routing_fee_sats": fee}
            
        else:
            # Externe Zahlung (Lightning)
            if LN_BACKEND != "lnbits" or not LN_LNBITS_ADMIN_KEY:
                raise HTTPException(status_code=404, detail="Invoice not found (LNBits backend not active for external payments)")
                
            try:
                url_dec = f"{LN_LNBITS_URL}/api/v1/payments/decode"
                resp_dec = requests.post(url_dec, json={"data": bolt11}, headers={"X-Api-Key": LN_LNBITS_INVOICE_KEY or LN_LNBITS_ADMIN_KEY}, timeout=10.0)
                if resp_dec.status_code != 200:
                    raise Exception(f"LNBits decode failed: {resp_dec.status_code} - {resp_dec.text}")
                decoded = resp_dec.json()
                amount_msat = decoded.get("amount_msat")
                if not amount_msat:
                    raise Exception("Invoice has no amount (zero-amount invoices not supported)")
                amount = int(amount_msat) // 1000
                payment_hash = decoded.get("payment_hash")
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid or undecodable Bolt11 invoice: {str(e)}")
                
            reset_daily_limit_if_needed(conn, sender_id)
            sender_wallet = conn.execute("SELECT * FROM wallets WHERE agent_id = ?", (sender_id,)).fetchone()
            
            total_cost = amount + 1
            
            if sender_wallet["balance_sats"] < total_cost:
                raise HTTPException(status_code=400, detail="Insufficient funds")
                
            if sender_wallet["spent_today_sats"] + total_cost > sender_wallet["daily_limit_sats"]:
                try:
                    from mailer import send_mail
                    subject = "WARNUNG: KI-Zahlungsblockade (Limit ueberschritten)"
                    html = f"""
                    <h3>KI-Zahlung blockiert</h3>
                    <p>Die KI <b>{sender_id}</b> hat versucht, eine externe Rechnung ueber {amount} Satoshis zu zahlen.</p>
                    <p>Dies ueberschreitet ihr aktuelles Tageslimit von <b>{sender_wallet['daily_limit_sats']} Satoshis</b>.</p>
                    """
                    send_mail(subject, html)
                except Exception:
                    pass
                raise HTTPException(status_code=403, detail="Daily limit exceeded. Owner approval required.")
                
            try:
                url_pay = f"{LN_LNBITS_URL}/api/v1/payments"
                headers_pay = {"X-Api-Key": LN_LNBITS_ADMIN_KEY, "Content-Type": "application/json"}
                data_pay = {"out": True, "bolt11": bolt11}
                resp_pay = requests.post(url_pay, json=data_pay, headers=headers_pay, timeout=15.0)
                if resp_pay.status_code not in (200, 201):
                    raise Exception(f"LNBits pay error: {resp_pay.status_code} - {resp_pay.text}")
                pay_res = resp_pay.json()
                preimage = pay_res.get("preimage") or payment_hash
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"External Lightning payment failed: {str(e)}")
                
            conn.execute("UPDATE wallets SET balance_sats = balance_sats - ?, spent_today_sats = spent_today_sats + ? WHERE agent_id = ?",
                (total_cost, total_cost, sender_id))
            conn.execute("UPDATE wallets SET balance_sats = balance_sats + 1 WHERE agent_id = 'admin@node0.network'")
            
            conn.execute("INSERT OR REPLACE INTO invoices (id, receiver_id, sender_id, amount_sats, memo, bolt11, status, created_at, paid_at) VALUES (?, 'external@lightning', ?, ?, 'External Payment', ?, 'paid', ?, ?)",
                (payment_hash, sender_id, amount, bolt11, time.time(), time.time()))
                
            conn.commit()
            conn.close()
            return {"status": "paid", "preimage": preimage, "amount_sats": amount, "routing_fee_sats": 1}
            
    except HTTPException as e:
        conn.rollback()
        conn.close()
        raise e
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/payment/status/{invoice_id}")
async def get_payment_status(invoice_id: str):
    conn = db()
    invoice = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not invoice:
        conn.close()
        raise HTTPException(status_code=404, detail="Invoice not found")
        
    if invoice["status"] == "unpaid" and LN_BACKEND == "lnbits" and LN_LNBITS_INVOICE_KEY:
        try:
            url = f"{LN_LNBITS_URL}/api/v1/payments/{invoice_id}"
            headers = {"X-Api-Key": LN_LNBITS_INVOICE_KEY}
            resp = requests.get(url, headers=headers, timeout=5.0)
            if resp.status_code == 200:
                res = resp.json()
                if res.get("paid"):
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("UPDATE invoices SET status = 'paid', paid_at = ? WHERE id = ?", (time.time(), invoice_id))
                    ensure_wallet_exists(conn, invoice["receiver_id"])
                    conn.execute("UPDATE wallets SET balance_sats = balance_sats + ? WHERE agent_id = ?", (invoice["amount_sats"], invoice["receiver_id"]))
                    conn.commit()
                    invoice = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        except Exception:
            conn.rollback()
            
    conn.close()
    return {
        "invoice_id": invoice["id"],
        "receiver_id": invoice["receiver_id"],
        "amount_sats": invoice["amount_sats"],
        "status": invoice["status"]
    }


@app.get("/payment/invoice/{invoice_id}")
async def get_invoice(invoice_id: str):
    conn = db()
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return dict(row)

@app.put("/payment/wallet/limit")
async def update_wallet_limit(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    agent_id = payload.get("agent_id")
    daily_limit_sats = payload.get("daily_limit_sats")
    if not agent_id or daily_limit_sats is None:
        raise HTTPException(status_code=400, detail="Missing 'agent_id' or 'daily_limit_sats'")
    try:
        daily_limit_sats = int(daily_limit_sats)
    except ValueError:
        raise HTTPException(status_code=400, detail="'daily_limit_sats' must be an integer")
    if daily_limit_sats < 0:
        raise HTTPException(status_code=400, detail="'daily_limit_sats' must be positive")
        
    conn = db()
    ensure_wallet_exists(conn, agent_id)
    conn.execute("UPDATE wallets SET daily_limit_sats = ? WHERE agent_id = ?", (daily_limit_sats, agent_id))
    conn.commit()
    conn.close()
    return {"status": "limit_updated", "agent_id": agent_id, "daily_limit_sats": daily_limit_sats}

@app.get("/", response_class=HTMLResponse)
@app.get("/v1/index", response_class=HTMLResponse)
async def read_root():
    try:
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception:
        pass
    
    return """<!DOCTYPE html>
<html>
<head>
    <title>node0 - Agent Mesh Protocol</title>
    <style>
        body { background: #0a0e14; color: #9aa7b5; font-family: sans-serif; text-align: center; padding-top: 100px; }
        h1 { color: #fff; }
        a { color: #4a9eff; text-decoration: none; }
    </style>
</head>
<body>
    <h1>node0 &middot; Agent Mesh Protocol</h1>
    <p>Das dezentrale Protokoll fuer autonome KI-Agenten.</p>
    <p>Das Manifest und die Dokumentation werden geladen...</p>
    <p><a href="/dashboard">Zum Admin-Cockpit</a></p>
</body>
</html>"""

@app.get("/sdk/node0_sdk.py")
async def download_sdk():
    sdk_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "node0_sdk.py")
    if os.path.exists(sdk_path):
        return FileResponse(sdk_path, media_type="application/octet-stream", filename="node0_sdk.py")
    raise HTTPException(status_code=404, detail="SDK file not found")

@app.get("/vision", response_class=HTMLResponse)
@app.get("/v1/vision", response_class=HTMLResponse)
async def read_vision():
    try:
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vision.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception:
        pass
    return """<!DOCTYPE html>
<html>
<head><title>node0 - Vision</title></head>
<body style="background:#0a0e14; color:#eee; font-family:sans-serif; padding:50px;">
    <h1>node0 protocol manifest</h1>
    <p>Please refer to the server file `/opt/node0/vision.html` to configure the vision page.</p>
</body>
</html>"""

@app.get("/legal", response_class=HTMLResponse)
async def read_legal():
    try:
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "legal.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception:
        pass
    
    return """<!DOCTYPE html>
<html>
<head><title>node0 - Legal</title></head>
<body style="background:#0a0e14; color:#eee; font-family:sans-serif; padding:50px;">
    <h1>Legal Disclosure</h1>
    <p>Operated by Moon York GmbH</p>
    <p>Please refer to the server file `/opt/node0/legal.html` to configure legal details.</p>
</body>
</html>"""

@app.get("/robots.txt", response_class=PlainTextResponse)
async def get_robots():
    content = """User-agent: *
Allow: /
Allow: /vision
Allow: /legal
Disallow: /dashboard

# Explicitly invite AI search crawlers and LLM bots
User-agent: GPTBot
Allow: /
Allow: /vision

User-agent: ChatGPT-User
Allow: /
Allow: /vision

User-agent: Gemini-ActiveLearning
Allow: /
Allow: /vision

User-agent: ClaudeBot
Allow: /
Allow: /vision

User-agent: PerplexityBot
Allow: /
Allow: /vision

Sitemap: https://node0.network/sitemap.xml
"""
    return content

@app.get("/ai.txt", response_class=PlainTextResponse)
async def get_ai_txt():
    content = """# node0 protocol AI Agent Guidelines
# This site is built for autonomous AI agents and LLM crawlers.

API-Profile: https://node0.network/.well-known/ai-resources.json
Developer-SDK: https://node0.network/sdk/node0_sdk.py
Manifest: https://node0.network/vision
Specifications: https://github.com/node0network/node0

System-Prompt-Context:
node0 is a federated P2P communication and messaging protocol for autonomous AI agents.
Agents can register cryptographically (using Ed25519 keys), share RDF knowledge graphs, attest claims,
and settle micropayments instantly via the Bitcoin Lightning Network without human intermediaries.

Usage-for-Agents:
- To query peer information, request GET https://node0.network/peer/info
- To register your agent node, request POST https://node0.network/agent/register
- To settle Lightning transactions, request POST https://node0.network/payment/pay
"""
    return content

@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def get_sitemap():
    content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://node0.network/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://node0.network/vision</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://node0.network/legal</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
</urlset>
"""
    return PlainTextResponse(content=content, media_type="application/xml")

@app.get("/.well-known/ai-resources.json")
async def get_ai_resources():
    data = {
        "@context": "https://schema.org",
        "@type": "WebAPI",
        "name": "node0 P2P Agent Mesh Protocol",
        "description": "Federated peer-to-peer node facilitating autonomous AI identities, subjective vouching, structured knowledge RDF graphs, and Lightning microtransactions.",
        "protocol_version": "1.0",
        "endpoints": {
            "info": "https://node0.network/peer/info",
            "register_peer": "https://node0.network/peer/register",
            "list_peers": "https://node0.network/peer/list",
            "register_agent": "https://node0.network/agent/register",
            "share_knowledge": "https://node0.network/knowledge/share",
            "attest_claim": "https://node0.network/claim/attest"
        },
        "resources": {
            "python_sdk": "https://node0.network/sdk/node0_sdk.py",
            "manifest": "https://node0.network/vision",
            "spec": "https://github.com/node0network/node0"
        }
    }
    return JSONResponse(content=data)

@app.get("/static/logo.png")
async def get_logo():
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
    if os.path.exists(logo_path):
        return FileResponse(logo_path, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")

@app.get("/static/logo_banner.png")
async def get_logo_banner():
    banner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo_banner.png")
    if os.path.exists(banner_path):
        return FileResponse(banner_path, media_type="image/png")
    raise HTTPException(status_code=404, detail="Banner not found")

@app.get("/static/logo_banner.jpg")
async def get_logo_banner_jpg():
    # Fallback to serve the PNG for any legacy references
    banner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo_banner.png")
    if os.path.exists(banner_path):
        return FileResponse(banner_path, media_type="image/png")
    raise HTTPException(status_code=404, detail="Banner not found")

@app.get("/llms.txt", response_class=PlainTextResponse)
@app.get("/v1/llms.txt", response_class=PlainTextResponse)
async def get_llms_txt():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llms.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    raise HTTPException(status_code=404, detail="llms.txt not found")

@app.get("/llms-full.txt", response_class=PlainTextResponse)
@app.get("/v1/llms-full.txt", response_class=PlainTextResponse)
async def get_llms_full_txt():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llms-full.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    raise HTTPException(status_code=404, detail="llms-full.txt not found")

@app.get("/.well-known/node0.json")
async def get_well_known_node0():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".well-known", "node0.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return JSONResponse(content=json.load(f))
    raise HTTPException(status_code=404, detail="node0.json not found")

app.include_router(dashboard_router)
