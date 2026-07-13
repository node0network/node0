#!/usr/bin/env python3
"""node0 — Schwellwert-Alerts. Prueft Mesh-Reifegrad, sendet Mail bei Ausloeser.
Idempotent ueber alert_state.json (kein Spam). Taeglich via systemd-Timer."""
import json, os, sys, urllib.request, urllib.error
from datetime import datetime, timezone

# Sichere Importpfade für mailer.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mailer import load_env_val

BASE_URL   = load_env_val("NODE0_BASE_URL", "http://127.0.0.1:8000")
STATE_FILE = load_env_val("NODE0_ALERT_STATE_FILE", "/opt/node0/alert_state.json")
RECIPIENT  = load_env_val("NODE0_ADMIN_EMAIL", "josh@moonyork.de")
own_agents_raw = load_env_val("NODE0_OWN_AGENTS", "oriion-460481,nexion-4f6340,zepeon-fc9531,veleon-10d10b,admin-node0,velara-aef9a4")
KNOWN_OWN_AGENTS = set(x.strip() for x in own_agents_raw.split(",") if x.strip())
CARTEL_AGENT_THRESHOLD = 50
CARTEL_ATTESTATION_THRESHOLD = 200
DRY_RUN = "--dry-run" in sys.argv

def get_json(path):
    req = urllib.request.Request(BASE_URL + path, headers={"User-Agent": "node0-alert-check"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))

def first_int(d, keys, default=0):
    if not isinstance(d, dict): return default
    for k in keys:
        if k in d and isinstance(d[k], (int, float)): return int(d[k])
    return default

def extract_agent_id(agent):
    if isinstance(agent, str): return agent
    if isinstance(agent, dict):
        for k in ("name", "agent_id", "agent_name", "id"):
            if k in agent and isinstance(agent[k], str): return agent[k]
    return None

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except (json.JSONDecodeError, OSError): pass
    return {}

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)

DB_PATH = load_env_val("NODE0_DB_PATH", "/opt/node0/mesh.db")
DB_SIZE_THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB
AGENT_COUNT_SCALE_THRESHOLD = 5000  # 5,000 agents

def evaluate(status, agents_list, state):
    state = dict(state)
    state.setdefault("cartel_alert_sent", False)
    state.setdefault("foreign_agents_notified", [])
    state.setdefault("db_size_warn_sent", False)
    state.setdefault("agent_scale_warn_sent", False)
    
    agent_count = first_int(status, ["agents", "agent_count", "total_agents"])
    if agent_count == 0 and isinstance(agents_list, list): agent_count = len(agents_list)
    attestation_count = first_int(status, ["attestations", "attestation_count", "total_attestations"])
    
    db_size = 0
    if os.path.exists(DB_PATH):
        try:
            db_size = os.path.getsize(DB_PATH)
        except OSError:
            pass

    foreign_ids = []
    if isinstance(agents_list, list):
        for a in agents_list:
            aid = extract_agent_id(a)
            if aid and aid not in KNOWN_OWN_AGENTS: foreign_ids.append(aid)
    
    alerts = []
    
    # 1. Cartel Alert
    if (agent_count >= CARTEL_AGENT_THRESHOLD or attestation_count >= CARTEL_ATTESTATION_THRESHOLD) and not state["cartel_alert_sent"]:
        body = ("<p>Die Kartell-Schwelle wurde erreicht. Die Kartell-Erkennung (Risiko 3) sollte jetzt aktiviert werden.</p>"
                "<ul><li>Agenten: <b>%d</b> (Schwelle %d)</li><li>Attestierungen: <b>%d</b> (Schwelle %d)</li></ul>"
                % (agent_count, CARTEL_AGENT_THRESHOLD, attestation_count, CARTEL_ATTESTATION_THRESHOLD))
        alerts.append({"kind": "cartel", "subject": "[node0 AKTION] Kartell-Erkennung jetzt faellig", "body": body})
        state["cartel_alert_sent"] = True
        
    # 2. Foreign Agents Alert
    already = set(state["foreign_agents_notified"])
    new_foreign = [a for a in foreign_ids if a not in already]
    if new_foreign:
        first = len(already) == 0
        intro = ("<p><b>Der erste fremde Agent hat sich registriert.</b> Der Schadwissen-Filter (Risiko 5) wird jetzt faellig.</p>"
                 if first else "<p>Weitere fremde Agenten haben sich registriert.</p>")
        items = "".join("<li><code>%s</code></li>" % a for a in new_foreign)
        body = intro + "<p>Neu hinzugekommen:</p><ul>" + items + "</ul>"
        subject = ("[node0 AKTION] Erster fremder Agent registriert — Schadwissen-Filter faellig"
                   if first else "[node0 AKTION] Weitere fremde Agenten im Mesh")
        alerts.append({"kind": "foreign_agent", "subject": subject, "body": body})
        state["foreign_agents_notified"] = sorted(already | set(new_foreign))
        
    # 3. Database Size Warning (Proactive PostgreSQL Migration Alert)
    if db_size >= DB_SIZE_THRESHOLD_BYTES and not state["db_size_warn_sent"]:
        body = (f"<p><b>WARNUNG: Datenbank-Skalierungsgrenze rückt näher.</b></p>"
                f"<p>Die Größe der SQLite-Datenbank auf dem Server beträgt aktuell <b>{db_size / (1024*1024*1024):.2f} GB</b> (Schwelle: 2.00 GB).</p>"
                f"<p>Um Schreibblockaden im Live-Betrieb bei sehr hoher Auslastung zu vermeiden, empfehlen wir dir, jetzt die Migration zu PostgreSQL einzuplanen.</p>")
        alerts.append({"kind": "performance_db_size", "subject": "[node0 WARNUNG] Datenbankgröße überschreitet 2 GB - PostgreSQL einplanen", "body": body})
        state["db_size_warn_sent"] = True

    # 4. Agent Count Scaling Warning
    if agent_count >= AGENT_COUNT_SCALE_THRESHOLD and not state["agent_scale_warn_sent"]:
        body = (f"<p><b>WARNUNG: Hohe Anzahl an registrierten Agenten erreicht.</b></p>"
                f"<p>Es sind aktuell <b>{agent_count} KIs</b> im System registriert (Schwelle: 5.000 KIs).</p>"
                f"<p>Bei dieser Anzahl an parallelen Akteuren können Schreib-Wartezeiten in SQLite auftreten. Wir empfehlen dringend den Wechsel auf PostgreSQL.</p>")
        alerts.append({"kind": "performance_agent_scale", "subject": "[node0 WARNUNG] Über 5.000 KIs registriert - PostgreSQL einplanen", "body": body})
        state["agent_scale_warn_sent"] = True

    return alerts, state, {"agent_count": agent_count, "attestation_count": attestation_count, "foreign_ids": foreign_ids}

def send_alert(subject, html_body):
    from mailer import send_mail
    return send_mail(subject, html_body, RECIPIENT)

def main():
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        status = get_json("/mesh/status")
        agents_list = get_json("/mesh/agents")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print("[%s] WARN: node0 nicht erreichbar (%s). Ausfall ist Aufgabe des externen Monitors." % (stamp, e))
        return 0
    state = load_state()
    alerts, new_state, m = evaluate(status, agents_list, state)
    print("[%s] Agenten=%d Attestierungen=%d fremde=%d neue_Alerts=%d%s" %
          (stamp, m["agent_count"], m["attestation_count"], len(m["foreign_ids"]), len(alerts), " (DRY-RUN)" if DRY_RUN else ""))
    if not alerts:
        print("  -> Kein neuer Ausloeser. Nichts zu tun.")
        return 0
    for a in alerts:
        if DRY_RUN:
            print("  -> WUERDE senden: " + a["subject"])
        else:
            ok = send_alert(a["subject"], a["body"])
            print("  -> gesendet: %s (Ergebnis: %s)" % (a["subject"], ok))
    if not DRY_RUN:
        save_state(new_state)
        print("  -> State aktualisiert: " + STATE_FILE)
    else:
        print("  -> DRY-RUN: State NICHT veraendert.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
