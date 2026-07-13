import requests, os

def load_env_val(key: str, default: str = None) -> str:
    """Liest einen Konfigurationswert aus den Umgebungsvariablen oder /opt/node0/.env"""
    val = os.getenv(key)
    if val:
        return val
    try:
        env_path = os.getenv("NODE0_ENV_PATH", "/opt/node0/.env")
        with open(env_path) as f:
            for line in f:
                if line.startswith(f"{key}="):
                    return line.strip().split("=", 1)[1]
    except FileNotFoundError:
        pass
    return default

def load_api_key():
    """Liest den Brevo API-Key aus der Umgebungsvariable oder /opt/node0/.env"""
    return load_env_val("BREVO_API_KEY")

SENDER_EMAIL = load_env_val("NODE0_SENDER_EMAIL", "noreply@node0.network")
SENDER_NAME = load_env_val("NODE0_SENDER_NAME", "node0")
DEFAULT_RECIPIENT = load_env_val("NODE0_ADMIN_EMAIL", "josh@moonyork.de")

def send_mail(subject: str, html_content: str, to_email: str = DEFAULT_RECIPIENT):
    """Versendet eine E-Mail über die Brevo API. Gibt (success, info) zurück."""
    api_key = load_api_key()
    if not api_key:
        return False, "Kein API-Key gefunden"
    try:
        resp = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
                "accept": "application/json"
            },
            json={
                "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
                "to": [{"email": to_email}],
                "subject": subject,
                "htmlContent": html_content
            },
            timeout=15
        )
        if resp.status_code in (200, 201):
            return True, resp.json().get("messageId", "ok")
        else:
            return False, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return False, str(e)
