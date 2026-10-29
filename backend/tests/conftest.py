"""Shared test setup (Phase 8: every API call needs a signed-in user or the ingest API key)."""
import os

# Real logins hash with 600,000 PBKDF2 iterations (~0.3 s). Tests create hundreds of apps,
# so they use a cheap setting. The hash format stores the count, so the code path is identical.
os.environ.setdefault("PASSWORD_HASH_ITERATIONS", "1000")

DEMO_PASSWORDS = {"admin": "Admin@123", "analyst": "Analyst@123", "viewer": "Viewer@123"}


def sign_in(client, username: str = "admin"):
    """Log in as a demo user and make the client send the token (and the ingest key) from now on."""
    r = client.post("/api/auth/login", json={"username": username, "password": DEMO_PASSWORDS[username]})
    assert r.status_code == 200, r.text
    client.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    client.headers["X-API-Key"] = "lab-ingest-key"
    return client


def ws_url(client) -> str:
    """Browsers can't send headers on a WebSocket, so the token goes in the URL."""
    return "/ws?token=" + client.headers["Authorization"].removeprefix("Bearer ")
