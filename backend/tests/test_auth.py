"""Authentication and role-based access tests (Phase 8).

    docker compose exec backend pytest -v tests/test_auth.py
"""
import base64
import importlib
import json
import sys
from pathlib import Path

import pytest
from conftest import DEMO_PASSWORDS, sign_in, ws_url

ROOT = Path(__file__).resolve().parents[1]
SIM_DIR = ROOT / "simulator" if (ROOT / "simulator").exists() else ROOT.parent / "simulator"
sys.path.insert(0, str(SIM_DIR))


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("MODEL_DIR", str(tmp_path / "no-model"))
    monkeypatch.setenv("SOC_AUTOTRAIN", "0")
    for mod in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[mod]
    return importlib.import_module("app.main").app


@pytest.fixture()
def anon(app):
    from fastapi.testclient import TestClient
    return TestClient(app)


def as_user(app, username):
    from fastapi.testclient import TestClient
    return sign_in(TestClient(app), username)


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


# ------------------------------------------------------------------ authentication
def test_everything_needs_a_login(anon):
    for path in ("/api/alerts", "/api/incidents", "/api/stats/overview", "/api/audit", "/api/users"):
        assert anon.get(path).status_code == 401, path
    assert anon.get("/health").status_code == 200          # liveness checks stay public


def test_login_returns_a_token_that_works(anon):
    r = login(anon, "analyst", DEMO_PASSWORDS["analyst"])
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["role"] == "analyst" and "password_hash" not in body["user"]
    me = anon.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.json()["username"] == "analyst"


def test_wrong_password_and_unknown_user_look_the_same(anon):
    a = login(anon, "analyst", "nope")
    b = login(anon, "nobody", "nope")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()                             # no "user exists" hint


def test_passwords_are_hashed_not_stored(app):
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import User
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == "admin"))
    assert DEMO_PASSWORDS["admin"] not in u.password_hash
    assert u.password_hash.startswith("pbkdf2_sha256$")


def test_lockout_after_five_wrong_passwords(anon):
    for _ in range(5):
        assert login(anon, "viewer", "wrong").status_code == 401
    r = login(anon, "viewer", DEMO_PASSWORDS["viewer"])     # even the RIGHT password is refused now
    assert r.status_code == 401 and "Too many failed attempts" in r.json()["detail"]
    admin = as_user(anon.app, "admin")
    actions = [a["action"] for a in admin.get("/api/audit", params={"category": "access"}).json()]
    assert actions.count("login_failed") >= 6 and "account_locked" in actions
    # an admin can unlock the account
    viewer_id = next(u["id"] for u in admin.get("/api/users").json() if u["username"] == "viewer")
    admin.patch(f"/api/users/{viewer_id}", json={"unlock": True})
    assert login(anon, "viewer", DEMO_PASSWORDS["viewer"]).status_code == 200


def test_tampered_or_garbage_tokens_are_rejected(anon):
    token = login(anon, "viewer", DEMO_PASSWORDS["viewer"]).json()["access_token"]
    header, payload, sig = token.split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    data["role"] = "admin"                                  # try to promote ourselves
    forged = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    for bad in (f"{header}.{forged}.{sig}", "not-a-token", token + "x"):
        assert anon.get("/api/alerts", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


def test_expired_token_is_rejected(app, anon):
    from app.auth.security import create_token
    old, _ = create_token("admin", "admin", hours=-1)
    assert anon.get("/api/alerts", headers={"Authorization": f"Bearer {old}"}).status_code == 401


# ------------------------------------------------------------------ roles
def test_viewer_reads_but_cannot_change(app):
    admin, viewer = as_user(app, "admin"), as_user(app, "viewer")
    admin.post("/api/lab/run", json={"attacks": ["brute_force"], "include_normal": False})
    alert_id = viewer.get("/api/alerts").json()[0]["id"]           # reading is fine
    r = viewer.patch(f"/api/alerts/{alert_id}", json={"status": "investigating"})
    assert r.status_code == 403 and "viewer" in r.json()["detail"]
    assert viewer.post("/api/response/actions", json={"action": "block_ip", "ip": "198.51.100.9"}).status_code == 403
    assert viewer.post("/api/lab/run", json={"attacks": ["port_scan"]}).status_code == 403


def test_analyst_triages_but_cannot_change_config(app):
    analyst = as_user(app, "analyst")
    analyst.post("/api/lab/run", json={"attacks": ["brute_force"], "include_normal": False})
    alert_id = analyst.get("/api/alerts").json()[0]["id"]
    assert analyst.patch(f"/api/alerts/{alert_id}", json={"status": "investigating"}).status_code == 200
    assert analyst.patch("/api/rules/SOC-001", json={"enabled": False}).status_code == 403
    assert analyst.patch("/api/response/playbooks/PB-01", json={"mode": "approval"}).status_code == 403
    assert analyst.post("/api/ml/train").status_code == 403
    assert analyst.get("/api/users").status_code == 403
    assert analyst.post("/api/lab/reset", json={"scope": "containments"}).status_code == 200
    assert analyst.post("/api/lab/reset", json={"scope": "full"}).status_code == 403   # wiping needs admin


def test_audit_log_records_who_did_it(app):
    analyst = as_user(app, "analyst")
    analyst.post("/api/lab/run", json={"attacks": ["brute_force"], "include_normal": False})
    alert_id = analyst.get("/api/alerts").json()[0]["id"]
    analyst.patch(f"/api/alerts/{alert_id}", json={"status": "investigating"})
    row = next(a for a in analyst.get("/api/audit").json() if a["action"] == "alert_status")
    assert row["actor"] == "analyst" and row["username"] == "analyst"
    auto = [a for a in analyst.get("/api/audit").json() if a["actor"] == "auto"]
    assert auto and all(a["username"] is None for a in auto)    # automation isn't a person


def test_role_change_applies_immediately(app):
    admin, analyst = as_user(app, "admin"), as_user(app, "analyst")
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["username"] == "analyst")
    admin.patch(f"/api/users/{uid}", json={"role": "viewer"})
    assert analyst.post("/api/lab/run", json={"attacks": ["port_scan"]}).status_code == 403  # same token
    admin.patch(f"/api/users/{uid}", json={"active": False})
    assert analyst.get("/api/alerts").status_code == 401


def test_admin_guardrails_on_user_management(app):
    admin = as_user(app, "admin")
    me = admin.get("/api/auth/me").json()
    assert admin.patch(f"/api/users/{me['id']}", json={"role": "analyst"}).status_code == 400
    r = admin.post("/api/users", json={"username": "neha", "display_name": "Neha", "role": "analyst", "password": "short"})
    assert r.status_code == 422                                     # minimum 8 characters
    r = admin.post("/api/users", json={"username": "Neha", "display_name": "Neha", "role": "analyst",
                                       "password": "LongEnough#1"})
    assert r.status_code == 201
    assert login(admin, "neha", "LongEnough#1").status_code == 200


def test_ingest_needs_the_api_key(anon):
    event = [{"timestamp": "2026-01-01T00:00:00+00:00", "host": "web-01", "source": "auth",
              "event_type": "login_failed", "user": "x", "src_ip": "203.0.113.1"}]
    assert anon.post("/api/ingest", json=event).status_code == 401
    assert anon.post("/api/ingest", json=event, headers={"X-API-Key": "guess"}).status_code == 401
    assert anon.post("/api/ingest", json=event, headers={"X-API-Key": "lab-ingest-key"}).status_code == 200


def test_websocket_needs_a_token(app):
    from starlette.websockets import WebSocketDisconnect
    from fastapi.testclient import TestClient
    with pytest.raises(WebSocketDisconnect):
        with TestClient(app).websocket_connect("/ws") as ws:
            ws.receive_text()
    viewer = as_user(app, "viewer")
    with viewer.websocket_connect(ws_url(viewer)):
        pass                                                         # accepted


def test_every_write_route_is_in_the_policy(app):
    """Secure by default: unknown write routes need admin. This test makes sure we notice
    new endpoints, so each one gets a deliberate decision."""
    from app.auth.permissions import POLICY
    writes = {(m, r.path) for r in app.routes for m in getattr(r, "methods", set())
              if m not in ("GET", "HEAD") and r.path.startswith("/api/")
              and not r.path.startswith(("/api/auth", "/api/ingest"))}
    assert writes - set(POLICY) == set(), f"add these to auth/permissions.py: {writes - set(POLICY)}"
