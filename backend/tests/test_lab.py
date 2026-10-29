"""Attack Simulator (lab) and real-time WebSocket tests.

    docker compose exec backend pytest -v tests/test_lab.py
"""
import importlib
import sys
from pathlib import Path

import pytest
from conftest import sign_in, ws_url

ROOT = Path(__file__).resolve().parents[1]
SIM_DIR = ROOT / "simulator" if (ROOT / "simulator").exists() else ROOT.parent / "simulator"
sys.path.insert(0, str(SIM_DIR))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("MODEL_DIR", str(tmp_path / "no-model"))
    monkeypatch.setenv("SOC_AUTOTRAIN", "0")
    for mod in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[mod]
    from fastapi.testclient import TestClient
    with TestClient(importlib.import_module("app.main").app) as c:
        yield sign_in(c)
        importlib.import_module("app.lab.live").live.stop()


def test_scenarios_catalog(client):
    rows = client.get("/api/lab/scenarios").json()
    assert len(rows) == 7
    by_id = {r["id"]: r for r in rows}
    assert by_id["brute_force"]["attacker_ip"] == "203.0.113.45"
    assert by_id["suspicious_process"]["attacker_ip"] is None      # malware on our own servers
    assert all(r["blocked"] is None for r in rows)


def test_launching_an_attack_runs_the_whole_pipeline(client):
    r = client.post("/api/lab/run", json={"attacks": ["brute_force"]}).json()
    assert r["alerts_created"] >= 2 and r["incidents_created"] == 1
    assert r["responses_executed"] >= 1                     # PB-01 blocked the attacker
    inc = client.get("/api/incidents").json()[0]
    assert inc["severity"] == "critical"
    # ...and the catalog now shows the attacker as blocked.
    bf = next(s for s in client.get("/api/lab/scenarios").json() if s["id"] == "brute_force")
    assert bf["blocked"] is not None


def test_replaying_a_blocked_attacker_is_dropped(client):
    client.post("/api/lab/run", json={"attacks": ["brute_force"]})
    again = client.post("/api/lab/run", json={"attacks": ["brute_force"], "include_normal": False}).json()
    assert again["stored"] == 0 and again["dropped_blocked"] == again["received"]


def test_unknown_scenario_is_rejected(client):
    assert client.post("/api/lab/run", json={"attacks": ["teleport"]}).status_code == 422


def test_reset_containments_then_full(client):
    client.post("/api/lab/run", json={"attacks": ["brute_force"]})
    r = client.post("/api/lab/reset", json={"scope": "containments"}).json()
    assert r["released"] >= 1
    assert client.get("/api/response/containments").json() == []

    r = client.post("/api/lab/reset", json={"scope": "full"}).json()
    assert r["deleted"]["events"] > 0 and r["deleted"]["incidents"] == 1
    assert client.get("/api/incidents").json() == []
    assert client.get("/api/alerts").json() == []
    # The audit log survives the wipe (it's append-only), and the reset itself is recorded.
    audit = client.get("/api/audit").json()
    rows = audit["items"] if isinstance(audit, dict) else audit
    actions = [a["action"] for a in rows]
    assert "lab_reset" in actions and "block_ip" in actions
    assert client.get("/api/response/pending").json() == []    # approvals for deleted incidents closed


def test_websocket_pushes_feed_on_ingest(client):
    with client.websocket_connect(ws_url(client)) as ws:
        client.post("/api/lab/run", json={"attacks": ["brute_force"], "include_normal": False})
        kinds = set()
        for _ in range(10):
            msg = ws.receive_json()
            assert msg["type"] == "update" and msg["source"] == "lab"
            kinds |= {f["kind"] for f in msg["feed"]}
            if {"alert", "incident", "response"} <= kinds:
                break
        assert {"alert", "incident", "response"} <= kinds


def test_websocket_announces_analyst_actions(client):
    client.post("/api/lab/run", json={"attacks": ["brute_force"], "include_normal": False})
    alert_id = client.get("/api/alerts").json()[0]["id"]
    with client.websocket_connect(ws_url(client)) as ws:
        assert client.patch(f"/api/alerts/{alert_id}", json={"status": "investigating"}).status_code == 200
        msg = ws.receive_json()
        assert msg["source"] == "api" and msg["path"] == f"/api/alerts/{alert_id}"


def test_live_traffic_tick(client):
    live = importlib.import_module("app.lab.live").live
    live.settings.update(rate_per_min=120, attacks=True, attack_every_s=15)
    live.tick()
    s = live.status()
    assert s["ticks"] == 1 and s["events_sent"] > 0 and len(s["attacks_launched"]) == 1
    assert "_last_attack_at" not in s
    # The API can start and stop the background thread.
    assert client.post("/api/lab/live", json={"running": True, "rate_per_min": 30}).json()["running"] is True
    assert client.post("/api/lab/live", json={"running": False}).json()["running"] is False
