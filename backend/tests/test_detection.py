"""Detection tests. Run from the backend folder:

    docker compose exec backend pytest -v

Each test uses a fresh throwaway SQLite database, so your real data is untouched.
They use the SAME simulator that generates your demo traffic.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest
from conftest import sign_in

ROOT = Path(__file__).resolve().parents[1]
SIM_DIR = ROOT / "simulator"                         # inside Docker: /code/simulator (mounted)
if not SIM_DIR.exists():
    SIM_DIR = ROOT.parent / "simulator"              # running from a normal checkout
sys.path.insert(0, str(SIM_DIR))
import simulator as sim  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("MODEL_DIR", str(tmp_path / "no-model"))   # rules only: no ML model here
    monkeypatch.setenv("SOC_AUTOTRAIN", "0")
    for mod in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[mod]                         # re-import app against the temp DB
    main = importlib.import_module("app.main")
    from fastapi.testclient import TestClient
    return sign_in(TestClient(main.app))


def send(client, events):
    r = client.post("/api/ingest", json=events)
    assert r.status_code == 200, r.text
    return r.json()


def window(minutes=30):
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def rules_fired(client):
    return {a["rule_id"] for a in client.get("/api/alerts").json()}


def test_normal_traffic_has_no_false_positives(client):
    sim.random.seed(1)
    send(client, sim.normal_events(window(120), minutes=120))   # 2,400 normal events
    assert client.get("/api/alerts").json() == []


def test_brute_force_detected_and_success_is_critical(client):
    sim.random.seed(2)
    send(client, sim.normal_events(window(), 30) + sim.brute_force(window(10)))
    fired = rules_fired(client)
    assert {"SOC-001", "SOC-002", "SOC-003"} <= fired
    critical = [a for a in client.get("/api/alerts").json() if a["rule_id"] == "SOC-002"][0]
    assert critical["severity"] == "critical"
    assert critical["entity"] == sim.ATTACKERS["brute_force"]
    assert critical["metrics"]["compromised_users"] == ["alice"]


def test_port_scan_detected(client):
    sim.random.seed(3)
    send(client, sim.port_scan(window(5)))
    assert "SOC-004" in rules_fired(client)


def test_process_and_exfil_rules(client):
    sim.random.seed(4)
    send(client, sim.suspicious_process(window(5)) + sim.exfiltration(window(5)))
    assert {"SOC-005", "SOC-006", "SOC-007", "SOC-008", "SOC-009", "SOC-010", "SOC-011"} <= rules_fired(client)


def test_alerts_are_deduplicated(client):
    sim.random.seed(5)
    events = sim.brute_force(window(10))
    send(client, events[:15])               # first half of the attack arrives
    send(client, events[15:])               # ...then the rest in a later batch
    send(client, events)                    # ...and a duplicate re-send
    brute = [a for a in client.get("/api/alerts").json() if a["rule_id"] == "SOC-001"]
    assert len(brute) == 1                  # one alert, not three
    assert brute[0]["event_count"] >= 25


def test_disabled_rule_does_not_fire(client):
    client.patch("/api/rules/SOC-004", json={"enabled": False})
    sim.random.seed(6)
    send(client, sim.port_scan(window(5)))
    assert "SOC-004" not in rules_fired(client)


def test_threshold_tuning(client):
    client.patch("/api/rules/SOC-004", json={"params": {"distinct_ports": 500}})   # scan only hits 120 ports
    sim.random.seed(7)
    send(client, sim.port_scan(window(5)))
    assert "SOC-004" not in rules_fired(client)


def test_triage_status_and_notes(client):
    sim.random.seed(8)
    send(client, sim.port_scan(window(5)))
    alert_id = client.get("/api/alerts").json()[0]["id"]
    r = client.patch(f"/api/alerts/{alert_id}", json={"status": "resolved", "note": "Blocked at firewall"})
    body = r.json()
    assert body["status"] == "resolved"
    assert any(n["text"] == "Blocked at firewall" for n in body["notes"])
    assert client.get("/api/alerts", params={"status": "open"}).json() == []


def test_inbound_scan_touching_attack_port_is_not_c2(client):
    # Regression: an inbound port scan that happens to probe 4444 must not fire SOC-011
    # (that rule is about OUR hosts connecting OUT to attacker infrastructure).
    sim.random.seed(9)
    events = sim.port_scan(window(5))
    events[0]["dst_port"] = 4444
    send(client, events)
    assert "SOC-011" not in rules_fired(client)
