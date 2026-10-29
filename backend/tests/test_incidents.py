"""Incident correlation + scoring tests (rules only, so they're fast and deterministic).

    docker compose exec backend pytest -v tests/test_incidents.py
"""
import importlib
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from conftest import sign_in

ROOT = Path(__file__).resolve().parents[1]
SIM_DIR = ROOT / "simulator" if (ROOT / "simulator").exists() else ROOT.parent / "simulator"
sys.path.insert(0, str(SIM_DIR))
import simulator as sim  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("MODEL_DIR", str(tmp_path / "no-model"))
    monkeypatch.setenv("SOC_AUTOTRAIN", "0")
    for mod in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[mod]
    from fastapi.testclient import TestClient
    return sign_in(TestClient(importlib.import_module("app.main").app))


def send(client, events):
    for i in range(0, len(events), 500):
        assert client.post("/api/ingest", json=events[i:i + 500]).status_code == 200


def ago(minutes):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def incidents(client, status="all"):
    return client.get("/api/incidents", params={"status": status}).json()


def test_one_attack_one_incident(client):
    random.seed(1)
    send(client, sim.brute_force(ago(10)))
    incs = incidents(client)
    assert len(incs) == 1                                   # 3 rule alerts, ONE incident
    inc = incs[0]
    assert inc["alert_count"] == 3
    assert inc["actors"] == [sim.ATTACKERS["brute_force"]]
    assert inc["tactics"] == ["Initial Access", "Credential Access"]   # kill-chain order


def test_full_intrusion_is_stitched_together(client):
    random.seed(2)
    send(client, sim.intrusion(ago(15)))
    incs = incidents(client)
    assert len(incs) == 1, [i["title"] for i in incs]
    inc = client.get(f"/api/incidents/{incs[0]['id']}").json()
    assert len(inc["tactics"]) >= 6
    assert inc["severity"] == "critical"
    factors = {b["factor"] for b in inc["score_breakdown"]}
    assert {"Attack stages", "Confirmed access"} <= factors
    assert "bob" in [u["user"] for u in inc["users"]]
    reached = [k["tactic"] for k in inc["kill_chain"] if k["reached"]]
    assert "Exfiltration" in reached and "Discovery" in reached


def test_unrelated_attacks_stay_separate(client):
    random.seed(3)
    send(client, sim.port_scan(ago(10)) + sim.exfiltration(ago(9)) + sim.slow_scan(ago(8)))
    actors = sorted(a for i in incidents(client) for a in i["actors"])
    assert len(incidents(client)) == 2                      # scan + exfil (slow scan is invisible to rules)
    assert sim.ATTACKERS["port_scan"] in actors


def test_activity_before_login_is_not_blamed_on_attacker(client):
    random.seed(4)
    # The miner runs 10 minutes BEFORE the brute force succeeds on the same host: not the attacker's doing.
    send(client, sim.suspicious_process(ago(20)) + sim.brute_force(ago(10)))
    attacker = [i for i in incidents(client) if sim.ATTACKERS["brute_force"] in i["actors"]]
    assert len(attacker) == 1
    assert "Impact" not in attacker[0]["tactics"]          # the miner stayed in its own incident


def test_activity_after_login_is_linked(client):
    random.seed(5)
    events = sim.brute_force(ago(12))
    last = datetime.fromisoformat(events[-1]["timestamp"])
    miner = [e for e in sim.suspicious_process(last + timedelta(minutes=2)) if e["host"] == "web-01"]
    send(client, events + miner)
    incs = incidents(client)
    assert len(incs) == 1                                   # login -> miner on the same host = one attack
    assert "Impact" in incs[0]["tactics"]


def test_asset_value_raises_score(client):
    random.seed(6)
    send(client, sim.exfiltration(ago(10)))                 # db-01 = customer database (critical asset)
    inc = incidents(client)[0]
    assert any(b["factor"] == "Asset value" and b["points"] == 10 for b in inc["score_breakdown"])


def test_resolving_closes_alerts_and_new_activity_reopens(client):
    random.seed(7)
    send(client, sim.port_scan(ago(30)))
    inc_id = incidents(client)[0]["id"]
    body = client.patch(f"/api/incidents/{inc_id}", json={"status": "resolved", "note": "Scanner blocked"}).json()
    assert body["status"] == "resolved"
    assert all(a["status"] == "resolved" for a in body["alerts"])
    assert incidents(client, "active") == []

    send(client, sim.port_scan(ago(5)))                     # same scanner comes back
    active = incidents(client, "active")
    assert len(active) == 1 and active[0]["id"] != inc_id
    repeat = [b for b in active[0]["score_breakdown"] if b["factor"] == "Repeat offender"]
    assert repeat, "a returning attacker should score higher"


def test_normal_traffic_no_incidents(client):
    random.seed(8)
    send(client, sim.normal_events(ago(60), 60))
    assert incidents(client) == []
