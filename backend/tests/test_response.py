"""Automated response tests: playbooks, guardrails, the simulated firewall/EDR, approvals, audit.

    docker compose exec backend pytest -v tests/test_response.py
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
    out = {"stored": 0, "dropped_blocked": 0}
    for i in range(0, len(events), 500):
        r = client.post("/api/ingest", json=events[i:i + 500]).json()
        out["stored"] += r["stored"]
        out["dropped_blocked"] += r["dropped_blocked"]
    return out


def ago(minutes):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def blocks(client):
    return {c["target"]: c for c in client.get("/api/response/containments", params={"kind": "ip"}).json()}


def test_critical_incident_auto_blocks_attacker(client):
    random.seed(1)
    send(client, sim.brute_force(ago(10)))                  # ends in a successful login -> critical
    ip = sim.ATTACKERS["brute_force"]
    b = blocks(client)
    assert ip in b and b[ip]["created_by"] == "auto" and b[ip]["playbook_id"] == "PB-01"
    assert b[ip]["expires_at"] is not None                  # automatic blocks are temporary

    inc = client.get("/api/incidents").json()[0]
    assert inc["status"] == "contained"

    again = send(client, sim.brute_force(ago(2)))           # the attacker tries again...
    assert again["dropped_blocked"] > 0 and again["stored"] == 0   # ...and the firewall drops it all
    assert blocks(client)[ip]["dropped_count"] == again["dropped_blocked"]


def test_malware_is_quarantined_and_cannot_run_again(client):
    random.seed(2)
    events = [e for e in sim.suspicious_process(ago(10)) if e["host"] == "web-01"]   # xmrig from /tmp
    send(client, events)
    procs = client.get("/api/response/containments", params={"kind": "process"}).json()
    assert [p["target"] for p in procs] == ["web-01:/tmp/.x/xmrig"]
    rerun = send(client, [dict(events[0], timestamp=ago(1).isoformat())])
    assert rerun["dropped_blocked"] == 1                    # EDR stops it starting again


def test_exfil_destination_blocked_automatically(client):
    random.seed(3)
    send(client, sim.exfiltration(ago(10)))
    assert sim.ATTACKERS["exfiltration"] in blocks(client)


def test_host_isolation_needs_approval(client):
    random.seed(4)
    send(client, [e for e in sim.suspicious_process(ago(10)) if e["host"] == "web-02"])   # web shell
    pending = client.get("/api/response/pending").json()
    iso = [p for p in pending if p["action"] == "isolate_host"]
    assert len(iso) == 1 and iso[0]["target"] == "web-02" and iso[0]["playbook_id"] == "PB-05"
    assert client.get("/api/response/containments", params={"kind": "host"}).json() == []   # nothing yet

    decided = client.post(f"/api/response/pending/{iso[0]['id']}/approve").json()
    assert decided["status"] == "success" and decided["actor"] == "analyst"
    traffic = [e for e in sim.normal_events(ago(5), 5) if e["host"] == "web-02" and e["source"] == "network"]
    assert send(client, traffic)["dropped_blocked"] == len(traffic)   # isolated host is cut off


def test_rejecting_a_pending_action(client):
    random.seed(5)
    send(client, [e for e in sim.suspicious_process(ago(10)) if e["host"] == "web-02"])
    pid = client.get("/api/response/pending").json()[0]["id"]
    assert client.post(f"/api/response/pending/{pid}/reject").json()["status"] == "rejected"
    assert client.get("/api/response/pending").json() == []


@pytest.mark.parametrize("ip,why", [("10.0.0.5", "internal"), ("8.8.8.8", "allowlisted"), ("not-an-ip", "valid")])
def test_guardrails_refuse_dangerous_blocks(client, ip, why):
    r = client.post("/api/response/actions", json={"action": "block_ip", "ip": ip})
    assert r.status_code == 422 and why in r.json()["detail"]
    log = client.get("/api/audit", params={"status": "blocked_by_guardrail"}).json()
    assert log and log[0]["target"] == ip                    # refusals are audited too


def test_critical_asset_never_isolated_automatically(client):
    client.patch("/api/response/playbooks/PB-05", json={"mode": "auto"})   # analyst makes isolation automatic...
    random.seed(6)
    events = sim.brute_force(ago(10))
    for e in events:
        e["host"] = "db-01"                                   # ...and the customer database gets compromised
    send(client, events)
    assert client.get("/api/response/containments", params={"kind": "host"}).json() == []
    refused = client.get("/api/audit", params={"status": "blocked_by_guardrail"}).json()
    assert any(a["target"] == "db-01" for a in refused)


def test_manual_block_unblock_and_audit(client):
    r = client.post("/api/response/actions", json={"action": "block_ip", "ip": "198.51.100.200", "reason": "threat intel"})
    assert r.status_code == 200
    cid = r.json()["containment"]["id"]
    assert send(client, sim.port_scan(ago(5)) and [dict(e, src_ip="198.51.100.200") for e in sim.port_scan(ago(5))])["stored"] == 0
    client.post(f"/api/response/containments/{cid}/release")
    assert send(client, [dict(e, src_ip="198.51.100.200") for e in sim.port_scan(ago(3))])["stored"] > 0
    actions = [a["action"] for a in client.get("/api/audit").json()]
    assert "block_ip" in actions and "unblock_ip" in actions


def test_disabled_playbook_does_nothing(client):
    client.patch("/api/response/playbooks/PB-01", json={"enabled": False})
    random.seed(7)
    send(client, sim.brute_force(ago(10)))
    assert sim.ATTACKERS["brute_force"] not in blocks(client)
    assert any(a["action"] == "playbook_updated" for a in client.get("/api/audit", params={"category": "config"}).json())


def test_expired_block_is_lifted(client):
    random.seed(8)
    send(client, sim.brute_force(ago(10)))
    ip = sim.ATTACKERS["brute_force"]
    from app.database import SessionLocal
    from app.models import Containment
    with SessionLocal() as db:                                # fast-forward 25 hours
        c = db.query(Containment).filter_by(target=ip).one()
        c.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    assert ip not in blocks(client)
    assert any(a["action"] == "unblock_ip" and a["actor"] == "system" for a in client.get("/api/audit").json())


def test_release_all_resets_lab(client):
    random.seed(9)
    send(client, sim.brute_force(ago(10)) + sim.exfiltration(ago(9)))
    assert len(blocks(client)) >= 2
    assert client.post("/api/response/release-all").json()["released"] >= 2
    assert blocks(client) == {}


def test_full_intrusion_response(client):
    random.seed(10)
    send(client, sim.intrusion(ago(15)))
    inc = client.get(f"/api/incidents/{client.get('/api/incidents').json()[0]['id']}").json()
    assert inc["status"] == "contained"
    done = {s["kind"] for s in inc["response"]["suggestions"] if s["done"]}
    assert {"ip", "process"} <= done                        # attacker blocked + kworkerd quarantined
    assert any(p["action"] == "isolate_host" for p in inc["response"]["pending"])   # laptop isolation awaits approval
    summary = client.get("/api/response/summary").json()
    assert summary["time_to_contain_s"]["auto"] is not None and summary["time_to_contain_s"]["auto"] < 5


def test_containment_closes_stale_approval_request(client):
    # PB-02 asks an analyst to approve blocking the exfil server (high incident)... but the IP gets
    # blocked another way first. The old request must not linger in the approval queue.
    client.patch("/api/response/playbooks/PB-04", json={"enabled": False})
    random.seed(11)
    send(client, sim.exfiltration(ago(10)))
    ip = sim.ATTACKERS["exfiltration"]
    assert any(p["target"] == ip for p in client.get("/api/response/pending").json())
    client.post("/api/response/actions", json={"action": "block_ip", "ip": ip})
    assert client.get("/api/response/pending").json() == []
    assert any(a["status"] == "skipped" and a["target"] == ip for a in client.get("/api/audit").json())
