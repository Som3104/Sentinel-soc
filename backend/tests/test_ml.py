"""ML tests. A small model is trained once (~2s) into a temp folder, then reused.

    docker compose exec backend pytest -v tests/test_ml.py
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


def _fresh_app():
    for mod in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[mod]
    return importlib.import_module("app.main")


@pytest.fixture(scope="module")
def model_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("models")
    mp = pytest.MonkeyPatch()
    mp.setenv("MODEL_DIR", str(d))
    mp.setenv("SOC_AUTOTRAIN", "0")
    mp.setenv("DATABASE_URL", f"sqlite:///{d / 'train.db'}")
    _fresh_app()
    from app.ml.train import train
    metrics = train(n_scenarios=20, seed=7, include_db=False)
    yield d, metrics
    mp.undo()


@pytest.fixture()
def client(model_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("MODEL_DIR", str(model_dir[0]))
    monkeypatch.setenv("SOC_AUTOTRAIN", "0")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    from fastapi.testclient import TestClient
    return sign_in(TestClient(_fresh_app().app))


def send(client, events):
    for i in range(0, len(events), 500):
        assert client.post("/api/ingest", json=events[i:i + 500]).status_code == 200


def ago(minutes):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def test_metrics_are_reasonable(model_dir):
    m = model_dir[1]
    assert m["ml_detector"]["recall"] >= 0.75
    assert m["ml_detector"]["false_positive_rate"] <= 0.001
    assert m["random_forest"]["macro_f1"] >= 0.85
    # The whole point of adding ML: it catches attacks the rules miss.
    assert m["combined"]["recall"] > m["rules"]["recall"]
    assert m["by_variant"]["slow_brute_force"]["rules"] == 0


def test_stealthy_attacks_caught_only_by_ml(client):
    random.seed(11)
    send(client, sim.normal_events(ago(30), 30)
         + sim.slow_brute_force(ago(25)) + sim.slow_scan(ago(20)))
    alerts = client.get("/api/alerts").json()
    by_entity = {}
    for a in alerts:
        by_entity.setdefault(a["entity"], set()).add(a["detector"])
    assert by_entity.get(sim.ATTACKERS["slow_brute_force"]) == {"ml"}
    assert by_entity.get(sim.ATTACKERS["slow_scan"]) == {"ml"}


def test_false_alarm_budget_on_busy_normal_traffic(client):
    """ML is statistical, so we test a BUDGET rather than demanding exactly zero:
    on 7,200 busy normal events (~3,000 one-minute windows) allow at most ONE alert,
    and only a low-priority one. Rules must stay at zero."""
    start = ago(120)
    for i in range(3):                               # three overlapping runs = ~60 events/minute
        random.seed(500 + i)
        send(client, sim.normal_events(start, 120))
    alerts = client.get("/api/alerts").json()
    assert all(a["detector"] == "ml" for a in alerts), "rules must not fire on normal traffic"
    assert len(alerts) <= 1
    assert all(a["severity"] == "low" for a in alerts)


def test_ml_alert_explains_itself(client):
    random.seed(12)
    send(client, sim.port_scan(ago(5)))
    ml = [a for a in client.get("/api/alerts").json() if a["detector"] == "ml"]
    assert ml, "port scan should also be flagged by ML"
    detail = client.get(f"/api/alerts/{ml[0]['id']}").json()
    assert detail["mitre_technique"] == "T1046"
    assert detail["metrics"]["signals"], "should list the unusual features"


def test_disabling_ml(client):
    client.patch("/api/rules/ML-001", json={"enabled": False})
    random.seed(13)
    send(client, sim.slow_scan(ago(10)))
    assert all(a["detector"] != "ml" for a in client.get("/api/alerts").json())


def test_status_endpoint(client):
    s = client.get("/api/ml/status").json()
    assert s["trained"] and s["enabled"]
    assert "confusion_matrix" in s["metrics"]["random_forest"]
