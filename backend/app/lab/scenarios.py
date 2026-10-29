"""The attack scenarios you can launch from the Attack Simulator page.

They reuse the generators in simulator/simulator.py (the same code the CLI and the
ML training use). A launched attack is shifted in time so it ENDS right now: it
looks exactly like an attack that just happened, so detection, correlation and
automated response all kick in within the same second.
"""
import random
from datetime import datetime, timedelta, timezone

from ..ml.dataset import load_simulator

# What each scenario is, and what the SOC should do about it (shown on the page).
CATALOG = [
    {"id": "brute_force", "name": "SSH brute force", "target": "web-01",
     "techniques": ["T1110", "T1110.003", "T1078"], "detected_by": ["rules", "ml"],
     "description": "25-40 password guesses against several accounts in about a minute, then a successful login as alice.",
     "expect": "Critical incident. The attacker is blocked automatically (PB-01); isolating web-01 waits for approval (PB-05)."},
    {"id": "port_scan", "name": "Port scan", "target": "web-02",
     "techniques": ["T1046"], "detected_by": ["rules", "ml"],
     "description": "120 different ports probed in about 10 seconds, mapping which services are open.",
     "expect": "Medium incident. Scanning alone isn't blocked automatically: no playbook fires."},
    {"id": "suspicious_process", "name": "Crypto-miner + web shell", "target": "web-01, web-02",
     "techniques": ["T1496", "T1564.001", "T1505.003", "T1059.004"], "detected_by": ["rules", "ml"],
     "description": "xmrig runs from a hidden /tmp folder at 97% CPU; nginx spawns a shell that launches netcat.",
     "expect": "Two incidents. xmrig is quarantined automatically (PB-03); isolating web-02 waits for approval."},
    {"id": "exfiltration", "name": "Data exfiltration", "target": "db-01",
     "techniques": ["T1041", "T1571"], "detected_by": ["rules", "ml"],
     "description": "The customer database sends 5-50 MB at a time to an outside server on port 4444.",
     "expect": "High incident (critical asset). The destination is blocked automatically (PB-04)."},
    {"id": "slow_brute_force", "name": "Slow brute force (stealthy)", "target": "web-02",
     "techniques": ["T1110"], "detected_by": ["ml"],
     "description": "One guess every ~20 seconds at a single account: never fast enough for any rule.",
     "expect": "No rule fires. Only the ML detector catches it, as a medium incident."},
    {"id": "slow_scan", "name": "Slow port scan (stealthy)", "target": "web-01",
     "techniques": ["T1046"], "detected_by": ["ml"],
     "description": "One port every ~5 seconds: about 12 per minute, under the 20-port rule threshold.",
     "expect": "No rule fires. Only the ML detector catches it, as a medium incident."},
    {"id": "intrusion", "name": "Full intrusion (kill chain)", "target": "dev-laptop-07",
     "techniques": ["T1046", "T1110", "T1078", "T1059", "T1564.001", "T1571", "T1041"], "detected_by": ["rules", "ml"],
     "description": "One attacker, 8 ATT&CK stages in ~6 minutes: scan, brute force, login as bob, malware, C2, exfiltration.",
     "expect": "One critical incident from ~11 alerts. Attacker blocked and malware quarantined within a second; isolation waits for approval."},
]
CATALOG_BY_ID = {c["id"]: c for c in CATALOG}


def attacker_of(sim, scenario_id: str) -> str | None:
    return sim.ATTACKERS.get(scenario_id)


def shift_to_end_at(events: list[dict], end: datetime) -> list[dict]:
    """Move an attack in time so its last event happens at `end`."""
    if not events:
        return events
    times = [datetime.fromisoformat(e["timestamp"]) for e in events]
    delta = end - max(times)
    for e, t in zip(events, times):
        e["timestamp"] = (t + delta).isoformat()
    return events


def build_scenario(scenario_id: str, background: bool = True) -> list[dict]:
    """One attack ending now, plus normal traffic around it (so it hides in a realistic crowd)."""
    sim = load_simulator(reload=False)
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    attack = shift_to_end_at(sim.ATTACK_FUNCS[scenario_id](now), now)
    events = list(attack)
    if background:
        start = min(datetime.fromisoformat(e["timestamp"]) for e in attack) - timedelta(minutes=2)
        minutes = max(1, int((now - start).total_seconds() // 60) + 1)
        events += [e for e in sim.normal_events(start, minutes) if datetime.fromisoformat(e["timestamp"]) <= now]
    return sorted(events, key=lambda e: e["timestamp"])


def build_full_demo(minutes: int = 30) -> list[dict]:
    """Same as `python simulator.py`: `minutes` of normal traffic with all 7 attacks hidden in it."""
    sim = load_simulator(reload=False)
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    start = now - timedelta(minutes=minutes)
    events = sim.normal_events(start, minutes)
    for name in sim.ALL_ATTACKS:
        at = start + timedelta(seconds=random.uniform(0, max(60, minutes * 60 - 600)))
        attack = sim.ATTACK_FUNCS[name](at)
        if attack and datetime.fromisoformat(max(e["timestamp"] for e in attack)) > now:
            attack = shift_to_end_at(attack, now)
        events += attack
    return sorted(events, key=lambda e: e["timestamp"])
