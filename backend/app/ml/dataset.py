"""Training data.

Models need lots of labeled examples. We build them from the SAME simulator that
feeds the dashboard, but with variety: each "scenario" is 30 minutes of normal
traffic plus a random mix of attacks at random intensities - some loud, some
weakened (fewer attempts, spread out over time, smaller transfers).

Why weaken attacks? If every training attack is a loud 40-attempt burst, the
model gets 100% accuracy and learns nothing useful. Harder examples give
honest metrics and a model that generalises to quieter attacks.

Labeled events already in your database can be added too (include_db=True).
"""
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def load_simulator(reload: bool = True):
    """reload=True picks up simulator edits without restarting the API (used for training);
    the lab's live traffic generator calls this every few seconds, so it skips the reload."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[2] / "simulator", here.parents[3] / "simulator"):   # Docker, then local checkout
        if (candidate / "simulator.py").exists():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            import importlib  # noqa: PLC0415
            import simulator  # noqa: PLC0415
            return importlib.reload(simulator) if reload else simulator
    raise RuntimeError("simulator/simulator.py not found - it's needed to generate training data")


def _ts(e):
    return datetime.fromisoformat(e["timestamp"])


def _stretch(events, factor):
    """Spread an attack out over time (factor 3 = three times slower)."""
    if not events:
        return events
    t0 = _ts(events[0])
    for e in events:
        e["timestamp"] = (t0 + (_ts(e) - t0) * factor).isoformat()
    return events


def _thin(events, keep, keep_last=False):
    """Drop a random share of an attack's events (a weaker attack)."""
    last = events[-1] if keep_last else None
    body = events[:-1] if keep_last else events
    kept = [e for e in body if random.random() < keep] or body[:1]
    return kept + ([last] if last else [])


def _variants(sim, at):
    """Every attack the model trains on, with randomised intensity."""
    def brute():
        ev = sim.brute_force(at)
        return _stretch(_thin(ev, random.uniform(0.25, 1), keep_last=random.random() < 0.6), random.uniform(1, 4))

    def scan():
        return _stretch(_thin(sim.port_scan(at), random.uniform(0.1, 1)), random.uniform(1, 6))

    def proc():
        ev = sim.suspicious_process(at)
        return random.sample(ev, random.randint(1, len(ev)))

    def exfil():
        ev = _thin(sim.exfiltration(at), random.uniform(0.3, 1))
        scale = random.uniform(0.02, 1)
        for e in ev:
            e["bytes_sent"] = int(e["bytes_sent"] * scale)
        return ev

    return {
        "brute_force": brute,
        "port_scan": scan,
        "suspicious_process": proc,
        "exfiltration": exfil,
        "slow_brute_force": lambda: sim.slow_brute_force(at),
        "slow_scan": lambda: sim.slow_scan(at),
        "intrusion": lambda: sim.intrusion(at),
    }


def generate_scenarios(n: int = 40, seed: int = 42, minutes: int = 30) -> list[list[dict]]:
    """Returns n independent scenarios, each a list of event dicts (with `_variant` tags on attacks)."""
    sim = load_simulator()
    state = random.getstate()
    random.seed(seed)
    scenarios = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    try:
        for i in range(n):
            start = base + timedelta(days=i)   # scenarios never overlap in time
            # Quiet nights to busy mornings (and overlapping simulator runs): busier
            # traffic alone must never look like an attack.
            events = sim.normal_events(start, minutes, rate_per_min=random.choice([8, 12, 20, 30, 45, 60, 90]))
            for name in sim.ALL_ATTACKS:
                if random.random() < 0.55:
                    at = start + timedelta(seconds=random.uniform(0, (minutes - 8) * 60))
                    attack = _variants(sim, at)[name]()
                    for e in attack:
                        e["_variant"] = name
                    events += attack
            events.sort(key=lambda e: e["timestamp"])
            scenarios.append(events)
    finally:
        random.setstate(state)
    return scenarios
