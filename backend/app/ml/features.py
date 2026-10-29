"""Feature engineering: turning raw log lines into numbers a model can learn from.

ML models don't read logs. They read rows of numbers. So we:

1. Group events into WINDOWS: everything one entity did in one minute.
   - entity = the source IP for login and network events
   - entity = the host for process events ("host:web-01")
2. Describe each window with 14 numbers (the FEATURES below).

One window = one row = one prediction. A brute-force minute looks like
(failed_logins=25, distinct_users=6, ...); a normal minute looks like
(failed_logins=0, distinct_users=1, ...). The model learns that difference.

The "unseen_*" features are learned from normal traffic: anything never seen
before (a new process name, a new port, a new parent->child process pair) is
worth noticing. This is how ML can catch attacks no rule describes.
"""
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np

from ..utils import is_external

WINDOW_SECONDS = 60

# (name, plain-English description) - shown on the ML Models page.
FEATURES = [
    ("events", "Total events from the entity in the minute"),
    ("failed_logins", "Failed login attempts"),
    ("successful_logins", "Successful logins"),
    ("distinct_users", "Different usernames used"),
    ("distinct_dst_ports", "Different destination ports contacted"),
    ("distinct_dst_ips", "Different destination IPs contacted"),
    ("unseen_ports", "Destination ports never seen in normal traffic"),
    ("log_bytes_out", "Data sent, log scale: log(1 + bytes)"),
    ("external_dst_share", "Share of connections going OUT to the internet"),
    ("external_source", "1 if the entity's IP is outside our network"),
    ("max_cpu", "Highest CPU % of any process started"),
    ("unseen_processes", "Process names never seen in normal traffic"),
    ("unseen_parent_child", "Parent → child process pairs never seen in normal traffic"),
    ("hosts_touched", "Different hosts involved"),
]
FEATURE_NAMES = [f for f, _ in FEATURES]

# The Isolation Forest only sees these 10 behaviour features. "events", "successful_logins",
# "distinct_dst_ips" and "hosts_touched" vary a lot in harmless ways (a busy employee), and
# Isolation Forests are known to get worse when given noisy, irrelevant features: random splits
# get wasted on them. We tested both sets; this one found ~67% vs ~45% of attacks at the same
# false-alarm rate. The Random Forest still uses all 14 (it learns which ones matter).
IF_FEATURES = ["failed_logins", "distinct_users", "distinct_dst_ports", "unseen_ports", "log_bytes_out",
               "external_dst_share", "external_source", "max_cpu", "unseen_processes", "unseen_parent_child"]
IF_COLS = [FEATURE_NAMES.index(f) for f in IF_FEATURES]

def is_internal(ip: str | None) -> bool:
    return bool(ip) and not is_external(ip)


def parse_ts(ts) -> datetime:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


EVENT_FIELDS = ["id", "timestamp", "host", "source", "event_type", "user", "src_ip", "dst_ip", "dst_port",
                "bytes_sent", "process_name", "process_path", "parent_process", "pid", "cpu_percent", "label"]


def event_to_dict(e) -> dict:
    """DB rows and simulator dicts both become plain dicts, so one code path handles both."""
    if isinstance(e, dict):
        return e
    return {f: getattr(e, f, None) for f in EVENT_FIELDS}


@dataclass
class Window:
    entity: str
    bucket: int                        # minute number since epoch
    events: list = field(default_factory=list)

    @property
    def start(self) -> datetime:
        return datetime.fromtimestamp(self.bucket * WINDOW_SECONDS, tz=timezone.utc)

    @property
    def host(self) -> str | None:
        hosts = Counter(e["host"] for e in self.events)
        return hosts.most_common(1)[0][0] if hosts else None

    @property
    def label(self) -> str:
        """Ground truth for training: if ANY event in the window is an attack, the window is that attack."""
        attacks = Counter(e.get("label") for e in self.events if e.get("label") not in (None, "normal"))
        return attacks.most_common(1)[0][0] if attacks else "normal"

    @property
    def variant(self) -> str:
        """Which simulator scenario produced it (e.g. slow_brute_force). Only exists in training data."""
        v = Counter(e.get("_variant") for e in self.events if e.get("_variant"))
        return v.most_common(1)[0][0] if v else self.label


def entity_of(e: dict) -> str | None:
    if e.get("src_ip"):
        return e["src_ip"]
    if e.get("source") == "process":
        return f"host:{e['host']}"
    return None


def make_windows(events) -> list[Window]:
    windows: dict[tuple, Window] = {}
    for raw in events:
        e = event_to_dict(raw)
        ent = entity_of(e)
        if ent is None:
            continue
        bucket = int(parse_ts(e["timestamp"]).timestamp() // WINDOW_SECONDS)
        w = windows.get((ent, bucket))
        if w is None:
            w = windows[(ent, bucket)] = Window(ent, bucket)
        w.events.append(e)
    return list(windows.values())


@dataclass
class Vocab:
    """What 'normal' looks like, learned from normal training events."""
    ports: set
    processes: set
    parent_child: set

    @classmethod
    def from_events(cls, events) -> "Vocab":
        ports, procs, pairs = set(), set(), set()
        for raw in events:
            e = event_to_dict(raw)
            if e.get("label") not in (None, "normal"):
                continue
            if e.get("dst_port") is not None:
                ports.add(e["dst_port"])
            if e.get("process_name"):
                procs.add(e["process_name"])
                pairs.add((e.get("parent_process"), e["process_name"]))
        return cls(ports, procs, pairs)


def featurize(w: Window, vocab: Vocab) -> list[float]:
    ev = w.events
    auth = [e for e in ev if e["source"] == "auth"]
    net = [e for e in ev if e["source"] == "network"]
    proc = [e for e in ev if e["source"] == "process"]
    ports = {e["dst_port"] for e in net if e.get("dst_port") is not None}
    entity_ip = None if w.entity.startswith("host:") else w.entity
    return [
        len(ev),
        sum(e["event_type"] == "login_failed" for e in auth),
        sum(e["event_type"] == "login_success" for e in auth),
        len({e.get("user") for e in auth if e.get("user")}),
        len(ports),
        len({e.get("dst_ip") for e in net if e.get("dst_ip")}),
        len(ports - vocab.ports),
        math.log1p(sum(e.get("bytes_sent") or 0 for e in net)),
        (sum(not is_internal(e.get("dst_ip")) for e in net) / len(net)) if net else 0.0,
        1.0 if entity_ip and not is_internal(entity_ip) else 0.0,
        max((e.get("cpu_percent") or 0 for e in proc), default=0.0),
        len({e["process_name"] for e in proc if e.get("process_name") and e["process_name"] not in vocab.processes}),
        len({(e.get("parent_process"), e.get("process_name")) for e in proc} - vocab.parent_child) if proc else 0,
        len({e["host"] for e in ev}),
    ]


def feature_matrix(windows: list[Window], vocab: Vocab) -> np.ndarray:
    if not windows:
        return np.zeros((0, len(FEATURES)))
    return np.array([featurize(w, vocab) for w in windows], dtype=float)


def if_transform(X: np.ndarray) -> np.ndarray:
    """Log-scale features for the Isolation Forest.

    The forest picks split points uniformly between a feature's min and max. On a
    raw scale where a loud scan hits 120 ports, a quiet scan's 12 ports sits right
    next to normal's 2 and is rarely separated. log(1+x) spreads out the small
    values, so moderate anomalies get isolated too. (Random Forests don't need this:
    they choose split points by learning, not at random.)
    """
    return np.log1p(np.clip(X[:, IF_COLS], 0, None))
