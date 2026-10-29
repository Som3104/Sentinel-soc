"""The detection rule library.

Each rule is a RuleDef: metadata (name, MITRE ATT&CK mapping, severity,
default thresholds) plus a Python function holding the detection logic.

Two kinds of rules:
  * Single-event rules  - one log line is enough ("xmrig started from /tmp").
  * Windowed rules      - a PATTERN over time ("5+ failed logins from one IP
                          within 60 seconds"). These use `bursts()` below.

Thresholds live in `params`, so analysts can tune them from the Rules page
without touching code. Every rule was checked against normal simulator traffic
to make sure it produces zero false positives on the baseline.
"""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Event
from ..utils import aware, is_external


# --------------------------------------------------------------------------- data types
@dataclass
class Match:
    """One rule hit, before it's turned into (or merged into) an Alert."""
    entity: str                    # who/what the alert is about: an IP or a host
    host: str | None
    events: list[Event]            # the evidence
    summary: str                   # one human-readable sentence
    metrics: dict = field(default_factory=dict)
    key: str | None = None         # dedup key suffix; defaults to entity
    # ML matches decide these per match (rules use the rule's own settings):
    title: str | None = None
    severity: str | None = None
    score: float | None = None
    technique: str | None = None
    tactic: str | None = None

    @property
    def first_seen(self) -> datetime:
        return min(aware(e.timestamp) for e in self.events)

    @property
    def last_seen(self) -> datetime:
        return max(aware(e.timestamp) for e in self.events)


@dataclass
class RuleDef:
    id: str
    name: str
    description: str
    source: str
    tactic: str
    technique: str
    technique_name: str
    severity: str
    params: dict
    logic: str                     # human-readable logic, {placeholders} filled from params
    recommended: list[str]
    fn: Callable[[Session, dict, datetime, datetime], list[Match]]
    detector: str = "rule"         # rule | ml
    fixed_lookback: int = 0
    # Correlation scope (Phase 5): "actor" = the alert is about an outside attacker's IP;
    # "asset" = it's about something happening ON one of our machines.
    scope: str = "asset"

    def lookback_seconds(self, params: dict) -> int:
        """How far BEFORE the new data a windowed rule must look to see a whole pattern."""
        return max(self.fixed_lookback,
                   int(params.get("window_seconds", 0)) + int(params.get("success_within_seconds", 0)))


# --------------------------------------------------------------------------- helpers
def fetch(db: Session, start: datetime, end: datetime, *conditions) -> list[Event]:
    q = select(Event).where(Event.timestamp >= start, Event.timestamp <= end, *conditions)
    return list(db.scalars(q.order_by(Event.timestamp, Event.id)).all())


def group_by(events, key):
    groups = defaultdict(list)
    for e in events:
        k = key(e)
        if k is not None:
            groups[k].append(e)
    return groups


def bursts(events: list[Event], window_s: int, metric: Callable[[list[Event]], float], threshold: float):
    """Sliding-window detector.

    Slides a `window_s`-second window across time-sorted events. Whenever
    metric(events in window) >= threshold, those events are marked "hot".
    Hot events closer together than the window are merged into one burst.

    Example: metric=len, threshold=5, window=60 -> "5+ events within 60s".
    Returns a list of bursts (each a list of events).
    """
    if not events:
        return []
    win = timedelta(seconds=window_s)
    ts = [aware(e.timestamp) for e in events]
    hot = [False] * len(events)
    left = 0
    for right in range(len(events)):
        while ts[right] - ts[left] > win:
            left += 1
        if metric(events[left:right + 1]) >= threshold:
            for i in range(left, right + 1):
                hot[i] = True

    groups, current, last = [], [], None
    for i, e in enumerate(events):
        if not hot[i]:
            continue
        if current and ts[i] - last > win:
            groups.append(current)
            current = []
        current.append(e)
        last = ts[i]
    if current:
        groups.append(current)
    return groups


def distinct(attr):
    return lambda evs: len({getattr(e, attr) for e in evs})


def duration_s(events) -> int:
    return int((aware(events[-1].timestamp) - aware(events[0].timestamp)).total_seconds())


def top_host(events) -> str | None:
    hosts = Counter(e.host for e in events)
    return hosts.most_common(1)[0][0] if hosts else None


# --------------------------------------------------------------------------- AUTH rules
def r_brute_force(db, p, start, end):
    failures = fetch(db, start, end, Event.event_type == "login_failed", Event.src_ip.is_not(None))
    out = []
    for ip, evs in group_by(failures, lambda e: e.src_ip).items():
        for b in bursts(evs, p["window_seconds"], len, p["threshold"]):
            users = Counter(e.user for e in b)
            out.append(Match(
                entity=ip, host=top_host(b), events=b,
                summary=f"{len(b)} failed logins from {ip} in {duration_s(b)}s against {len(users)} account(s)",
                metrics={"failed_logins": len(b), "distinct_users": len(users), "duration_s": duration_s(b),
                         "top_users": dict(users.most_common(5)), "external_source": is_external(ip)},
            ))
    return out


def r_brute_force_success(db, p, start, end):
    auth = fetch(db, start, end, Event.source == "auth", Event.src_ip.is_not(None))
    out = []
    follow = timedelta(seconds=p["success_within_seconds"])
    for ip, evs in group_by(auth, lambda e: e.src_ip).items():
        failures = [e for e in evs if e.event_type == "login_failed"]
        successes = [e for e in evs if e.event_type == "login_success"]
        if not successes:
            continue
        for b in bursts(failures, p["window_seconds"], len, p["threshold"]):
            b_start, b_end = aware(b[0].timestamp), aware(b[-1].timestamp)
            wins = [s for s in successes if b_start <= aware(s.timestamp) <= b_end + follow]
            if not wins:
                continue
            users = sorted({s.user for s in wins})
            out.append(Match(
                entity=ip, host=top_host(wins), events=b + wins,
                summary=f"{ip} logged in as {', '.join(users)} right after {len(b)} failed attempts - likely compromised account",
                metrics={"failed_before_success": len(b), "compromised_users": users,
                         "seconds_to_success": int((aware(wins[0].timestamp) - b_start).total_seconds())},
            ))
    return out


def r_password_spray(db, p, start, end):
    failures = fetch(db, start, end, Event.event_type == "login_failed", Event.src_ip.is_not(None))
    out = []
    for ip, evs in group_by(failures, lambda e: e.src_ip).items():
        for b in bursts(evs, p["window_seconds"], distinct("user"), p["distinct_users"]):
            users = sorted({e.user for e in b})
            out.append(Match(
                entity=ip, host=top_host(b), events=b,
                summary=f"{ip} tried {len(users)} different usernames: {', '.join(users[:6])}",
                metrics={"distinct_users": len(users), "usernames": users, "attempts": len(b)},
            ))
    return out


# --------------------------------------------------------------------------- NETWORK rules
def r_port_scan(db, p, start, end):
    conns = fetch(db, start, end, Event.source == "network", Event.src_ip.is_not(None))
    out = []
    for ip, evs in group_by(conns, lambda e: e.src_ip).items():
        for b in bursts(evs, p["window_seconds"], distinct("dst_port"), p["distinct_ports"]):
            ports = sorted({e.dst_port for e in b})
            targets = sorted({e.dst_ip for e in b})
            out.append(Match(
                entity=ip, host=top_host(b), events=b,
                summary=f"{ip} probed {len(ports)} ports on {', '.join(targets)} in {duration_s(b)}s",
                metrics={"distinct_ports": len(ports), "targets": targets, "port_range": [ports[0], ports[-1]],
                         "avg_bytes": round(sum(e.bytes_sent or 0 for e in b) / len(b)), "duration_s": duration_s(b)},
            ))
    return out


def r_large_outbound(db, p, start, end):
    conns = [e for e in fetch(db, start, end, Event.source == "network", Event.dst_ip.is_not(None)) if is_external(e.dst_ip)]
    limit = p["megabytes"] * 1024 * 1024
    out = []
    for (host, dst), evs in group_by(conns, lambda e: (e.host, e.dst_ip)).items():
        total = lambda w: sum(e.bytes_sent or 0 for e in w)
        for b in bursts(evs, p["window_seconds"], total, limit):
            mb = total(b) / 1024 / 1024
            out.append(Match(
                entity=dst, host=host, events=b, key=f"{host}->{dst}",
                summary=f"{host} sent {mb:.1f} MB to external host {dst} in {duration_s(b)}s",
                metrics={"megabytes": round(mb, 1), "connections": len(b), "dst_ports": sorted({e.dst_port for e in b}),
                         "duration_s": duration_s(b)},
            ))
    return out


def r_suspicious_port(db, p, start, end):
    ports = set(p["ports"])
    # Outbound only: an attacker's scan TOUCHING port 4444 on our server isn't command-and-control.
    conns = [e for e in fetch(db, start, end, Event.source == "network") if e.dst_port in ports and is_external(e.dst_ip)]
    out = []
    for (host, dst, port), evs in group_by(conns, lambda e: (e.host, e.dst_ip, e.dst_port)).items():
        out.append(Match(
            entity=host, host=host, events=evs, key=f"{host}->{dst}:{port}",
            summary=f"{host} connected out to {dst} on port {port}, a port commonly used by attack tools",
            metrics={"dst_ip": dst, "dst_port": port, "connections": len(evs)},
        ))
    return out


# --------------------------------------------------------------------------- PROCESS rules
def _process_rule(predicate, summary_fn):
    """Builds a single-event process rule: every matching process start is evidence."""
    def rule(db, p, start, end):
        procs = [e for e in fetch(db, start, end, Event.source == "process") if predicate(e, p)]
        out = []
        for (host, path), evs in group_by(procs, lambda e: (e.host, e.process_path or e.process_name)).items():
            e = evs[0]
            out.append(Match(
                entity=host, host=host, events=evs, key=f"{host}:{path}",
                summary=summary_fn(e),
                metrics={"process": e.process_name, "path": e.process_path, "parent": e.parent_process,
                         "pid": e.pid, "cpu_percent": e.cpu_percent, "occurrences": len(evs)},
            ))
        return out
    return rule


def _in_temp(e, p):
    path = e.process_path or ""
    return path.startswith(tuple(p["directories"])) or "/." in path


r_temp_exec = _process_rule(_in_temp, lambda e: f"{e.process_name} ran from {e.process_path} on {e.host}")

r_known_tool = _process_rule(
    lambda e, p: (e.process_name or "").lower() in p["watchlist"],
    lambda e: f"Known malicious tool '{e.process_name}' started on {e.host} ({e.cpu_percent}% CPU)",
)

r_web_shell = _process_rule(
    lambda e, p: (e.parent_process or "") in p["web_servers"] and (e.process_name or "") in p["shells"],
    lambda e: f"Web server '{e.parent_process}' spawned a shell ({e.process_path}) on {e.host}",
)

r_netcat = _process_rule(
    lambda e, p: (e.process_name or "") in p["tools"],
    lambda e: f"'{e.process_name}' started on {e.host} (parent: {e.parent_process}), often used for reverse shells",
)

r_high_cpu = _process_rule(
    lambda e, p: (e.cpu_percent or 0) >= p["cpu_percent"] and (e.process_name or "") not in p["allowlist"],
    lambda e: f"{e.process_name} using {e.cpu_percent}% CPU on {e.host}",
)


# --------------------------------------------------------------------------- the library
RULES: list[RuleDef] = [
    RuleDef(
        id="SOC-001", name="SSH brute force", source="auth", severity="high",
        description="Many failed logins from one source IP in a short time: someone guessing passwords.",
        tactic="Credential Access", technique="T1110", technique_name="Brute Force",
        params={"threshold": 5, "window_seconds": 60},
        logic="count(login_failed) by src_ip >= {threshold} within {window_seconds}s",
        recommended=["Block the source IP at the firewall", "Check whether any login from this IP succeeded",
                     "Enforce account lockout and MFA on targeted accounts"],
        fn=r_brute_force,
        scope="actor",
    ),
    RuleDef(
        id="SOC-002", name="Successful login after brute force", source="auth", severity="critical",
        description="A burst of failed logins followed by a SUCCESS from the same IP. The attacker likely guessed a password.",
        tactic="Initial Access", technique="T1078", technique_name="Valid Accounts",
        params={"threshold": 5, "window_seconds": 60, "success_within_seconds": 300},
        logic="brute-force burst ({threshold}+ failures in {window_seconds}s) then login_success from same src_ip within {success_within_seconds}s",
        recommended=["Disable or reset the compromised account immediately", "Kill active sessions for that user",
                     "Block the source IP", "Review everything the account did after login"],
        fn=r_brute_force_success,
        scope="actor",
    ),
    RuleDef(
        id="SOC-003", name="Multiple usernames from one IP", source="auth", severity="medium",
        description="One IP failing logins across many different usernames: username enumeration or password spraying.",
        tactic="Credential Access", technique="T1110.003", technique_name="Password Spraying",
        params={"distinct_users": 4, "window_seconds": 300},
        logic="count(distinct user) where login_failed by src_ip >= {distinct_users} within {window_seconds}s",
        recommended=["Block the source IP", "Check if the tried usernames exist (enumeration)",
                     "Look for the same IP on other hosts"],
        fn=r_password_spray,
        scope="actor",
    ),
    RuleDef(
        id="SOC-004", name="Port scan", source="network", severity="medium",
        description="One IP connecting to many different ports quickly: mapping which services are open.",
        tactic="Discovery", technique="T1046", technique_name="Network Service Discovery",
        params={"distinct_ports": 20, "window_seconds": 60},
        logic="count(distinct dst_port) by src_ip >= {distinct_ports} within {window_seconds}s",
        recommended=["Block the scanning IP", "Check which scanned ports are actually open",
                     "Watch for follow-up exploitation from the same IP"],
        fn=r_port_scan,
        scope="actor",
    ),
    RuleDef(
        id="SOC-005", name="Execution from temp or hidden directory", source="process", severity="high",
        description="A program started from /tmp, /dev/shm or a hidden folder. Malware hides there because anyone can write to it.",
        tactic="Defense Evasion", technique="T1564.001", technique_name="Hidden Files and Directories",
        params={"directories": ["/tmp/", "/var/tmp/", "/dev/shm/"]},
        logic="process_path starts with {directories} OR contains '/.'",
        recommended=["Isolate the process and capture the binary for analysis", "Find how the file got there (parent process, downloads)",
                     "Check other hosts for the same file"],
        fn=r_temp_exec,
    ),
    RuleDef(
        id="SOC-006", name="Known malicious tool", source="process", severity="critical",
        description="A process whose name matches a known attack tool or crypto-miner.",
        tactic="Impact", technique="T1496", technique_name="Resource Hijacking",
        params={"watchlist": ["xmrig", "minerd", "cpuminer", "mimikatz", "lazagne", "kinsing"]},
        logic="lower(process_name) in {watchlist}",
        recommended=["Kill the process", "Isolate the host from the network", "Look for persistence (cron jobs, services)"],
        fn=r_known_tool,
    ),
    RuleDef(
        id="SOC-007", name="Web server spawned a shell", source="process", severity="critical",
        description="A web server process started a command shell. Classic sign of a web shell or remote code execution.",
        tactic="Persistence", technique="T1505.003", technique_name="Web Shell",
        params={"web_servers": ["nginx", "apache2", "httpd", "php-fpm", "tomcat"], "shells": ["sh", "bash", "dash", "zsh"]},
        logic="parent_process in {web_servers} AND process_name in {shells}",
        recommended=["Isolate the web server", "Search web root for recently modified files",
                     "Review web access logs around this time"],
        fn=r_web_shell,
    ),
    RuleDef(
        id="SOC-008", name="Netcat / socat execution", source="process", severity="high",
        description="Networking tools often used to open reverse shells or move data out.",
        tactic="Execution", technique="T1059.004", technique_name="Unix Shell",
        params={"tools": ["nc", "ncat", "netcat", "socat"]},
        logic="process_name in {tools}",
        recommended=["Check the process's network connections", "Kill the process if unauthorised",
                     "Trace its parent process chain"],
        fn=r_netcat,
    ),
    RuleDef(
        id="SOC-009", name="Unusually high CPU process", source="process", severity="medium",
        description="A non-allowlisted process using very high CPU. Common for crypto-miners.",
        tactic="Impact", technique="T1496", technique_name="Resource Hijacking",
        params={"cpu_percent": 90, "allowlist": ["postgres", "java", "ffmpeg"]},
        logic="cpu_percent >= {cpu_percent} AND process_name not in {allowlist}",
        recommended=["Identify what the process is", "Kill it if unknown", "Check outbound connections to mining pools"],
        fn=r_high_cpu,
    ),
    RuleDef(
        id="SOC-010", name="Large outbound transfer", source="network", severity="high",
        description="A host sending a lot of data to one external address. Possible data theft.",
        tactic="Exfiltration", technique="T1041", technique_name="Exfiltration Over C2 Channel",
        params={"megabytes": 20, "window_seconds": 600},
        logic="sum(bytes_sent) by (host, external dst_ip) >= {megabytes} MB within {window_seconds}s",
        recommended=["Block the destination IP", "Identify what data was sent (DB queries, file access)",
                     "Isolate the source host"],
        fn=r_large_outbound,
    ),
    RuleDef(
        id="SOC-011", name="Connection on attack-tool port", source="network", severity="medium",
        description="Outbound traffic to ports that attack frameworks use by default (Metasploit 4444, IRC botnets 6667...).",
        tactic="Command and Control", technique="T1571", technique_name="Non-Standard Port",
        params={"ports": [4444, 1337, 31337, 6667, 5555, 9001]},
        logic="dst_port in {ports} AND dst_ip is external (outbound)",
        recommended=["Block the destination", "Find the process that opened the connection"],
        fn=r_suspicious_port,
    ),
]



def _ml_detect(db, p, start, end):
    from ..ml.detector import detect      # noqa: PLC0415  (imported lazily: loads scikit-learn)
    return detect(db, p, start, end)


RULES.append(RuleDef(
    id="ML-001", name="Machine learning anomaly", source="ml", severity="medium", detector="ml",
    description="Isolation Forest flags activity unlike normal traffic; Random Forest names the likely attack. "
                "Catches patterns no rule describes, like slow brute force and slow scans.",
    tactic="Anomaly", technique="ML", technique_name="Behavioural anomaly",
    params={"threshold_scale": 1.0, "rf_confidence": 0.9, "min_events": 1},
    logic="per entity per minute: IsolationForest score >= learned threshold x {threshold_scale} "
          "OR RandomForest attack confidence >= {rf_confidence} (windows with >= {min_events} events)",
    recommended=["Read 'Why the model flagged this' to see which behaviours were unusual",
                 "Check the evidence events: is this a known admin task or job?",
                 "If confirmed, contain it like the matching attack type; if harmless, mark False positive"],
    fn=_ml_detect, fixed_lookback=60,
))

RULES_BY_ID = {r.id: r for r in RULES}
