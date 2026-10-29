"""Attack + normal-traffic simulator for the Mini SOC lab.

Nothing here attacks anything real. It only GENERATES fake log events that
look like what a real host would produce, and sends them to the SOC API.
Every event carries a `label` (normal / brute_force / ...) so we know the
ground truth - that's what lets us measure detection accuracy later.

Usage:
    python simulator.py                         # 30 min of history, all attacks
    python simulator.py --attacks brute_force   # only one attack type
    python simulator.py --attacks slow_brute_force,slow_scan   # stealthy attacks rules can't see
    python simulator.py --attacks intrusion     # one attacker, full kill chain (scan -> login -> malware -> exfil)
    python simulator.py --attacks none          # normal traffic only (ML baseline)
    python simulator.py --live                  # stream events continuously (Ctrl+C to stop)

Only uses the Python standard library - no pip install needed.
"""
import argparse
import json
import os
import random
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# Log shippers authenticate with an API key (Phase 8). Must match INGEST_API_KEY on the backend.
API_KEY = os.getenv("SOC_INGEST_KEY", "lab-ingest-key")

HOSTS = ["web-01", "web-02", "db-01", "dev-laptop-07"]
USERS = ["alice", "bob", "carol", "dave", "erin", "svc_backup"]
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(10, 40)]
NORMAL_PROCS = [
    ("nginx", "/usr/sbin/nginx", "systemd"),
    ("python3", "/usr/bin/python3", "bash"),
    ("postgres", "/usr/lib/postgresql/16/bin/postgres", "systemd"),
    ("sshd", "/usr/sbin/sshd", "systemd"),
    ("cron", "/usr/sbin/cron", "systemd"),
    ("node", "/usr/bin/node", "bash"),
]
NORMAL_DST = [("142.250.183.14", 443), ("151.101.1.69", 443), ("8.8.8.8", 53), ("10.0.0.5", 5432), ("13.107.42.14", 443)]
# Public visitors browsing our websites. Real servers see lots of outside traffic, so
# "external IP" alone must not mean "attacker" - the ML model has to learn that.
WEB_VISITORS = [f"{a}.{b}.{c}.{d}" for a, b, c, d in
                [(49, 36, 112, 9), (103, 21, 244, 7), (106, 51, 8, 140), (117, 99, 3, 61), (122, 160, 75, 18),
                 (157, 32, 190, 4), (182, 64, 210, 33), (34, 120, 55, 201), (52, 95, 7, 88), (81, 2, 69, 142)]]
BACKUP_SERVER = "10.0.0.50"
# Employees working from home log in from outside the network (and mistype passwords too).
REMOTE_WORKERS = ["49.207.53.18", "106.215.90.44", "117.250.3.121", "152.58.30.7", "223.187.12.96"]
# Each machine belongs to one person: one IP = (almost always) one username. That's what
# makes "several usernames from one IP" a meaningful attack signal.
OWNER = {ip: USERS[i % len(USERS)] for i, ip in enumerate(INTERNAL_IPS + REMOTE_WORKERS)}

# Attacker IPs come from documentation/reserved ranges (RFC 5737), so they can never be real hosts.
ATTACKERS = {
    "brute_force": "203.0.113.45",
    "port_scan": "198.51.100.23",
    "exfiltration": "192.0.2.77",
    "slow_brute_force": "203.0.113.99",
    "slow_scan": "198.51.100.77",
    "intrusion": "203.0.113.66",
}
DEV_LAPTOP_IP = "10.0.0.77"

ALL_ATTACKS = ["brute_force", "port_scan", "suspicious_process", "exfiltration", "slow_brute_force", "slow_scan", "intrusion"]


def iso(ts: datetime) -> str:
    return ts.isoformat()


# ---------------------------------------------------------------- normal traffic
def normal_events(start: datetime, minutes: int, rate_per_min: int = 20) -> list[dict]:
    events = []
    total = minutes * rate_per_min
    for _ in range(total):
        ts = start + timedelta(seconds=random.uniform(0, minutes * 60))
        host = random.choice(HOSTS)
        kind = random.choices(["auth", "remote", "process", "network", "web", "backup"], weights=[2, 0.6, 3, 4, 1.2, 0.03])[0]

        if kind in ("auth", "remote"):
            src = random.choice(REMOTE_WORKERS if kind == "remote" else INTERNAL_IPS)
            # Mostly the machine's owner; now and then a shared machine (internal only).
            user = OWNER[src] if kind == "remote" or random.random() < 0.95 else random.choice(USERS)
            # Real users mistype passwords occasionally - a good detector must NOT alert on this.
            failed = random.random() < 0.08
            events.append({
                "timestamp": iso(ts), "host": "web-01" if kind == "remote" else host, "source": "auth",
                "event_type": "login_failed" if failed else "login_success",
                "user": user, "src_ip": src, "label": "normal",
            })
            if failed and random.random() < 0.5:
                # ...and usually retry a few seconds later, often successfully.
                events.append({
                    "timestamp": iso(ts + timedelta(seconds=random.uniform(3, 15))), "host": events[-1]["host"],
                    "source": "auth", "event_type": "login_success" if random.random() < 0.8 else "login_failed",
                    "user": user, "src_ip": src, "label": "normal",
                })
        elif kind == "process":
            name, path, parent = random.choice(NORMAL_PROCS)
            events.append({
                "timestamp": iso(ts), "host": host, "source": "process", "event_type": "process_start",
                "process_name": name, "process_path": path, "parent_process": parent,
                # Occasionally a legit job (report build, data import) works hard.
                "pid": random.randint(1000, 60000),
                "cpu_percent": round(random.uniform(40, 85) if random.random() < 0.03 else random.uniform(0.1, 25), 1),
                "label": "normal",
            })
        elif kind == "web":
            # Inbound HTTPS from the internet to a web server.
            events.append({
                "timestamp": iso(ts), "host": random.choice(["web-01", "web-02"]), "source": "network",
                "event_type": "net_conn", "src_ip": random.choice(WEB_VISITORS), "dst_ip": "10.0.0.12",
                "dst_port": 443, "bytes_sent": int(random.lognormvariate(7, 1)), "label": "normal",
            })
        elif kind == "backup":
            # Nightly backup: db-01 pushes a LOT of data, but to an INTERNAL server.
            # Looks like exfiltration by volume alone - a good detector must tell them apart.
            events.append({
                "timestamp": iso(ts), "host": "db-01", "source": "network", "event_type": "net_conn",
                "src_ip": "10.0.0.5", "dst_ip": BACKUP_SERVER, "dst_port": 873,
                "bytes_sent": random.randint(20_000_000, 80_000_000), "label": "normal",
            })
        else:
            dst_ip, port = random.choice(NORMAL_DST)
            events.append({
                "timestamp": iso(ts), "host": host, "source": "network", "event_type": "net_conn",
                "src_ip": random.choice(INTERNAL_IPS), "dst_ip": dst_ip, "dst_port": port,
                "bytes_sent": int(random.lognormvariate(8, 1.2)),  # mostly 1-20 KB, long tail
                "label": "normal",
            })
    return events


# ---------------------------------------------------------------- attacks
def brute_force(at: datetime) -> list[dict]:
    """MITRE T1110: many failed logins from one IP in a short window, then a success (compromise)."""
    ip, host = ATTACKERS["brute_force"], "web-01"
    targets = ["root", "admin", "ubuntu", "test", "oracle", "alice"]
    events = []
    t = at
    for _ in range(random.randint(25, 40)):
        t += timedelta(seconds=random.uniform(0.5, 2.5))
        events.append({
            "timestamp": iso(t), "host": host, "source": "auth", "event_type": "login_failed",
            "user": random.choice(targets), "src_ip": ip, "label": "brute_force",
        })
    t += timedelta(seconds=2)
    events.append({
        "timestamp": iso(t), "host": host, "source": "auth", "event_type": "login_success",
        "user": "alice", "src_ip": ip, "label": "brute_force",
    })
    return events


def port_scan(at: datetime) -> list[dict]:
    """MITRE T1046: one IP touching many ports in seconds, sending almost no data."""
    ip = ATTACKERS["port_scan"]
    ports = random.sample(range(1, 10000), 120)
    events = []
    t = at
    for p in ports:
        t += timedelta(milliseconds=random.randint(20, 150))
        events.append({
            "timestamp": iso(t), "host": "web-02", "source": "network", "event_type": "net_conn",
            "src_ip": ip, "dst_ip": "10.0.0.12", "dst_port": p, "bytes_sent": random.randint(40, 80),
            "label": "port_scan",
        })
    return events


def suspicious_process(at: datetime) -> list[dict]:
    """MITRE T1496 (crypto-miner from /tmp) and T1059 (shell spawned by a web server)."""
    return [
        {
            "timestamp": iso(at), "host": "web-01", "source": "process", "event_type": "process_start",
            "process_name": "xmrig", "process_path": "/tmp/.x/xmrig", "parent_process": "bash",
            "pid": 31337, "cpu_percent": 97.5, "label": "suspicious_process",
        },
        {
            "timestamp": iso(at + timedelta(seconds=40)), "host": "web-02", "source": "process",
            "event_type": "process_start", "process_name": "sh", "process_path": "/bin/sh",
            "parent_process": "nginx", "pid": 31338, "cpu_percent": 1.2, "label": "suspicious_process",
        },
        {
            "timestamp": iso(at + timedelta(seconds=45)), "host": "web-02", "source": "process",
            "event_type": "process_start", "process_name": "nc", "process_path": "/usr/bin/nc",
            "parent_process": "sh", "pid": 31339, "cpu_percent": 0.5, "label": "suspicious_process",
        },
    ]


def exfiltration(at: datetime) -> list[dict]:
    """MITRE T1041: large outbound transfers to an unknown external host on an odd port."""
    events = []
    t = at
    for _ in range(8):
        t += timedelta(seconds=random.uniform(5, 15))
        events.append({
            "timestamp": iso(t), "host": "db-01", "source": "network", "event_type": "net_conn",
            "src_ip": "10.0.0.5", "dst_ip": ATTACKERS["exfiltration"], "dst_port": 4444,
            "bytes_sent": random.randint(5_000_000, 50_000_000), "label": "exfiltration",
        })
    return events


def slow_brute_force(at: datetime) -> list[dict]:
    """STEALTHY T1110: one password guess every ~20s against a single account.

    Never more than 4 failures in any 60s window, and only one username, so it
    slips under SOC-001 (5 in 60s) and SOC-003 (4+ usernames). Rules miss it;
    the ML model should still find it unusual.
    """
    ip, host = ATTACKERS["slow_brute_force"], "web-02"
    events = []
    t = at
    for _ in range(random.randint(14, 20)):
        t += timedelta(seconds=random.uniform(17, 24))
        events.append({
            "timestamp": iso(t), "host": host, "source": "auth", "event_type": "login_failed",
            "user": "admin", "src_ip": ip, "label": "brute_force",
        })
    t += timedelta(seconds=random.uniform(17, 24))
    events.append({
        "timestamp": iso(t), "host": host, "source": "auth", "event_type": "login_success",
        "user": "admin", "src_ip": ip, "label": "brute_force",
    })
    return events


def slow_scan(at: datetime) -> list[dict]:
    """STEALTHY T1046: one port every ~5s. About 12 ports per minute stays under
    SOC-004's 20-ports-per-minute threshold, but over 6 minutes it maps ~70 ports."""
    ip = ATTACKERS["slow_scan"]
    events = []
    t = at
    for p in random.sample(range(1, 10000), random.randint(60, 80)):
        t += timedelta(seconds=random.uniform(4.2, 6))
        events.append({
            "timestamp": iso(t), "host": "web-01", "source": "network", "event_type": "net_conn",
            "src_ip": ip, "dst_ip": "10.0.0.11", "dst_port": p, "bytes_sent": random.randint(40, 80),
            "label": "port_scan",
        })
    return events


def intrusion(at: datetime) -> list[dict]:
    """A FULL attack chain by one attacker against one machine (dev-laptop-07), ~8 minutes:

      1. Discovery           scan the laptop's ports                       (T1046)
      2. Credential Access   brute-force its SSH                           (T1110)
      3. Initial Access      log in as bob                                 (T1078)
      4. Execution           curl downloads a binary, bash runs it         (T1059)
      5. Defense Evasion     binary hides in /tmp/.cache, named like a kernel thread (T1564)
      6. Command & Control   laptop calls back to the attacker on port 4444 (T1571)
      7. Exfiltration        laptop uploads ~150 MB to the attacker        (T1041)

    Each step alone is one alert. Correlation should stitch them into ONE incident.
    """
    ip, host = ATTACKERS["intrusion"], "dev-laptop-07"
    events, t = [], at
    for p in random.sample(range(1, 10000), 40):                          # 1. scan
        t += timedelta(milliseconds=random.randint(50, 200))
        events.append({"timestamp": iso(t), "host": host, "source": "network", "event_type": "net_conn",
                       "src_ip": ip, "dst_ip": DEV_LAPTOP_IP, "dst_port": p, "bytes_sent": random.randint(40, 80),
                       "label": "port_scan"})
    t += timedelta(seconds=random.uniform(40, 90))
    for _ in range(random.randint(12, 18)):                               # 2. brute force
        t += timedelta(seconds=random.uniform(1, 3))
        events.append({"timestamp": iso(t), "host": host, "source": "auth", "event_type": "login_failed",
                       "user": random.choice(["root", "admin", "bob", "dev"]), "src_ip": ip, "label": "brute_force"})
    t += timedelta(seconds=3)
    events.append({"timestamp": iso(t), "host": host, "source": "auth", "event_type": "login_success",  # 3. in
                   "user": "bob", "src_ip": ip, "label": "brute_force"})
    t += timedelta(seconds=random.uniform(30, 60))
    for name, path, parent, cpu in [("curl", "/usr/bin/curl", "bash", 2.0),                     # 4. download
                                    ("kworkerd", "/tmp/.cache/kworkerd", "bash", 93.5)]:         # 5. run hidden
        t += timedelta(seconds=random.uniform(5, 15))
        events.append({"timestamp": iso(t), "host": host, "source": "process", "event_type": "process_start",
                       "process_name": name, "process_path": path, "parent_process": parent,
                       "pid": random.randint(40000, 60000), "cpu_percent": cpu, "label": "suspicious_process"})
    for _ in range(4):                                                     # 6. C2 callbacks
        t += timedelta(seconds=random.uniform(20, 40))
        events.append({"timestamp": iso(t), "host": host, "source": "network", "event_type": "net_conn",
                       "src_ip": DEV_LAPTOP_IP, "dst_ip": ip, "dst_port": 4444,
                       "bytes_sent": random.randint(300, 2000), "label": "exfiltration"})
    for _ in range(5):                                                     # 7. exfiltration
        t += timedelta(seconds=random.uniform(10, 25))
        events.append({"timestamp": iso(t), "host": host, "source": "network", "event_type": "net_conn",
                       "src_ip": DEV_LAPTOP_IP, "dst_ip": ip, "dst_port": 443,
                       "bytes_sent": random.randint(20_000_000, 40_000_000), "label": "exfiltration"})
    return events


ATTACK_FUNCS = {
    "brute_force": brute_force,
    "port_scan": port_scan,
    "suspicious_process": suspicious_process,
    "exfiltration": exfiltration,
    "slow_brute_force": slow_brute_force,
    "slow_scan": slow_scan,
    "intrusion": intrusion,
}


# ---------------------------------------------------------------- sending
def send(url: str, events: list[dict], batch_size: int = 500) -> None:
    stored = dropped = created = updated = inc_new = inc_upd = resp_auto = resp_pending = 0
    for i in range(0, len(events), batch_size):
        chunk = events[i:i + batch_size]
        req = urllib.request.Request(
            url, data=json.dumps(chunk).encode(), headers={"Content-Type": "application/json", "X-API-Key": API_KEY}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                stored += result["stored"]
                dropped += result["dropped_blocked"]
                created += result.get("alerts_created", 0)
                updated += result.get("alerts_updated", 0)
                inc_new += result.get("incidents_created", 0)
                inc_upd += result.get("incidents_updated", 0)
                resp_auto += result.get("responses_executed", 0)
                resp_pending += result.get("responses_pending", 0)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise SystemExit("API rejected the API key. Set SOC_INGEST_KEY to the backend's INGEST_API_KEY.")
            raise SystemExit(f"API rejected batch: {e.code} {e.read().decode()[:500]}")
        except urllib.error.URLError as e:
            raise SystemExit(f"Can't reach {url} - is the backend running? ({e.reason})")
    msg = f"  sent {len(events)} events -> stored {stored}, dropped by firewall {dropped}"
    if created or updated:
        msg += f" | ALERTS: {created} new, {updated} updated"
    if inc_new or inc_upd:
        msg += f" | INCIDENTS: {inc_new} new, {inc_upd} updated"
    if resp_auto or resp_pending:
        msg += f" | RESPONSE: {resp_auto} automatic, {resp_pending} awaiting approval"
    print(msg)


def parse_attacks(value: str) -> list[str]:
    if value == "all":
        return ALL_ATTACKS
    if value == "none":
        return []
    chosen = [a.strip() for a in value.split(",")]
    bad = [a for a in chosen if a not in ATTACK_FUNCS]
    if bad:
        raise SystemExit(f"Unknown attack(s): {bad}. Choose from {ALL_ATTACKS}, 'all' or 'none'.")
    return chosen


def run_history(args, attacks):
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=args.minutes)
    events = normal_events(start, args.minutes)
    for name in attacks:
        # Each attack starts at a random point in the window (leaving room for it to finish).
        at = start + timedelta(seconds=random.uniform(0, max(60, args.minutes * 60 - 600)))
        attack_events = ATTACK_FUNCS[name](at)
        print(f"  injecting {name}: {len(attack_events)} events at {at:%H:%M:%S} UTC")
        events += attack_events
    events.sort(key=lambda e: e["timestamp"])
    send(args.url, events)


def run_live(args, attacks):
    print("Streaming live traffic every 5s. Ctrl+C to stop.")
    tick = 0
    try:
        while True:
            now = datetime.now(timezone.utc)
            events = normal_events(now - timedelta(seconds=5), minutes=1, rate_per_min=8)
            # Fire a random attack roughly every 6th tick (~30s).
            if attacks and tick % 6 == 5:
                name = random.choice(attacks)
                print(f"  [attack] {name}")
                events += ATTACK_FUNCS[name](now)
            send(args.url, events)
            tick += 1
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopped.")


def main():
    p = argparse.ArgumentParser(description="Mini SOC log simulator")
    p.add_argument("--url", default="http://localhost:8000/api/ingest")
    p.add_argument("--minutes", type=int, default=30, help="minutes of history to generate")
    p.add_argument("--attacks", default="all", help="all | none | comma list, e.g. brute_force,port_scan")
    p.add_argument("--seed", type=int, default=None, help="set for repeatable runs")
    p.add_argument("--live", action="store_true", help="stream continuously instead of one batch")
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    attacks = parse_attacks(args.attacks)

    print(f"Simulator -> {args.url}  attacks={attacks or 'none'}")
    if args.live:
        run_live(args, attacks)
    else:
        run_history(args, attacks)


if __name__ == "__main__":
    main()
