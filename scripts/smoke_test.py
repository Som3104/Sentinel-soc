r"""End-to-end smoke test: is the running SOC actually detecting and responding?

Run it against a live backend after sending traffic with the simulator:

    python simulator\simulator.py --seed 21
    python scripts\smoke_test.py

CI (.github/workflows/ci.yml) does exactly this against a real PostgreSQL on every push.
Standard library only.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request


def call(base, path, token=None, body=None):
    req = urllib.request.Request(
        base + path, method="POST" if body is not None else "GET",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8000")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="Admin@123")
    a = p.parse_args()

    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}{f' ({detail})' if detail else ''}")

    print(f"Smoke test against {a.url}")
    status, _ = call(a.url, "/health")
    check("backend is up", status == 200, f"HTTP {status}")
    status, _ = call(a.url, "/api/incidents")
    check("API refuses requests without a login", status == 401, f"HTTP {status}")
    status, body = call(a.url, "/api/auth/login", body={"username": a.user, "password": a.password})
    check("demo admin can sign in", status == 200, f"HTTP {status}")
    if status != 200:
        return 1
    token = body["access_token"]

    _, alerts = call(a.url, "/api/alerts/summary", token)
    _, incidents = call(a.url, "/api/incidents", token)
    _, response = call(a.url, "/api/response/summary", token)
    _, audit = call(a.url, "/api/audit?category=access", token)

    check("alerts were raised", (alerts or {}).get("total", 0) > 0, f"{(alerts or {}).get('total')} alerts")
    crit = [i for i in incidents or [] if i["severity"] == "critical"]
    check("attacks grouped into incidents, at least one critical", len(incidents or []) > 0 and len(crit) > 0,
          f"{len(incidents or [])} incidents, {len(crit)} critical")
    check("brute-force attacker 203.0.113.45 is in an incident",
          any("203.0.113.45" in json.dumps(i) for i in incidents or []))
    contained = (response or {}).get("active", {})
    check("automated response contained something", sum(contained.values()) > 0 if isinstance(contained, dict) else bool(contained),
          json.dumps(contained))
    check("sign-ins are audited", any(r["action"] == "login" for r in audit or []))

    print(f"{sum(checks)}/{len(checks)} checks passed")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
