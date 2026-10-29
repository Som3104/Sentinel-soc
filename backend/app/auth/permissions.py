"""Who may do what: the whole access policy in one table.

Three roles, each including everything below it:
    viewer   read-only: dashboards, alerts, incidents, audit log (e.g. a manager, an auditor)
    analyst  + triage alerts and incidents, contain threats, approve playbook actions, run the lab
    admin    + change detection rules and playbooks, retrain ML, wipe the lab, manage users

Every API route is checked against this table by `authorize` (auth/deps.py).
Secure by default: a route that isn't listed needs viewer for reads and ADMIN for changes,
so a new endpoint someone forgets to add here is locked down, not wide open.
"""
ROLES = ["viewer", "analyst", "admin"]
RANK = {r: i for i, r in enumerate(ROLES)}

# (method, route path as declared in FastAPI) -> (minimum role, what it does)
POLICY: dict[tuple[str, str], tuple[str, str]] = {
    ("PATCH", "/api/alerts/{alert_id}"): ("analyst", "Triage alerts (status, notes)"),
    ("PATCH", "/api/incidents/{incident_id}"): ("analyst", "Triage incidents (status, notes)"),
    ("POST", "/api/incidents/correlate"): ("analyst", "Re-run incident correlation"),
    ("POST", "/api/detection/run"): ("analyst", "Re-run detection over recent logs"),
    ("POST", "/api/response/actions"): ("analyst", "Block IPs, quarantine processes, isolate hosts"),
    ("POST", "/api/response/containments/{cid}/release"): ("analyst", "Release a containment"),
    ("POST", "/api/response/release-all"): ("analyst", "Release all containments (lab reset)"),
    ("POST", "/api/response/pending/{action_id}/{decision}"): ("analyst", "Approve or reject playbook actions"),
    ("POST", "/api/lab/run"): ("analyst", "Launch attack scenarios"),
    ("POST", "/api/lab/demo"): ("analyst", "Run the full demo"),
    ("POST", "/api/lab/live"): ("analyst", "Start/stop live traffic"),
    ("POST", "/api/lab/reset"): ("analyst", "Reset the lab (wiping all data needs admin)"),
    ("PATCH", "/api/rules/{rule_id}"): ("admin", "Enable, disable and tune detection rules"),
    ("PATCH", "/api/response/playbooks/{pb_id}"): ("admin", "Switch playbooks between auto and approval"),
    ("POST", "/api/response/run-playbooks"): ("admin", "Run playbooks over open incidents"),
    ("POST", "/api/ml/train"): ("admin", "Retrain the ML models"),
    ("GET", "/api/users"): ("admin", "List users"),
    ("POST", "/api/users"): ("admin", "Create users"),
    ("PATCH", "/api/users/{user_id}"): ("admin", "Change role, disable, reset password"),
}


def required_role(method: str, path: str) -> str:
    if (method, path) in POLICY:
        return POLICY[(method, path)][0]
    return "viewer" if method in ("GET", "HEAD") else "admin"


def allows(role: str, needed: str) -> bool:
    return RANK.get(role, -1) >= RANK[needed]


def policy_table() -> list[dict]:
    """For the Users page: what each role can do."""
    rows = [{"method": "GET", "path": "/api/*", "role": "viewer", "what": "Read every dashboard, alert, incident and audit entry"}]
    rows += [{"method": m, "path": p, "role": r, "what": w} for (m, p), (r, w) in POLICY.items()]
    return rows
