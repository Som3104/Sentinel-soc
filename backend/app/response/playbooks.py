"""Playbooks: automated response policies (SOAR - Security Orchestration, Automation and Response).

Each playbook says WHEN to act (trigger) and WHAT to do (action), plus a mode:
  auto      - act immediately, no human in the loop (fast, for clear-cut cases)
  approval  - propose the action; an analyst approves or rejects it in the Response Center

The design principle: automate the low-risk, high-confidence actions (blocking an
outside attacker's IP is cheap to undo); require a human for high-impact ones
(cutting a server off the network can take a business service down).
"""
from dataclasses import dataclass
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, Incident, Playbook, ResponseAction
from ..utils import is_external, utcnow
from .actions import active_containment, contain, target_for
from .audit import audit

ACTIVE_INCIDENT = ("open", "investigating", "contained")


@dataclass
class Proposal:
    kind: str                 # ip | process | host
    reason: str
    ip: str | None = None
    host: str | None = None
    path: str | None = None

    @property
    def target(self) -> str:
        return target_for(self.kind, self.ip, self.host, self.path)


@dataclass
class PlaybookDef:
    id: str
    name: str
    description: str
    trigger: str              # plain-English trigger, shown in the UI
    action: str               # plain-English action
    mode: str                 # default mode
    params: dict
    fn: Callable[[Incident, list[Alert], dict], list[Proposal]]


# --------------------------------------------------------------------------- triggers
def _actors(inc, alerts, p, min_severity):
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if rank.get(inc.severity, 0) < rank[min_severity]:
        return []
    return [Proposal("ip", ip=ip, reason=f"Attacker in INC-{inc.id} ({inc.severity}, risk {round(inc.score)})")
            for ip in inc.actors or [] if is_external(ip)]


def pb_block_critical(inc, alerts, p):
    return _actors(inc, alerts, p, "critical") if inc.severity == "critical" else []


def pb_block_high(inc, alerts, p):
    return _actors(inc, alerts, p, "high") if inc.severity == "high" else []


def pb_quarantine(inc, alerts, p):
    out, seen = [], set()
    for a in alerts:
        if a.rule_id in p["rules"] and a.status != "false_positive":
            m = (a.details or {}).get("metrics", {})
            host, path = a.host, m.get("path")
            if host and path and (host, path) not in seen:
                seen.add((host, path))
                out.append(Proposal("process", host=host, path=path,
                                    reason=f"{a.title}: {m.get('process') or path} on {host}"))
    return out


def pb_block_exfil(inc, alerts, p):
    out, seen = [], set()
    for a in alerts:
        if a.rule_id not in p["rules"] or a.status == "false_positive":
            continue
        m = (a.details or {}).get("metrics", {})
        dst = m.get("dst_ip") or (a.entity if is_external(a.entity) else None)
        if dst and is_external(dst) and dst not in seen:
            seen.add(dst)
            out.append(Proposal("ip", ip=dst, reason=f"{a.title}: data or C2 traffic to {dst}"))
    return out


def pb_isolate(inc, alerts, p):
    hosts = []
    for a in alerts:
        if a.rule_id in p["rules"] and a.status != "false_positive" and a.host and a.host not in hosts:
            hosts.append(a.host)
    return [Proposal("host", host=h, reason=f"Confirmed attacker access to {h} (INC-{inc.id})") for h in hosts]


PLAYBOOKS: list[PlaybookDef] = [
    PlaybookDef("PB-01", "Block attacker - critical incidents",
                "Critical incidents are near-certain attacks. Blocking an outside IP is cheap to undo, so do it instantly.",
                "Incident severity is critical and has an external attacker IP", "Block the attacker's IP for 24h",
                "auto", {"block_hours": 24}, pb_block_critical),
    PlaybookDef("PB-02", "Block attacker - high incidents",
                "High incidents are probably attacks, but less certain: propose the block, let an analyst decide.",
                "Incident severity is high and has an external attacker IP", "Block the attacker's IP for 24h",
                "approval", {"block_hours": 24}, pb_block_high),
    PlaybookDef("PB-03", "Quarantine malicious binary",
                "A known attack tool or a binary hiding in /tmp should never run. Kill it and stop it running again.",
                "Alert from SOC-005 (temp/hidden dir) or SOC-006 (known malicious tool)",
                "Kill the process and quarantine the file on that host",
                "auto", {"rules": ["SOC-005", "SOC-006"]}, pb_quarantine),
    PlaybookDef("PB-04", "Block exfiltration / C2 destination",
                "Data leaving to an outside server is the most damaging stage. Cut the channel immediately.",
                "Alert from SOC-010 (large outbound transfer) or SOC-011 (attack-tool port)",
                "Block the outside destination IP for 24h",
                "auto", {"rules": ["SOC-010", "SOC-011"], "block_hours": 24}, pb_block_exfil),
    PlaybookDef("PB-05", "Isolate compromised host",
                "Isolation stops an attacker moving further, but also stops the machine doing its job. A human decides.",
                "Confirmed access: SOC-002 (login after brute force) or SOC-007 (web shell)",
                "Cut the host off the network",
                "approval", {"rules": ["SOC-002", "SOC-007"]}, pb_isolate),
]
PLAYBOOKS_BY_ID = {p.id: p for p in PLAYBOOKS}


def seed_playbooks(db: Session) -> None:
    existing = {p.id for p in db.scalars(select(Playbook)).all()}
    for pd in PLAYBOOKS:
        if pd.id not in existing:
            db.add(Playbook(id=pd.id, name=pd.name, enabled=True, mode=pd.mode, params={}))
    db.commit()


# --------------------------------------------------------------------------- engine
def _already_handled(db: Session, pb_id: str, target: str, incident_id: int) -> bool:
    return db.scalar(select(ResponseAction.id).where(
        ResponseAction.playbook_id == pb_id, ResponseAction.target == target[:200],
        ResponseAction.incident_id == incident_id).limit(1)) is not None


def run_playbooks(db: Session) -> dict:
    """Evaluate every enabled playbook against every active incident.

    Auto playbooks run first, so an IP that gets blocked automatically isn't ALSO
    queued for approval by a slower playbook.
    """
    settings = {p.id: p for p in db.scalars(select(Playbook)).all()}
    order = sorted(PLAYBOOKS, key=lambda pd: (getattr(settings.get(pd.id), "mode", pd.mode) != "auto", pd.id))
    incidents = db.scalars(select(Incident).where(Incident.status.in_(ACTIVE_INCIDENT))).all()
    executed = pending = 0
    for inc in incidents:
        alerts = db.scalars(select(Alert).where(Alert.incident_id == inc.id)).all()
        for pd in order:
            pb = settings.get(pd.id)
            if pb is None or not pb.enabled:
                continue
            params = {**pd.params, **(pb.params or {})}
            for prop in pd.fn(inc, alerts, params):
                if active_containment(db, prop.kind, prop.target) or _already_handled(db, pd.id, prop.target, inc.id):
                    continue
                if pb.mode == "auto":
                    status, _, _ = contain(db, prop.kind, ip=prop.ip, host=prop.host, path=prop.path,
                                           reason=f"{pd.id}: {prop.reason}", actor="auto", incident_id=inc.id,
                                           playbook_id=pd.id, hours=params.get("block_hours") if prop.kind == "ip" else None)
                    executed += status == "success"
                else:
                    audit(db, category="response",
                          action={"ip": "block_ip", "process": "quarantine_process", "host": "isolate_host"}[prop.kind],
                          target=prop.target, actor="auto", status="pending_approval", incident_id=inc.id,
                          playbook_id=pd.id, result=f"Waiting for analyst approval ({pd.name})",
                          details={"reason": prop.reason, "kind": prop.kind, "ip": prop.ip, "host": prop.host,
                                   "path": prop.path, "hours": params.get("block_hours") if prop.kind == "ip" else None})
                    pending += 1
                db.flush()
    db.commit()
    return {"responses_executed": executed, "responses_pending": pending}


def decide(db: Session, row: ResponseAction, approve: bool) -> ResponseAction:
    """Analyst approves or rejects a pending playbook action."""
    d = row.details or {}
    if approve:
        contain(db, d["kind"], ip=d.get("ip"), host=d.get("host"), path=d.get("path"),
                reason=f"{row.playbook_id}: {d.get('reason', '')} (approved)", actor="analyst",
                incident_id=row.incident_id, playbook_id=row.playbook_id, hours=d.get("hours"), audit_row=row)
    else:
        row.status, row.result, row.decided_at, row.triggered_by = "rejected", "Rejected by analyst", utcnow(), "analyst"
    db.commit()
    return row
