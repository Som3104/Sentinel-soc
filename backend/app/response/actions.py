"""Containment actions + the guardrails that keep automation from hurting us.

Everything here is SIMULATED: "blocking an IP" adds a row to the containments
table, and the ingest endpoint then drops matching log events, the way a real
firewall would drop the packets. Nothing touches your real network or PC.

Guardrails (checked for every action, automatic or manual):
  1. Never block an internal IP: we'd cut off our own machine.
  2. Never block allowlisted IPs (DNS, cloud providers we depend on).
  3. Automation can't isolate a CRITICAL asset (db-01): that needs a human.
  4. At most MAX_AUTO_BLOCKS_PER_HOUR automatic blocks: a runaway rule
     shouldn't be able to block half the internet.
"""
import ipaddress
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..assets import asset
from ..models import Containment, Incident, ResponseAction
from ..utils import aware, is_external, utcnow
from .audit import audit

ALLOWLIST = {
    "8.8.8.8": "Google DNS",
    "142.250.183.14": "Google services",
    "151.101.1.69": "Fastly CDN (our website assets)",
    "13.107.42.14": "Microsoft 365",
}
MAX_AUTO_BLOCKS_PER_HOUR = 20
DEFAULT_BLOCK_HOURS = 24

ACTION_KIND = {"block_ip": "ip", "quarantine_process": "process", "isolate_host": "host"}
RELEASE_ACTION = {"ip": "unblock_ip", "process": "release_process", "host": "release_host"}
LABEL = {"ip": "Blocked IP", "process": "Quarantined process", "host": "Isolated host"}


class GuardrailError(Exception):
    """Raised when an action is refused by a guardrail. The message explains why."""


def target_for(kind: str, ip: str | None = None, host: str | None = None, path: str | None = None) -> str:
    return {"ip": ip, "host": host, "process": f"{host}:{path}"}[kind]


def active_containment(db: Session, kind: str, target: str) -> Containment | None:
    return db.scalars(select(Containment).where(
        Containment.kind == kind, Containment.target == target, Containment.active.is_(True))).first()


def check_guardrails(db: Session, kind: str, *, ip=None, host=None, path=None, actor="analyst"):
    if kind == "ip":
        try:
            ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            raise GuardrailError(f"'{ip}' is not a valid IP address")
        if not is_external(ip):
            raise GuardrailError(f"{ip} is an internal address: blocking it would cut off one of our own machines")
        if ip in ALLOWLIST:
            raise GuardrailError(f"{ip} is allowlisted ({ALLOWLIST[ip]}): blocking it would break a service we rely on")
        if actor == "auto":
            hour_ago = utcnow() - timedelta(hours=1)
            recent = db.scalar(select(func.count()).select_from(Containment).where(
                Containment.kind == "ip", Containment.created_by == "auto", Containment.created_at >= hour_ago))
            if recent >= MAX_AUTO_BLOCKS_PER_HOUR:
                raise GuardrailError(f"automatic block limit reached ({MAX_AUTO_BLOCKS_PER_HOUR}/hour): needs an analyst")
    elif kind == "host":
        if not host:
            raise GuardrailError("no host given")
        if actor == "auto" and asset(host)["criticality"] == "critical":
            raise GuardrailError(f"{host} is a critical asset ({asset(host)['role']}): isolation must be approved by an analyst")
    elif kind == "process":
        if not host or not path:
            raise GuardrailError("host and process path are both required")


def contain(db: Session, kind: str, *, ip=None, host=None, path=None, reason: str, actor: str = "analyst",
            incident_id=None, playbook_id=None, hours: float | None = None, audit_row: ResponseAction | None = None):
    """Apply a containment. Returns (status, message, containment|None) and always writes the audit log.

    audit_row: when approving a pending action, update that row instead of adding a new one.
    """
    action = {"ip": "block_ip", "process": "quarantine_process", "host": "isolate_host"}[kind]
    target = target_for(kind, ip, host, path)

    def record(status, message):
        if audit_row is not None:
            audit_row.status, audit_row.result, audit_row.decided_at = status, message, utcnow()
            audit_row.triggered_by = actor
        else:
            audit(db, category="response", action=action, target=target, actor=actor, result=message, status=status,
                  incident_id=incident_id, playbook_id=playbook_id, details={"reason": reason})

    try:
        check_guardrails(db, kind, ip=ip, host=host, path=path, actor=actor)
    except GuardrailError as e:
        record("blocked_by_guardrail", f"Refused: {e}")
        return "blocked_by_guardrail", str(e), None

    if active_containment(db, kind, target):
        record("skipped", f"{target} is already contained")
        return "skipped", f"{target} is already contained", None

    hours = hours if hours is not None else (DEFAULT_BLOCK_HOURS if actor == "auto" and kind == "ip" else None)
    c = Containment(
        kind=kind, target=target, host=host, process_path=path, reason=reason, incident_id=incident_id,
        playbook_id=playbook_id, created_by=actor, created_at=utcnow(), active=True, dropped_count=0,
        expires_at=utcnow() + timedelta(hours=hours) if hours else None,
    )
    db.add(c)
    message = {
        "ip": f"Firewall now drops all traffic to and from {ip}",
        "process": f"EDR killed and quarantined {path} on {host}; it can't run there again",
        "host": f"EDR cut {host} off the network (its traffic is dropped)",
    }[kind] + (f" for {hours:g}h" if hours else "")
    record("success", message)
    # Any OTHER approval request for the same action is now moot (e.g. PB-02 asked to block an IP
    # while the incident was "high"; it turned critical and PB-01 blocked it automatically).
    stale = db.scalars(select(ResponseAction).where(
        ResponseAction.status == "pending_approval", ResponseAction.action == action,
        ResponseAction.target == target[:200])).all()
    for row in stale:
        if row is not audit_row:
            row.status, row.result, row.decided_at = "skipped", f"No longer needed: {target} already contained", utcnow()
    _mark_incident_contained(db, incident_id, f"{LABEL[kind]}: {target} ({'automatic' if actor == 'auto' else 'analyst'})")
    db.flush()
    return "success", message, c


def release(db: Session, c: Containment, actor: str = "analyst", reason: str = "released by analyst") -> None:
    c.active, c.released_at, c.released_by = False, utcnow(), actor
    audit(db, category="response" if actor != "system" else "system", action=RELEASE_ACTION[c.kind],
          target=c.target, actor=actor, result=f"{LABEL[c.kind]} released: {reason}",
          incident_id=c.incident_id, details={"containment_id": c.id, "dropped_while_active": c.dropped_count})


def expire_old(db: Session) -> int:
    """Auto-blocks are temporary: attacker IPs get reassigned, and permanent lists rot."""
    now = utcnow()
    expired = [c for c in db.scalars(select(Containment).where(Containment.active.is_(True), Containment.expires_at.is_not(None))).all()
               if aware(c.expires_at) <= now]
    for c in expired:
        release(db, c, actor="system", reason="block expired")
    return len(expired)


def _mark_incident_contained(db: Session, incident_id, why: str) -> None:
    if not incident_id:
        return
    inc = db.get(Incident, incident_id)
    if inc is not None and inc.status in ("open", "investigating"):
        from ..detection.correlation import set_incident_status   # noqa: PLC0415
        set_incident_status(db, inc, "contained", author="system")
        notes = list(inc.notes or [])
        notes.append({"at": utcnow().isoformat(), "author": "system", "system": True, "text": f"Containment applied - {why}"})
        inc.notes = notes


# --------------------------------------------------------------------------- the simulated firewall / EDR
def apply_containments(db: Session, events: list) -> tuple[list, int]:
    """Called by /api/ingest. Drops events that our active containments would have stopped.
    Returns (events to keep, number dropped)."""
    expire_old(db)
    active = db.scalars(select(Containment).where(Containment.active.is_(True))).all()
    if not active:
        return events, 0
    ips = {c.target: c for c in active if c.kind == "ip"}
    procs = {(c.host, c.process_path): c for c in active if c.kind == "process"}
    hosts = {c.target: c for c in active if c.kind == "host"}

    kept, dropped, now = [], 0, utcnow()
    for e in events:
        hit = (ips.get(e.src_ip) or ips.get(e.dst_ip)
               or (procs.get((e.host, e.process_path)) if e.source == "process" else None)
               or (hosts.get(e.host) if e.source in ("network", "auth") else None))
        if hit is None:
            kept.append(e)
            continue
        dropped += 1
        hit.dropped_count = (hit.dropped_count or 0) + 1
        hit.last_dropped_at = now
    return kept, dropped


