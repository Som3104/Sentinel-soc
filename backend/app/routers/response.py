"""Response Center API: containments, manual actions, approvals, playbooks."""
from datetime import timedelta
from statistics import median
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Containment, Incident, Playbook, ResponseAction
from ..response.actions import (ALLOWLIST, DEFAULT_BLOCK_HOURS, MAX_AUTO_BLOCKS_PER_HOUR, contain, expire_old,
                                release)
from ..response.audit import audit
from ..response.playbooks import PLAYBOOKS, PLAYBOOKS_BY_ID, decide, run_playbooks
from ..utils import aware, utcnow

router = APIRouter(prefix="/api/response", tags=["response"])


def containment_dict(c: Containment) -> dict:
    return {
        "id": c.id, "kind": c.kind, "target": c.target, "host": c.host, "process_path": c.process_path,
        "reason": c.reason, "incident_id": c.incident_id, "playbook_id": c.playbook_id, "created_by": c.created_by,
        "created_at": c.created_at, "expires_at": c.expires_at, "active": c.active, "released_at": c.released_at,
        "released_by": c.released_by, "dropped_count": c.dropped_count or 0, "last_dropped_at": c.last_dropped_at,
    }


def action_dict(a: ResponseAction) -> dict:
    return {
        "id": a.id, "category": a.category or "response", "action": a.action, "target": a.target,
        "actor": a.triggered_by, "username": a.username, "result": a.result, "status": a.status or "success", "incident_id": a.incident_id,
        "alert_id": a.alert_id, "playbook_id": a.playbook_id, "details": a.details or {},
        "created_at": a.created_at, "decided_at": a.decided_at,
    }


@router.get("/containments")
def list_containments(active: bool = True, kind: str | None = None, db: Session = Depends(get_db)):
    expire_old(db)
    db.commit()
    q = select(Containment).order_by(Containment.created_at.desc()).limit(500)
    if active:
        q = q.where(Containment.active.is_(True))
    if kind:
        q = q.where(Containment.kind == kind)
    return [containment_dict(c) for c in db.scalars(q).all()]


class ActionIn(BaseModel):
    action: Literal["block_ip", "quarantine_process", "isolate_host"]
    ip: str | None = None
    host: str | None = None
    path: str | None = None
    reason: str = Field(default="Manual action by analyst", max_length=500)
    hours: float | None = Field(default=None, gt=0, le=24 * 30)
    incident_id: int | None = None


@router.post("/actions")
def take_action(body: ActionIn, db: Session = Depends(get_db)):
    """An analyst contains something by hand. Guardrails still apply."""
    kind = {"block_ip": "ip", "quarantine_process": "process", "isolate_host": "host"}[body.action]
    status, message, c = contain(db, kind, ip=body.ip and body.ip.strip(), host=body.host, path=body.path,
                                 reason=body.reason, actor="analyst", incident_id=body.incident_id, hours=body.hours)
    db.commit()
    if status == "blocked_by_guardrail":
        raise HTTPException(422, f"Guardrail: {message}")
    return {"status": status, "message": message, "containment": containment_dict(c) if c else None}


@router.post("/containments/{cid}/release")
def release_containment(cid: int, db: Session = Depends(get_db)):
    c = db.get(Containment, cid)
    if c is None or not c.active:
        raise HTTPException(404, "No active containment with that id")
    release(db, c, actor="analyst")
    db.commit()
    return containment_dict(c)


@router.post("/release-all")
def release_all(db: Session = Depends(get_db)):
    """Lab reset: lift every active containment (so you can replay attacks)."""
    active = db.scalars(select(Containment).where(Containment.active.is_(True))).all()
    for c in active:
        release(db, c, actor="analyst", reason="lab reset (release all)")
    db.commit()
    return {"released": len(active)}


@router.get("/pending")
def pending(db: Session = Depends(get_db)):
    rows = db.scalars(select(ResponseAction).where(ResponseAction.status == "pending_approval")
                      .order_by(ResponseAction.created_at)).all()
    out = []
    for r in rows:
        inc = db.get(Incident, r.incident_id) if r.incident_id else None
        out.append({**action_dict(r), "incident": {"id": inc.id, "title": inc.title, "severity": inc.severity,
                                                   "score": inc.score, "status": inc.status} if inc else None})
    return out


@router.post("/pending/{action_id}/{decision}")
def decide_pending(action_id: int, decision: Literal["approve", "reject"], db: Session = Depends(get_db)):
    row = db.get(ResponseAction, action_id)
    if row is None or row.status != "pending_approval":
        raise HTTPException(404, "No pending action with that id")
    return action_dict(decide(db, row, approve=decision == "approve"))


@router.get("/playbooks")
def list_playbooks(db: Session = Depends(get_db)):
    settings = {p.id: p for p in db.scalars(select(Playbook)).all()}
    counts = dict(db.execute(select(ResponseAction.playbook_id, func.count()).where(
        ResponseAction.playbook_id.is_not(None), ResponseAction.status.in_(("success", "pending_approval")))
        .group_by(ResponseAction.playbook_id)).all())
    out = []
    for pd in PLAYBOOKS:
        pb = settings.get(pd.id)
        out.append({"id": pd.id, "name": pd.name, "description": pd.description, "trigger": pd.trigger,
                    "action": pd.action, "default_mode": pd.mode, "mode": pb.mode if pb else pd.mode,
                    "enabled": bool(pb and pb.enabled), "runs": counts.get(pd.id, 0)})
    return out


class PlaybookUpdate(BaseModel):
    enabled: bool | None = None
    mode: Literal["auto", "approval"] | None = None


@router.patch("/playbooks/{pb_id}")
def update_playbook(pb_id: str, body: PlaybookUpdate, db: Session = Depends(get_db)):
    pb = db.get(Playbook, pb_id)
    if pb is None or pb_id not in PLAYBOOKS_BY_ID:
        raise HTTPException(404, "Playbook not found")
    changes = {}
    if body.enabled is not None and body.enabled != pb.enabled:
        changes["enabled"], pb.enabled = body.enabled, body.enabled
    if body.mode and body.mode != pb.mode:
        changes["mode"], pb.mode = body.mode, body.mode
    if changes:
        pb.updated_at = utcnow()
        audit(db, category="config", action="playbook_updated", target=pb_id, actor="analyst",
              result=f"{pb.name}: " + ", ".join(f"{k} → {v}" for k, v in changes.items()), details=changes)
    db.commit()
    return next(p for p in list_playbooks(db) if p["id"] == pb_id)


@router.post("/run-playbooks")
def run_now(db: Session = Depends(get_db)):
    return run_playbooks(db)


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    expire_old(db)
    db.commit()
    active = db.scalars(select(Containment).where(Containment.active.is_(True))).all()
    day_ago = utcnow() - timedelta(hours=24)
    recent = db.scalars(select(ResponseAction).where(ResponseAction.category == "response",
                                                     ResponseAction.created_at >= day_ago)).all()

    # Mean/median time to contain: from incident DETECTION to the first successful containment.
    # Automation should make this seconds; manual approval makes it minutes.
    firsts = {}
    for a in db.scalars(select(ResponseAction).where(
            ResponseAction.status == "success", ResponseAction.category == "response",
            ResponseAction.action.in_(("block_ip", "quarantine_process", "isolate_host")),
            ResponseAction.incident_id.is_not(None))).all():
        t = aware(a.decided_at or a.created_at)
        if a.incident_id not in firsts or t < firsts[a.incident_id][0]:
            firsts[a.incident_id] = (t, a.triggered_by)
    ttc = {"auto": [], "analyst": []}
    for inc_id, (t, actor) in firsts.items():
        inc = db.get(Incident, inc_id)
        if inc is not None:
            ttc.setdefault(actor, []).append(max(0.0, (t - aware(inc.created_at)).total_seconds()))

    return {
        "active": {k: sum(1 for c in active if c.kind == k) for k in ("ip", "process", "host")},
        "pending_approvals": db.scalar(select(func.count()).select_from(ResponseAction).where(
            ResponseAction.status == "pending_approval")),
        "events_dropped": sum(c.dropped_count or 0 for c in db.scalars(select(Containment)).all()),
        "last_24h": {
            "auto_actions": sum(1 for a in recent if a.triggered_by == "auto" and a.status == "success"),
            "analyst_actions": sum(1 for a in recent if a.triggered_by == "analyst" and a.status == "success"),
            "guardrail_blocks": sum(1 for a in recent if a.status == "blocked_by_guardrail"),
        },
        "time_to_contain_s": {k: round(median(v), 1) if v else None for k, v in ttc.items()},
        "contained_incidents": len(firsts),
        "guardrails": {
            "allowlist": [{"ip": ip, "service": s} for ip, s in ALLOWLIST.items()],
            "max_auto_blocks_per_hour": MAX_AUTO_BLOCKS_PER_HOUR,
            "auto_block_hours": DEFAULT_BLOCK_HOURS,
            "rules": [
                "Internal IPs are never blocked",
                "Allowlisted services are never blocked",
                "Critical assets are never isolated automatically",
                f"At most {MAX_AUTO_BLOCKS_PER_HOUR} automatic IP blocks per hour",
                f"Automatic blocks expire after {DEFAULT_BLOCK_HOURS}h",
            ],
        },
    }
