"""Incidents API: the case-management side of the SOC."""
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..assets import ASSETS, asset
from ..database import get_db
from ..detection.correlation import ACTIVE, correlate, kill_chain, set_incident_status
from ..models import Alert, Containment, Event, Incident, ResponseAction
from ..response.audit import audit
from ..utils import aware, is_external, utcnow
from .alerts import alert_dict

router = APIRouter(prefix="/api", tags=["incidents"])

Status = Literal["open", "investigating", "contained", "resolved", "false_positive"]
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def incident_dict(i: Incident) -> dict:
    return {
        "id": i.id, "title": i.title, "status": i.status, "severity": i.severity, "score": i.score,
        "entity": i.entity, "summary": i.summary, "first_seen": i.first_seen, "last_seen": i.last_seen,
        "created_at": i.created_at, "updated_at": i.updated_at, "closed_at": i.closed_at,
        "alert_count": i.alert_count or 0, "event_count": i.event_count or 0,
        "actors": i.actors or [], "hosts": i.hosts or [], "tactics": i.tactics or [],
        "detectors": i.detectors or [], "score_breakdown": i.score_breakdown or [],
        "notes_count": len(i.notes or []),
    }


@router.get("/incidents")
def list_incidents(
    status: str | None = Query(default="active", description="active | all | open | investigating | contained | resolved | false_positive"),
    severity: str | None = None,
    q: str | None = None,
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(get_db),
):
    query = select(Incident).order_by(Incident.last_seen.desc(), Incident.id.desc()).limit(limit)
    if status == "active":
        query = query.where(Incident.status.in_(ACTIVE))
    elif status and status != "all":
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if q:
        like = f"%{q}%"
        query = query.where(or_(Incident.title.ilike(like), Incident.entity.ilike(like), Incident.summary.ilike(like)))
    return [incident_dict(i) for i in db.scalars(query).all()]


@router.get("/incidents/summary")
def incidents_summary(db: Session = Depends(get_db)):
    incidents = db.scalars(select(Incident)).all()
    active = [i for i in incidents if i.status in ACTIVE]
    top = sorted(active, key=lambda i: (SEV_RANK.get(i.severity, 0), i.score or 0), reverse=True)[:5]
    return {
        "total": len(incidents),
        "active": len(active),
        "active_by_severity": {s: sum(1 for i in active if i.severity == s) for s in ("critical", "high", "medium", "low")},
        "by_status": dict(Counter(i.status for i in incidents)),
        "top_active": [incident_dict(i) for i in top],
    }


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found")
    alerts = sorted(db.scalars(select(Alert).where(Alert.incident_id == inc.id)).all(),
                    key=lambda a: aware(a.first_seen or a.created_at))

    # Evidence across all alerts: who was involved, and the shape of activity over time.
    ids = sorted({i for a in alerts for i in (a.details or {}).get("event_ids", [])})[:3000]
    events = db.scalars(select(Event).where(Event.id.in_(ids))).all() if ids else []
    users = Counter(e.user for e in events if e.user)
    per_minute = Counter(aware(e.timestamp).replace(second=0, microsecond=0) for e in events)

    # Recommended actions from every alert, most severe alert first, without duplicates.
    # ML's generic advice ("read why the model flagged this") only helps when no rule explains the attack.
    recommended = []
    has_rules = any(a.detector == "rule" for a in alerts)
    for a in sorted(alerts, key=lambda a: -SEV_RANK.get(a.severity, 0)):
        if has_rules and a.detector == "ml":
            continue
        for r in (a.details or {}).get("recommended", []):
            if r not in recommended:
                recommended.append(r)

    return {
        **incident_dict(inc),
        "notes": inc.notes or [],
        "alerts": [alert_dict(a) for a in alerts],
        "kill_chain": kill_chain(alerts),
        "assets": [{"host": h, **asset(h)} for h in inc.hosts or []],
        "users": [{"user": u, "events": n} for u, n in users.most_common(8)],
        "activity": [{"time": t.isoformat(), "events": n} for t, n in sorted(per_minute.items())],
        "recommended": recommended[:10],
        "response": _response_section(db, inc, alerts),
    }


def _response_section(db: Session, inc: Incident, alerts: list[Alert]) -> dict:
    """Containment options for this incident, plus everything already done or waiting for approval."""
    from ..response.actions import active_containment, target_for   # noqa: PLC0415
    from .response import action_dict, containment_dict            # noqa: PLC0415

    suggestions, seen = [], set()

    def suggest(kind, label, why, **kw):
        target = target_for(kind, kw.get("ip"), kw.get("host"), kw.get("path"))
        if target in seen:
            return
        seen.add(target)
        c = active_containment(db, kind, target)
        suggestions.append({"kind": kind, "target": target, "label": label, "why": why, **kw,
                            "done": c is not None, "containment_id": c.id if c else None})

    for ip in inc.actors or []:
        if is_external(ip):
            suggest("ip", f"Block {ip}", "Firewall drops all its traffic", ip=ip)
    for a in alerts:
        m = (a.details or {}).get("metrics", {})
        if m.get("path") and a.host:
            suggest("process", f"Quarantine {m.get('process') or m['path']} on {a.host}",
                    "Kill it and stop it running again", host=a.host, path=m["path"])
    for h in inc.hosts or []:
        suggest("host", f"Isolate {h}", f"Cut it off the network ({asset(h)['criticality']} asset)", host=h)

    actions = db.scalars(select(ResponseAction).where(ResponseAction.incident_id == inc.id,
                                                      ResponseAction.category == "response")
                         .order_by(ResponseAction.created_at)).all()
    contained = db.scalars(select(Containment).where(Containment.incident_id == inc.id)).all()
    return {
        "suggestions": suggestions,
        "actions": [action_dict(a) for a in actions],
        "pending": [action_dict(a) for a in actions if a.status == "pending_approval"],
        "containments": [containment_dict(c) for c in contained],
    }


class IncidentUpdate(BaseModel):
    status: Status | None = None
    note: str | None = Field(default=None, max_length=2000)


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, body: IncidentUpdate, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found")
    if body.status and body.status != inc.status:
        audit(db, category="case", action="incident_status", target=f"INC-{inc.id}", actor="analyst",
              result=f"{inc.status} → {body.status}", incident_id=inc.id)
        set_incident_status(db, inc, body.status)
    if body.note and body.note.strip():
        notes = list(inc.notes or [])
        notes.append({"at": utcnow().isoformat(), "author": "analyst", "system": False, "text": body.note.strip()})
        inc.notes = notes
        inc.updated_at = utcnow()
        audit(db, category="case", action="incident_note", target=f"INC-{inc.id}", actor="analyst",
              result=body.note.strip()[:300], incident_id=inc.id)
    db.commit()
    return get_incident(incident_id, db)


@router.post("/incidents/correlate")
def run_correlation(db: Session = Depends(get_db)):
    """Re-group open alerts into incidents (also runs automatically after every detection pass)."""
    return correlate(db)


@router.get("/assets")
def list_assets():
    return [{"host": h, **a} for h, a in ASSETS.items()]
