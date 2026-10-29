"""Alerts API: list, investigate and triage detections."""
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..detection.engine import OPEN_STATUSES
from ..models import Alert, DetectionRule, Event
from ..schemas import EventOut
from ..response.audit import audit
from ..utils import utcnow

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

Status = Literal["new", "investigating", "resolved", "false_positive"]


def alert_dict(a: Alert) -> dict:
    d = a.details or {}
    return {
        "id": a.id, "rule_id": a.rule_id, "title": a.title, "detector": a.detector,
        "severity": a.severity, "score": a.score, "status": a.status or "new",
        "entity": a.entity, "host": a.host, "summary": a.summary,
        "mitre_tactic": a.mitre_tactic, "mitre_technique": a.mitre_technique,
        "first_seen": a.first_seen, "last_seen": a.last_seen, "event_count": a.event_count,
        "created_at": a.created_at, "updated_at": a.updated_at, "incident_id": a.incident_id,
        "metrics": d.get("metrics", {}), "notes_count": len(d.get("notes", [])),
    }


@router.get("")
def list_alerts(
    status: str | None = Query(default=None, description="new | investigating | resolved | false_positive | open"),
    severity: str | None = None,
    rule_id: str | None = None,
    detector: str | None = Query(default=None, description="rule | ml"),
    entity: str | None = None,
    q: str | None = None,
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(get_db),
):
    query = select(Alert).order_by(Alert.last_seen.desc(), Alert.id.desc()).limit(limit)
    if status == "open":
        query = query.where(Alert.status.in_(OPEN_STATUSES))
    elif status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)
    if detector:
        query = query.where(Alert.detector == detector)
    if entity:
        query = query.where(Alert.entity == entity)
    if q:
        like = f"%{q}%"
        query = query.where(or_(Alert.title.ilike(like), Alert.entity.ilike(like),
                                Alert.host.ilike(like), Alert.summary.ilike(like)))
    return [alert_dict(a) for a in db.scalars(query).all()]


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    """Numbers for the Overview page and the sidebar badge."""
    alerts = db.scalars(select(Alert)).all()
    open_alerts = [a for a in alerts if (a.status or "new") in OPEN_STATUSES]
    latest = sorted(open_alerts, key=lambda a: (a.last_seen or a.created_at), reverse=True)[:6]
    return {
        "total": len(alerts),
        "open": len(open_alerts),
        "open_by_severity": {s: sum(1 for a in open_alerts if a.severity == s) for s in ("critical", "high", "medium", "low")},
        "by_status": dict(Counter(a.status or "new" for a in alerts)),
        "by_rule": dict(Counter(a.rule_id for a in alerts)),
        "by_tactic": dict(Counter(a.mitre_tactic for a in open_alerts if a.mitre_tactic)),
        "open_by_detector": dict(Counter(a.detector for a in open_alerts)),
        "latest_open": [alert_dict(a) for a in latest],
    }


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "Alert not found")
    d = a.details or {}
    ids = d.get("event_ids", [])
    events = db.scalars(select(Event).where(Event.id.in_(ids)).order_by(Event.timestamp)).all() if ids else []
    rule = db.get(DetectionRule, a.rule_id)
    # Other alerts about the same entity = context for the investigation (Phase 5 groups these into incidents).
    related = db.scalars(
        select(Alert).where(Alert.entity == a.entity, Alert.id != a.id).order_by(Alert.last_seen.desc()).limit(10)
    ).all()
    return {
        **alert_dict(a),
        "logic": d.get("logic"),
        "recommended": d.get("recommended", []),
        "notes": d.get("notes", []),
        "rule": {"id": rule.id, "name": rule.name, "description": rule.description,
                 "technique_name": rule.mitre_technique_name} if rule else None,
        "evidence": [EventOut.model_validate(e).model_dump() for e in events],
        "related": [alert_dict(r) for r in related],
    }


class AlertUpdate(BaseModel):
    status: Status | None = None
    note: str | None = Field(default=None, max_length=2000)


@router.patch("/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, db: Session = Depends(get_db)):
    """Triage: change status and/or add an analyst note."""
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "Alert not found")
    details = dict(a.details or {})
    notes = list(details.get("notes", []))
    now = utcnow()
    if body.status and body.status != a.status:
        notes.append({"at": now.isoformat(), "author": "analyst", "text": f"Status changed: {a.status} → {body.status}", "system": True})
        audit(db, category="case", action="alert_status", target=f"ALERT-{a.id}", actor="analyst",
              result=f"{a.title}: {a.status} → {body.status}", alert_id=a.id, incident_id=a.incident_id)
        a.status = body.status
    if body.note and body.note.strip():
        notes.append({"at": now.isoformat(), "author": "analyst", "text": body.note.strip(), "system": False})
        audit(db, category="case", action="alert_note", target=f"ALERT-{a.id}", actor="analyst",
              result=body.note.strip()[:300], alert_id=a.id, incident_id=a.incident_id)
    details["notes"] = notes
    a.details = details
    a.updated_at = now
    db.commit()
    if a.incident_id:                          # an alert marked false positive lowers its incident's risk
        from ..detection.correlation import correlate   # noqa: PLC0415
        correlate(db)
    return get_alert(alert_id, db)
