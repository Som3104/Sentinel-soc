"""Rules management + on-demand detection runs."""
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..detection.engine import OPEN_STATUSES, effective_params, run_detection
from ..detection.rules import RULES, RULES_BY_ID
from ..models import Alert, DetectionRule, Event
from ..response.audit import audit
from ..utils import utcnow

router = APIRouter(prefix="/api", tags=["detection"])


def rule_dict(rule: DetectionRule, db: Session) -> dict:
    rdef = RULES_BY_ID[rule.id]
    params = effective_params(rule, rdef)
    hits = db.execute(
        select(func.count(), func.max(Alert.last_seen)).where(Alert.rule_id == rule.id)
    ).one()
    open_hits = db.scalar(select(func.count()).where(Alert.rule_id == rule.id, Alert.status.in_(OPEN_STATUSES)))
    return {
        "id": rule.id, "name": rule.name, "description": rule.description, "source": rule.source,
        "mitre_tactic": rule.mitre_tactic, "mitre_technique": rule.mitre_technique,
        "mitre_technique_name": rule.mitre_technique_name,
        "severity": rule.severity, "default_severity": rdef.severity, "enabled": rule.enabled,
        "params": params, "default_params": rdef.params, "customized": bool(rule.params),
        "logic": rdef.logic.format(**params), "recommended": rdef.recommended,
        "hits": hits[0], "open_hits": open_hits, "last_fired": hits[1],
    }


@router.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    rows = {r.id: r for r in db.scalars(select(DetectionRule)).all()}
    return [rule_dict(rows[rd.id], db) for rd in RULES if rd.id in rows]


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    params: dict | None = None
    reset: bool = False


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    rdef = RULES_BY_ID.get(rule_id)
    if rule is None or rdef is None:
        raise HTTPException(404, "Rule not found")

    if body.reset:
        rule.params, rule.severity, rule.enabled = {}, rdef.severity, True
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.severity:
        rule.severity = body.severity
    if body.params:
        cleaned = {}
        for key, value in body.params.items():
            if key not in rdef.params:
                raise HTTPException(422, f"Unknown parameter '{key}' for {rule_id}")
            default = rdef.params[key]
            try:
                if isinstance(default, list):
                    items = value if isinstance(value, list) else str(value).split(",")
                    caster = type(default[0]) if default else str
                    cleaned[key] = [caster(str(v).strip()) for v in items if str(v).strip()]
                else:
                    cleaned[key] = type(default)(value)
            except (TypeError, ValueError):
                raise HTTPException(422, f"Bad value for '{key}': {value!r}")
            if isinstance(cleaned[key], (int, float)) and cleaned[key] <= 0:
                raise HTTPException(422, f"'{key}' must be positive")
        # Only store values that differ from the defaults.
        merged = {**(rule.params or {}), **cleaned}
        rule.params = {k: v for k, v in merged.items() if v != rdef.params[k]}
    rule.updated_at = utcnow()
    audit(db, category="config", action="rule_updated", target=rule_id, actor="analyst",
          result=f"{rule.name}: " + ", ".join(f"{k}={v}" for k, v in body.model_dump(exclude_none=True).items() if v not in (False, None)),
          details=body.model_dump(exclude_none=True))
    db.commit()
    return rule_dict(rule, db)


@router.post("/detection/run")
def run_now(hours: int = Query(default=24, ge=1, le=720), db: Session = Depends(get_db)):
    """Re-scan stored events. Useful after tuning a rule or importing old logs."""
    end = utcnow() + timedelta(minutes=5)   # simulator events can be slightly in the future
    start = end - timedelta(hours=hours)
    scanned = db.scalar(select(func.count()).select_from(Event).where(Event.timestamp >= start))
    return {"hours": hours, "events_scanned": scanned, **run_detection(db, start, end)}
