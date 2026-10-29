"""Detection engine: runs every enabled rule and turns matches into alerts.

Called automatically after each /api/ingest batch, and on demand from the
"Run detection" button (POST /api/detection/run).

Alert de-duplication (a core SOC concept): rules re-examine overlapping time
windows, and a long attack keeps matching. Instead of 50 alerts for one brute
force, matches with the same dedup key (rule + entity) are MERGED into the
existing open alert: its evidence, event count, last_seen and score grow.
"""
import math
import time
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, DetectionRule
from ..utils import aware, utcnow
from .rules import RULES, RULES_BY_ID, Match, RuleDef

OPEN_STATUSES = ("new", "investigating")
MERGE_GAP = timedelta(minutes=15)       # activity further apart than this becomes a new alert
MAX_EVIDENCE = 500                      # cap stored event ids per alert
BASE_SCORE = {"low": 25, "medium": 50, "high": 70, "critical": 88}


def score_for(severity: str, event_count: int) -> float:
    """Phase 3 scoring: severity sets the base, volume adds a little (log scale).
    Phase 5 replaces this with a richer score (asset value, ML, repeat offender...)."""
    return float(min(100, BASE_SCORE.get(severity, 50) + min(10, int(math.log2(max(1, event_count))))))


def effective_params(rule: DetectionRule, rdef: RuleDef) -> dict:
    """Defaults from code, overridden by whatever the analyst saved in the UI."""
    return {**rdef.params, **(rule.params or {})}


def seed_rules(db: Session) -> None:
    """Make sure every rule in code has a row in the DB. Keeps analysts' edits
    (enabled / severity / params) but refreshes names and descriptions."""
    existing = {r.id: r for r in db.scalars(select(DetectionRule)).all()}
    for rd in RULES:
        row = existing.get(rd.id)
        if row is None:
            db.add(DetectionRule(
                id=rd.id, name=rd.name, description=rd.description, source=rd.source,
                mitre_tactic=rd.tactic, mitre_technique=rd.technique, mitre_technique_name=rd.technique_name,
                severity=rd.severity, enabled=True, params={},
            ))
        else:
            row.name, row.description, row.source = rd.name, rd.description, rd.source
            row.mitre_tactic, row.mitre_technique, row.mitre_technique_name = rd.tactic, rd.technique, rd.technique_name
    db.commit()


def _upsert(db: Session, rule: DetectionRule, rdef: RuleDef, params: dict, m: Match) -> str | None:
    dedup_key = f"{rule.id}:{m.key or m.entity}"
    ids = [e.id for e in m.events]

    candidate = db.scalars(
        select(Alert).where(Alert.dedup_key == dedup_key, Alert.last_seen >= m.first_seen - MERGE_GAP)
        .order_by(Alert.last_seen.desc()).limit(1)
    ).first()

    now = utcnow()
    if candidate is not None:
        old_ids = set((candidate.details or {}).get("event_ids", []))
        new_ids = [i for i in ids if i not in old_ids]
        if not new_ids:
            return None                                   # already known - nothing to do
        if candidate.status in OPEN_STATUSES:
            merged = sorted(old_ids | set(ids))
            details = dict(candidate.details or {})       # copy: SQLAlchemy only saves a NEW dict
            details["event_ids"] = merged[-MAX_EVIDENCE:]
            candidate.event_count = len(merged)
            candidate.first_seen = min(aware(candidate.first_seen), m.first_seen)
            candidate.last_seen = max(aware(candidate.last_seen), m.last_seen)
            if m.score is None:                           # rule: newest evidence wins, score from volume
                details["metrics"] = m.metrics
                candidate.summary = m.summary
                candidate.score = score_for(candidate.severity, len(merged))
            elif m.score >= (candidate.score or 0):       # ML: keep the most suspicious window's verdict
                details["metrics"] = m.metrics
                candidate.summary, candidate.score, candidate.severity = m.summary, m.score, m.severity
                candidate.title, candidate.mitre_technique, candidate.mitre_tactic = m.title, m.technique, m.tactic
            candidate.details = details
            candidate.updated_at = now
            return "updated"
        # The old alert was resolved, but the attacker is back: open a fresh alert for the new activity.
        ids = new_ids

    is_ml = rdef.detector == "ml"
    severity = m.severity or rule.severity
    db.add(Alert(
        rule_id=rule.id, title=m.title or rule.name, detector=rdef.detector, severity=severity,
        score=m.score if m.score is not None else score_for(severity, len(ids)),
        entity=m.entity, host=m.host, summary=m.summary,
        mitre_technique=m.technique if is_ml else rule.mitre_technique,
        mitre_tactic=m.tactic if is_ml else rule.mitre_tactic,
        first_seen=m.first_seen, last_seen=m.last_seen, event_count=len(ids),
        dedup_key=dedup_key, status="new", created_at=now, updated_at=now,
        details={
            "metrics": m.metrics,
            "event_ids": ids[-MAX_EVIDENCE:],
            "logic": rdef.logic.format(**params),
            "recommended": rdef.recommended,
            "notes": [],
        },
    ))
    return "created"


def run_detection(db: Session, start: datetime, end: datetime) -> dict:
    """Run all enabled rules over [start, end] (plus each rule's lookback)."""
    t0 = time.perf_counter()
    created = updated = 0
    per_rule = {}
    for rule in db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all():
        rdef = RULES_BY_ID.get(rule.id)
        if rdef is None:
            continue
        params = effective_params(rule, rdef)
        lookback = timedelta(seconds=rdef.lookback_seconds(params))
        for m in rdef.fn(db, params, start - lookback, end):
            result = _upsert(db, rule, rdef, params, m)
            db.flush()   # so the next match's dedup lookup sees alerts just added
            if result:
                per_rule[rule.id] = per_rule.get(rule.id, 0) + 1
                created += result == "created"
                updated += result == "updated"
    db.commit()
    from ..response.playbooks import run_playbooks   # noqa: PLC0415  (Phase 6: automated response)
    from .correlation import correlate               # noqa: PLC0415  (Phase 5: group alerts into incidents)
    incidents = correlate(db)
    responses = run_playbooks(db)
    return {"alerts_created": created, "alerts_updated": updated, "by_rule": per_rule, **incidents, **responses,
            "duration_ms": round((time.perf_counter() - t0) * 1000)}
