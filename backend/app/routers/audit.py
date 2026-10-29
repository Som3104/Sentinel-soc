"""Audit Log API: read-only history of every action in the SOC."""
from collections import Counter

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ResponseAction
from .response import action_dict

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit(
    category: str | None = Query(default=None, description="response | case | config | system | access"),
    actor: str | None = Query(default=None, description="auto | analyst | system"),
    status: str | None = None,
    username: str | None = None,
    incident_id: int | None = None,
    q: str | None = None,
    limit: int = Query(default=300, le=2000),
    db: Session = Depends(get_db),
):
    query = select(ResponseAction).order_by(ResponseAction.created_at.desc(), ResponseAction.id.desc()).limit(limit)
    if category:
        query = query.where(ResponseAction.category == category)
    if actor:
        query = query.where(ResponseAction.triggered_by == actor)
    if status:
        query = query.where(ResponseAction.status == status)
    if username:
        query = query.where(ResponseAction.username == username)
    if incident_id:
        query = query.where(ResponseAction.incident_id == incident_id)
    if q:
        like = f"%{q}%"
        query = query.where(or_(ResponseAction.target.ilike(like), ResponseAction.result.ilike(like),
                                ResponseAction.action.ilike(like), ResponseAction.username.ilike(like)))
    return [action_dict(a) for a in db.scalars(query).all()]


@router.get("/summary")
def audit_summary(db: Session = Depends(get_db)):
    rows = db.execute(select(ResponseAction.category, ResponseAction.triggered_by)).all()
    return {"total": len(rows), "by_category": dict(Counter(r[0] or "response" for r in rows)),
            "by_actor": dict(Counter(r[1] for r in rows))}
