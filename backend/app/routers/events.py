"""Read-only endpoints to look at what's been ingested (powers the Live Events page)."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Event
from ..schemas import EventOut

router = APIRouter(prefix="/api", tags=["events"])


@router.get("/events", response_model=list[EventOut])
def list_events(
    source: str | None = None,
    event_type: str | None = None,
    host: str | None = None,
    src_ip: str | None = None,
    label: str | None = None,
    q: str | None = Query(default=None, description="free-text search across user, IPs and process"),
    since_id: int | None = Query(default=None, description="only events with id > since_id (for live polling)"),
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
):
    query = select(Event).order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit)
    if source:
        query = query.where(Event.source == source)
    if event_type:
        query = query.where(Event.event_type == event_type)
    if host:
        query = query.where(Event.host == host)
    if src_ip:
        query = query.where(Event.src_ip == src_ip)
    if label:
        query = query.where(Event.label == label)
    if since_id:
        query = query.where(Event.id > since_id)
    if q:
        like = f"%{q}%"
        query = query.where(or_(
            Event.user.ilike(like), Event.src_ip.ilike(like), Event.dst_ip.ilike(like),
            Event.process_name.ilike(like), Event.host.ilike(like),
        ))
    return db.scalars(query).all()


@router.get("/events/filters")
def event_filters(db: Session = Depends(get_db)):
    """Distinct values for the dropdowns on the Live Events page."""
    def distinct(col):
        return sorted(v for v in db.scalars(select(col).distinct()).all() if v)

    return {
        "sources": distinct(Event.source),
        "event_types": distinct(Event.event_type),
        "hosts": distinct(Event.host),
        "labels": distinct(Event.label),
    }


@router.get("/events/stats")
def event_stats(db: Session = Depends(get_db)):
    """Counts by source, event type and label - a quick sanity check after a simulation run."""
    def counts(col):
        rows = db.execute(select(col, func.count()).group_by(col)).all()
        return {str(k): v for k, v in rows}

    return {
        "total": db.scalar(select(func.count()).select_from(Event)),
        "by_source": counts(Event.source),
        "by_event_type": counts(Event.event_type),
        "by_label": counts(Event.label),
    }
