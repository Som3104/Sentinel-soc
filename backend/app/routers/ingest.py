"""Ingestion: the front door for all logs.

Accepts a BATCH of events (a list) rather than one at a time - shipping logs
in batches is far cheaper than one HTTP request per log line.

After storing a batch, the detection engine runs over the batch's time range,
so attacks become alerts within seconds of the logs arriving - then correlation
groups them into incidents and playbooks respond (block, quarantine, isolate).
"""
import threading

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import require_ingest_key
from ..database import get_db
from ..detection.engine import run_detection
from ..models import Alert, Event, Incident, ResponseAction
from ..realtime import hub
from ..response.actions import apply_containments
from ..schemas import EventIn, IngestResult

router = APIRouter(prefix="/api", tags=["ingest"])

# One batch at a time. The live traffic generator, the Attack Simulator buttons and the CLI
# can all send at once; detection + correlation must see each batch's results before the next
# (otherwise two batches could both open "INC-new" for the same attacker).
_pipeline_lock = threading.Lock()


def ingest_events(db: Session, events: list[EventIn], source: str = "ingest") -> IngestResult:
    """The whole pipeline for one batch. Used by POST /api/ingest (the CLI simulator) and by the
    lab endpoints and live traffic generator (the Attack Simulator page)."""
    with _pipeline_lock:
        out, feed = _run_pipeline(db, events)
    hub.publish({"type": "update", "source": source, "stats": out.model_dump(), "feed": feed})
    return out


def _run_pipeline(db: Session, events: list[EventIn]) -> tuple[IngestResult, list[dict]]:
    marks = _high_water_marks(db)

    # Simulated firewall + EDR: drop events our active containments would have stopped
    # (blocked IPs, quarantined binaries, isolated hosts). See response/actions.py.
    stored, dropped = apply_containments(db, events)
    for e in stored:
        db.add(Event(**e.model_dump()))
    db.commit()

    result = {}
    if stored:
        times = [e.timestamp for e in stored]
        result = run_detection(db, min(times), max(times))

    out = IngestResult(
        received=len(events), stored=len(stored), dropped_blocked=dropped,
        alerts_created=result.get("alerts_created", 0), alerts_updated=result.get("alerts_updated", 0),
        incidents_created=result.get("incidents_created", 0), incidents_updated=result.get("incidents_updated", 0),
        responses_executed=result.get("responses_executed", 0), responses_pending=result.get("responses_pending", 0),
    )
    return out, _feed_since(db, marks)


ACTION_TEXT = {"block_ip": "Block IP", "quarantine_process": "Quarantine", "isolate_host": "Isolate host"}


def _high_water_marks(db: Session) -> dict:
    return {
        "alert": db.scalar(select(func.max(Alert.id))) or 0,
        "incident": db.scalar(select(func.max(Incident.id))) or 0,
        "action": db.scalar(select(func.max(ResponseAction.id))) or 0,
    }


def _feed_since(db: Session, marks: dict) -> list[dict]:
    """What's new since `marks`: the items behind the dashboard's live notifications."""
    feed = []
    for i in db.scalars(select(Incident).where(Incident.id > marks["incident"]).order_by(Incident.id)).all():
        feed.append({"kind": "incident", "severity": i.severity, "id": i.id, "link": f"/incidents/{i.id}",
                     "text": f"INC-{i.id} opened: {i.title}", "score": i.score})
    for a in db.scalars(select(ResponseAction).where(
            ResponseAction.id > marks["action"], ResponseAction.category == "response",
            ResponseAction.status.in_(("success", "pending_approval"))).order_by(ResponseAction.id)).all():
        pending = a.status == "pending_approval"
        feed.append({"kind": "approval" if pending else "response", "id": a.id,
                     "link": "/response" if pending else (f"/incidents/{a.incident_id}" if a.incident_id else "/response"),
                     "text": f"{ACTION_TEXT.get(a.action, a.action.replace('_', ' '))} {a.target}"
                             + (f" ({a.playbook_id})" if a.playbook_id else "")})
    for a in db.scalars(select(Alert).where(Alert.id > marks["alert"]).order_by(Alert.id).limit(50)).all():
        feed.append({"kind": "alert", "severity": a.severity, "id": a.id, "link": f"/alerts?id={a.id}",
                     "text": f"{a.title} · {a.entity}", "detector": a.detector})
    return feed


@router.post("/ingest", response_model=IngestResult, dependencies=[Depends(require_ingest_key)])
def ingest(events: list[EventIn], db: Session = Depends(get_db)):
    """Log shippers authenticate with the X-API-Key header (machines don't log in like people)."""
    return ingest_events(db, events)
