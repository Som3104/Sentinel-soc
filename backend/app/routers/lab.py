"""Attack Simulator API: launch attacks, run live traffic and reset the lab from the browser.

Everything here goes through ingest_events() - the exact pipeline real logs take -
so what you see on the dashboard is the real detection and response, not a canned demo.
"""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from ..auth.deps import CurrentUser, authorize, require_role
from ..database import get_db
from ..lab.live import live
from ..lab.scenarios import CATALOG, CATALOG_BY_ID, attacker_of, build_full_demo, build_scenario
from ..ml.dataset import load_simulator
from ..models import Alert, Containment, Event, Incident, ResponseAction
from ..realtime import hub
from ..response.actions import active_containment, release, target_for
from ..response.audit import audit
from ..schemas import EventIn
from ..utils import utcnow
from .ingest import ingest_events

router = APIRouter(prefix="/api/lab", tags=["lab"])
BATCH = 500


class RunIn(BaseModel):
    attacks: list[str] = Field(min_length=1)
    include_normal: bool = True


class LiveIn(BaseModel):
    running: bool
    rate_per_min: int = Field(20, ge=5, le=300)
    attacks: bool = False
    attack_every_s: int = Field(45, ge=15, le=600)


class ResetIn(BaseModel):
    scope: Literal["containments", "full"] = "containments"


def _ingest_all(db: Session, events: list[dict], source: str) -> dict:
    """Send events in sorted batches (like the CLI simulator) and add up the results."""
    total: dict[str, int] = {}
    for i in range(0, len(events), BATCH):
        r = ingest_events(db, [EventIn(**e) for e in events[i:i + BATCH]], source=source).model_dump()
        for k, v in r.items():
            total[k] = total.get(k, 0) + v
    return total


@router.get("/scenarios")
def scenarios(db: Session = Depends(get_db)):
    sim = load_simulator(reload=False)
    out = []
    for c in CATALOG:
        ip = attacker_of(sim, c["id"])
        blocked = active_containment(db, "ip", target_for("ip", ip=ip)) if ip else None
        out.append({**c, "attacker_ip": ip,
                    "blocked": {"containment_id": blocked.id, "since": blocked.created_at.isoformat()} if blocked else None})
    return out


@router.post("/run")
def run(body: RunIn, db: Session = Depends(get_db)):
    unknown = [a for a in body.attacks if a not in CATALOG_BY_ID]
    if unknown:
        raise HTTPException(422, f"Unknown scenario(s): {unknown}")
    events = []
    for name in body.attacks:
        events += build_scenario(name, background=body.include_normal)
    events.sort(key=lambda e: e["timestamp"])
    return {"scenarios": body.attacks, **_ingest_all(db, events, source="lab")}


@router.post("/demo")
def demo(db: Session = Depends(get_db)):
    """30 minutes of normal traffic with all 7 attacks hidden in it (same as running simulator.py)."""
    return {"scenarios": [c["id"] for c in CATALOG], **_ingest_all(db, build_full_demo(30), source="lab")}


@router.get("/status")
def status():
    return {"live": live.status(), "websocket_clients": len(hub.clients)}


@router.post("/live")
def set_live(body: LiveIn):
    if body.running:
        return live.start(body.rate_per_min, body.attacks, body.attack_every_s)
    return live.stop()


@router.post("/reset")
def reset(body: ResetIn, user: CurrentUser = Depends(authorize), db: Session = Depends(get_db)):
    """containments: lift every block/quarantine/isolation so attacks can be replayed.
    full: also delete all events, alerts and incidents (a clean slate for a demo).
    The audit log is NEVER deleted (that's the point of an audit log): old entries stay,
    detached from the incidents that no longer exist, and the reset itself is logged."""
    if body.scope == "full":
        require_role(user, "admin", "Wiping all lab data")
    if body.scope == "containments":
        active = db.scalars(select(Containment).where(Containment.active.is_(True))).all()
        for c in active:
            release(db, c, actor="analyst", reason="lab reset (release all)")
        db.commit()
        result = {"scope": "containments", "released": len(active)}
    else:
        if live.running:
            live.stop()
        now = utcnow()
        skipped = db.execute(update(ResponseAction).where(ResponseAction.status == "pending_approval")
                             .values(status="skipped", decided_at=now)).rowcount
        db.execute(update(ResponseAction).values(incident_id=None))      # keep the rows, drop the links
        counts = {}
        for name, model in (("containments", Containment), ("alerts", Alert), ("incidents", Incident), ("events", Event)):
            counts[name] = db.execute(delete(model)).rowcount
        audit(db, category="system", action="lab_reset", target="lab", actor="analyst",
              result="Lab reset: deleted " + ", ".join(f"{v} {k}" for k, v in counts.items())
                     + (f"; {skipped} pending approvals closed" if skipped else ""),
              details={**counts, "approvals_closed": skipped})
        db.commit()
        result = {"scope": "full", "deleted": counts, "approvals_closed": skipped}
    hub.publish({"type": "update", "source": "reset"})
    return result
