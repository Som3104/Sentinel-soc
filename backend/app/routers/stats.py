"""Aggregated numbers for the Overview dashboard.

Bucketing is done in Python (not SQL) so the same code works on PostgreSQL
and on the SQLite fallback. For a lab-sized dataset that's plenty fast.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..detection.engine import OPEN_STATUSES
from ..models import Alert, Containment, Event, Incident
from ..utils import aware, is_external

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/overview")
def overview(window: int = Query(default=60, ge=5, le=1440, description="minutes"), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=window)

    rows = db.execute(
        select(Event.timestamp, Event.source, Event.event_type, Event.src_ip, Event.host, Event.label)
        .where(Event.timestamp >= start)
    ).all()

    # --- events per minute, split by source (stacked area chart)
    buckets: dict[datetime, Counter] = defaultdict(Counter)
    for ts, source, *_ in rows:
        minute = aware(ts).replace(second=0, microsecond=0)
        buckets[minute][source] += 1
    timeline = []
    t = start.replace(second=0, microsecond=0)
    while t <= now:
        c = buckets.get(t, Counter())
        timeline.append({"time": t.isoformat(), "auth": c["auth"], "process": c["process"], "network": c["network"]})
        t += timedelta(minutes=1)

    # --- top source IPs, with failed-login counts (the brute-force signal you found by hand)
    ip_total, ip_failed = Counter(), Counter()
    for _, _, etype, ip, *_ in rows:
        if ip:
            ip_total[ip] += 1
            if etype == "login_failed":
                ip_failed[ip] += 1
    top_ips = [
        {"ip": ip, "events": n, "failed_logins": ip_failed[ip], "external": is_external(ip)}
        for ip, n in ip_total.most_common(8)
    ]
    # Make sure the noisiest failed-login IPs are visible even if their total volume is low.
    top_failed = [{"ip": ip, "failed_logins": n, "external": is_external(ip)} for ip, n in ip_failed.most_common(5)]

    host_counts = Counter(r.host for r in rows)
    fifteen = now - timedelta(minutes=15)

    return {
        "window_minutes": window,
        "generated_at": now.isoformat(),
        "totals": {
            "events_all_time": db.scalar(select(func.count()).select_from(Event)),
            "events_in_window": len(rows),
            "events_last_15m": sum(1 for r in rows if aware(r.timestamp) >= fifteen),
            "failed_logins": sum(1 for r in rows if r.event_type == "login_failed"),
            "unique_src_ips": len(ip_total),
            "external_ips": sum(1 for ip in ip_total if is_external(ip)),
            "hosts": len(host_counts),
            "open_alerts": db.scalar(select(func.count()).select_from(Alert).where(Alert.status.in_(OPEN_STATUSES))),
            "blocked_ips": db.scalar(select(func.count()).select_from(Containment).where(
                Containment.kind == "ip", Containment.active.is_(True))),
            "events_dropped": db.scalar(select(func.coalesce(func.sum(Containment.dropped_count), 0))),
            "active_incidents": db.scalar(select(func.count()).select_from(Incident).where(
                Incident.status.in_(("open", "investigating", "contained")))),
        },
        "timeline": timeline,
        "by_source": dict(Counter(r.source for r in rows)),
        "by_label": dict(Counter(r.label or "unlabeled" for r in rows)),
        "top_ips": top_ips,
        "top_failed_login_ips": top_failed,
        "hosts": [{"host": h, "events": n} for h, n in host_counts.most_common()],
    }
