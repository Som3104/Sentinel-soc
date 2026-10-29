"""Correlation: grouping related alerts into incidents, and scoring each incident.

One attack fires many detections. A brute force alone produces 3 rule alerts +
1 ML alert. Analysts shouldn't triage 4 tickets for one attacker, so we group
alerts that belong to the same story.

Two alerts are linked when ANY of these is true (and they're <= 60 min apart):

  1. Same entity        - both about 203.0.113.45, or both about web-01.
  2. Same machine       - both describe activity ON the same host of ours
                          (e.g. xmrig started on web-01 + web-01's high CPU).
  3. Compromise pivot   - an attacker LOGGED IN to a host (SOC-002), and suspicious
                          activity started on that host shortly after. That joins
                          "who got in" with "what they did next", the attack chain.

Links are transitive (A~B and B~C puts A, B, C in one incident), which we
compute with union-find, a classic algorithm for grouping connected items.

Alerts about an outside attacker's IP ("actor" scope) are never merged just
because they hit the same host: two different scanners hitting web-01 are two
different incidents.
"""
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import false, or_, select, update
from sqlalchemy.orm import Session

from ..assets import CRITICALITY_POINTS, asset
from ..models import Alert, Containment, Incident, ResponseAction
from ..utils import aware, is_external, utcnow
from .rules import RULES_BY_ID

ACTIVE = ("open", "investigating", "contained")
CLOSED = ("resolved", "false_positive")
OPEN_ALERT = ("new", "investigating")
LINK_GAP = timedelta(minutes=60)
CLOCK_SKEW = timedelta(minutes=1)
COMPROMISE_RULES = {"SOC-002"}                  # proof an attacker got in
FOOTHOLD_RULES = {"SOC-002", "SOC-007"}         # confirmed access: account takeover or web shell

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]
# How each ATT&CK tactic reads in an incident title.
TACTIC_PHRASE = {
    "Discovery": "Recon scan", "Credential Access": "Password attack", "Initial Access": "Account compromise",
    "Execution": "Malicious execution", "Persistence": "Web shell", "Defense Evasion": "Hidden malware",
    "Command and Control": "C2 traffic", "Exfiltration": "Data exfiltration", "Impact": "Crypto-mining",
}
BANDS = [(85, "critical"), (65, "high"), (40, "medium"), (0, "low")]
BASE_WEIGHT = 0.7


# --------------------------------------------------------------------------- helpers
def scope_of(a: Alert) -> str:
    if a.detector == "ml":
        return "actor" if is_external(a.entity) else "asset"
    rdef = RULES_BY_ID.get(a.rule_id)
    return rdef.scope if rdef else "asset"


def _close_in_time(a: Alert, b: Alert) -> bool:
    a0, a1 = aware(a.first_seen or a.created_at), aware(a.last_seen or a.created_at)
    b0, b1 = aware(b.first_seen or b.created_at), aware(b.last_seen or b.created_at)
    gap = max(a0, b0) - min(a1, b1)            # negative when the two time ranges overlap
    return gap <= LINK_GAP


def _compromise_link(c: Alert, a: Alert) -> bool:
    """c = a successful login after brute force; a = activity on the same host shortly after."""
    if c.rule_id not in COMPROMISE_RULES or scope_of(a) != "asset" or a.host != c.host:
        return False
    t = aware(c.last_seen)
    start = aware(a.first_seen)
    # Activity must START AFTER the attacker got in (1 min slack for clock differences between
    # machines). A miner running 4 minutes before the login can't be the attacker's doing.
    return t - CLOCK_SKEW <= start <= t + LINK_GAP


def linked(a: Alert, b: Alert) -> bool:
    if not _close_in_time(a, b):
        return False
    if a.entity == b.entity:
        return True
    if scope_of(a) == "asset" and scope_of(b) == "asset" and a.host and a.host == b.host:
        return True
    return _compromise_link(a, b) or _compromise_link(b, a)


class UnionFind:
    def __init__(self, items):
        self.parent = {i: i for i in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]     # path compression
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


# --------------------------------------------------------------------------- scoring
def band(score: float) -> str:
    return next(name for limit, name in BANDS if score >= limit)


def score_incident(alerts: list[Alert], tactics: list[str], hosts: list[str], repeat: bool) -> tuple[float, list]:
    """Risk score 0-100 with a breakdown, so every number on the dashboard is explainable."""
    counted = [a for a in alerts if a.status != "false_positive"] or alerts
    top = max(counted, key=lambda a: a.score or 0)
    # The worst alert sets the base (70% of its score); the remaining factors decide how much
    # worse the whole incident is than that one alert. Without the weighting, every incident with
    # a critical alert would sit at 100 and the score would stop helping analysts prioritise.
    parts = [{"factor": "Most severe alert", "points": round(BASE_WEIGHT * (top.score or 0)),
              "detail": f"{top.title} (alert score {round(top.score or 0)} x {BASE_WEIGHT})"}]

    if len(tactics) > 1:
        parts.append({"factor": "Attack stages", "points": min(15, 5 * (len(tactics) - 1)),
                      "detail": f"{len(tactics)} ATT&CK tactics: the attack progressed"})
    if {a.detector for a in counted} >= {"rule", "ml"}:
        parts.append({"factor": "Rules and ML agree", "points": 5, "detail": "two independent detectors"})
    foothold = sorted({a.title for a in counted if a.rule_id in FOOTHOLD_RULES})
    if foothold:
        # +15: an attacker who is IN is the most decisive fact in an incident. At +10 a rules-only
        # account takeover scored 84 ("high"), so the auto-block playbook for critical didn't fire.
        parts.append({"factor": "Confirmed access", "points": 15, "detail": ", ".join(foothold)})
    crit = max(hosts, key=lambda h: CRITICALITY_POINTS[asset(h)["criticality"]], default=None)
    if crit and CRITICALITY_POINTS[asset(crit)["criticality"]]:
        a = asset(crit)
        parts.append({"factor": "Asset value", "points": CRITICALITY_POINTS[a["criticality"]],
                      "detail": f"{crit}: {a['role']} ({a['criticality']})"})
    if repeat:
        parts.append({"factor": "Repeat offender", "points": 5, "detail": "this attacker had an earlier incident"})

    return float(min(100, sum(p["points"] for p in parts))), parts


# --------------------------------------------------------------------------- building incidents
def _title(alerts: list[Alert], tactics_by_time: list[str], actors: list[str], hosts: list[str]) -> str:
    phrases = []
    for t in tactics_by_time:
        p = TACTIC_PHRASE.get(t)
        if p and p not in phrases:
            phrases.append(p)
    if not phrases:
        phrases = [alerts[0].title.removeprefix("ML: ")]
    where = " → ".join(filter(None, [", ".join(actors[:2]), ", ".join(hosts[:2])])) or alerts[0].entity
    more = f" (+{len(phrases) - 3} more)" if len(phrases) > 3 else ""
    return f"{' → '.join(phrases[:3])}{more} · {where}"[:200]


def _refresh(db: Session, inc: Incident, alerts: list[Alert]) -> None:
    alerts = sorted(alerts, key=lambda a: aware(a.first_seen or a.created_at))
    first = min(aware(a.first_seen or a.created_at) for a in alerts)
    last = max(aware(a.last_seen or a.created_at) for a in alerts)

    actors = sorted({a.entity for a in alerts if scope_of(a) == "actor"}
                    | {a.entity for a in alerts if is_external(a.entity)})
    hosts = sorted({a.host for a in alerts if a.host})
    tactics_seen = {a.mitre_tactic for a in alerts if a.mitre_tactic}
    tactics = [t for t in TACTIC_ORDER if t in tactics_seen]
    by_time = []
    for a in alerts:
        if a.mitre_tactic and a.mitre_tactic not in by_time:
            by_time.append(a.mitre_tactic)

    repeat = bool(actors) and db.scalar(
        select(Incident.id).where(Incident.id != inc.id, Incident.status == "resolved", Incident.entity.in_(actors)).limit(1)
    ) is not None
    score, breakdown = score_incident(alerts, tactics, hosts, repeat)

    inc.title = _title(alerts, by_time, actors, hosts)
    inc.entity = (actors or hosts or [alerts[0].entity])[0]
    inc.first_seen, inc.last_seen = first, last
    inc.alert_count = len(alerts)
    inc.event_count = sum(a.event_count or 0 for a in alerts)
    inc.actors, inc.hosts, inc.tactics = actors, hosts, tactics
    inc.detectors = sorted({a.detector for a in alerts})
    inc.score, inc.severity, inc.score_breakdown = score, band(score), breakdown
    mins = max(1, round((last - first).total_seconds() / 60))
    inc.summary = (f"{len(alerts)} alerts over {mins} min across {len(tactics)} ATT&CK "
                   f"tactic{'s' if len(tactics) != 1 else ''}"
                   + (f", from {', '.join(actors)}" if actors else "")
                   + (f", affecting {', '.join(hosts)}" if hosts else "") + ".")
    inc.updated_at = utcnow()


def correlate(db: Session) -> dict:
    """Group alerts into incidents. Safe to run any time: it only adds and merges, never splits."""
    active_ids = set(db.scalars(select(Incident.id).where(Incident.status.in_(ACTIVE))).all())
    alerts = db.scalars(select(Alert).where(or_(
        (Alert.incident_id.is_(None)) & (Alert.status.in_(OPEN_ALERT)),
        Alert.incident_id.in_(active_ids) if active_ids else false(),
    ))).all()
    if not alerts:
        return {"incidents_created": 0, "incidents_updated": 0}

    uf = UnionFind([a.id for a in alerts])
    by_incident = defaultdict(list)
    for a in alerts:
        if a.incident_id:
            by_incident[a.incident_id].append(a.id)
    for ids in by_incident.values():          # once correlated, always correlated
        for i in ids[1:]:
            uf.union(ids[0], i)
    for i, a in enumerate(alerts):            # O(n^2) is fine for a lab's few hundred open alerts
        for b in alerts[i + 1:]:
            if linked(a, b):
                uf.union(a.id, b.id)

    groups = defaultdict(list)
    for a in alerts:
        groups[uf.find(a.id)].append(a)

    created = updated = 0
    for members in groups.values():
        existing = sorted({a.incident_id for a in members if a.incident_id})
        if existing:
            inc = db.get(Incident, existing[0])
            before = (inc.alert_count, inc.score)
        else:
            inc = Incident(status="open", severity="low", score=0, title="", entity=members[0].entity,
                           created_at=utcnow(), notes=[])
            db.add(inc)
            db.flush()
            before = None
        for a in members:
            a.incident_id = inc.id
        db.flush()                            # move alerts BEFORE deleting any merged incident (foreign key)
        for other_id in existing[1:]:         # two incidents turned out to be one attack: merge them
            notes = list(inc.notes or [])
            notes.append({"at": utcnow().isoformat(), "author": "system", "system": True,
                          "text": f"Merged INC-{other_id} into this incident (shared attacker or host)"})
            inc.notes = notes
            # Move the merged incident's response history and containments over BEFORE deleting it.
            db.execute(update(ResponseAction).where(ResponseAction.incident_id == other_id).values(incident_id=inc.id))
            db.execute(update(Containment).where(Containment.incident_id == other_id).values(incident_id=inc.id))
            db.delete(db.get(Incident, other_id))
        _refresh(db, inc, members)
        if before is None:
            created += 1
        elif before != (inc.alert_count, inc.score):
            updated += 1
    db.commit()
    return {"incidents_created": created, "incidents_updated": updated}


def set_incident_status(db: Session, inc: Incident, status: str, author: str = "analyst") -> None:
    """Closing an incident closes its alerts too (one decision, not ten clicks)."""
    if status == inc.status:
        return
    notes = list(inc.notes or [])
    notes.append({"at": utcnow().isoformat(), "author": author, "system": True,
                  "text": f"Status changed: {inc.status} → {status}"})
    inc.notes = notes
    inc.status = status
    inc.closed_at = utcnow() if status in CLOSED else None
    if status in CLOSED:
        alert_status = "false_positive" if status == "false_positive" else "resolved"
        for a in db.scalars(select(Alert).where(Alert.incident_id == inc.id, Alert.status.in_(OPEN_ALERT))).all():
            a.status = alert_status
            a.updated_at = utcnow()
    inc.updated_at = utcnow()


def kill_chain(alerts: list[Alert]) -> list[dict]:
    """For each ATT&CK tactic: did this incident reach it, and when first?"""
    first = {}
    for a in alerts:
        t = a.mitre_tactic
        if t and (t not in first or aware(a.first_seen) < first[t]["at"]):
            first[t] = {"at": aware(a.first_seen), "alert_id": a.id}
    return [{"tactic": t, "reached": t in first, "first_seen": first[t]["at"].isoformat() if t in first else None,
             "alert_id": first[t]["alert_id"] if t in first else None,
             "alerts": sum(1 for a in alerts if a.mitre_tactic == t)} for t in TACTIC_ORDER]

