"""Database tables.

`Event` is the heart of the system: every log line (auth, process, network)
is normalized into this ONE schema. A common schema is what real SIEMs do
(e.g. Elastic Common Schema) - it lets one detection rule work across sources.

Alert / Incident / ResponseAction are created now but filled in on Days 3-5.
"""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    host: Mapped[str] = mapped_column(String(100), index=True)
    source: Mapped[str] = mapped_column(String(20), index=True)       # auth | process | network
    event_type: Mapped[str] = mapped_column(String(40), index=True)   # login_failed, process_start, ...

    # Auth fields
    user: Mapped[str | None] = mapped_column(String(100), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)

    # Network fields
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_sent: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Process fields
    process_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    process_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    parent_process: Mapped[str | None] = mapped_column(String(200), nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Ground-truth label from the simulator (normal / brute_force / ...).
    # Real logs don't have this - we use it on Day 4 to TRAIN and EVALUATE the ML model.
    label: Mapped[str | None] = mapped_column(String(40), nullable=True)

    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    """A group of related alerts = one attack story. Built by detection/correlation.py."""
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    # open | investigating | contained | resolved | false_positive
    status: Mapped[str] = mapped_column(String(20), default="open")
    severity: Mapped[str] = mapped_column(String(10))
    score: Mapped[float] = mapped_column(Float, default=0)
    entity: Mapped[str] = mapped_column(String(100), index=True)      # main attacker IP, or the host
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Added in Phase 5 (nullable so migrate.py can add them to an existing table)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    alert_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actors: Mapped[list | None] = mapped_column(JSON, nullable=True)           # external attacker IPs
    hosts: Mapped[list | None] = mapped_column(JSON, nullable=True)            # our machines involved
    tactics: Mapped[list | None] = mapped_column(JSON, nullable=True)          # ATT&CK tactics, kill-chain order
    detectors: Mapped[list | None] = mapped_column(JSON, nullable=True)        # rule / ml
    score_breakdown: Mapped[list | None] = mapped_column(JSON, nullable=True)  # why this score
    notes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Alert(Base):
    """One detection. Repeated hits of the same rule on the same entity are MERGED
    into one alert (see detection/engine.py) instead of flooding the analyst."""
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    rule_id: Mapped[str] = mapped_column(String(50))                  # e.g. SOC-001 or ML-IFOREST
    title: Mapped[str] = mapped_column(String(200))
    detector: Mapped[str] = mapped_column(String(10))                 # rule | ml
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity: Mapped[str] = mapped_column(String(10))                 # low | medium | high | critical
    score: Mapped[float] = mapped_column(Float)                       # 0-100
    entity: Mapped[str] = mapped_column(String(100), index=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)

    # Added in Phase 3 (nullable so migrate.py can add them to an existing table)
    status: Mapped[str | None] = mapped_column(String(20), server_default="new", default="new", index=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    host: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(40), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    event_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String(300), nullable=True, index=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DetectionRule(Base):
    """Rule SETTINGS that analysts can change from the UI (on/off, severity, thresholds).
    The detection LOGIC lives in code: detection/rules.py."""
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)     # SOC-001
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(20))                   # auth | process | network
    mitre_tactic: Mapped[str] = mapped_column(String(40))
    mitre_technique: Mapped[str] = mapped_column(String(20))
    mitre_technique_name: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(10))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Containment(Base):
    """Something we've contained in the SIMULATED lab. Nothing touches your real network or PC.

    kind = "ip"      -> simulated firewall drops all traffic to/from that IP
           "process" -> simulated EDR blocks that binary from running on that host again
           "host"    -> simulated EDR cuts that host off the network
    The ingest endpoint applies active containments to every incoming log (routers/ingest.py).
    (Replaces Phase 1's blocked_ips table, which stays in old databases but is no longer used.)
    """
    __tablename__ = "containments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(10), index=True)          # ip | process | host
    target: Mapped[str] = mapped_column(String(600), index=True)       # 203.0.113.45 | web-01:/tmp/x | db-01
    host: Mapped[str | None] = mapped_column(String(100), nullable=True)
    process_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    reason: Mapped[str] = mapped_column(Text)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    playbook_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_by: Mapped[str] = mapped_column(String(20))                # auto | analyst
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_by: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dropped_count: Mapped[int] = mapped_column(Integer, default=0)     # events stopped by this containment
    last_dropped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Playbook(Base):
    """Playbook SETTINGS analysts can change (on/off, auto vs approval). Logic: response/playbooks.py."""
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)      # PB-01
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mode: Mapped[str] = mapped_column(String(10))                      # auto | approval
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ResponseAction(Base):
    """The AUDIT LOG: every action by the system or an analyst - containment, triage, config changes.
    Rows are only ever added (and pending approvals updated once). Never deleted."""
    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(40))                   # block_ip | incident_status | rule_updated ...
    target: Mapped[str] = mapped_column(String(600))
    triggered_by: Mapped[str] = mapped_column(String(20))             # auto | analyst | system
    result: Mapped[str] = mapped_column(Text)                         # human-readable outcome
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    # Added in Phase 6
    category: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)  # response | case | config | system
    status: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)    # success | failed | blocked_by_guardrail | pending_approval | rejected | skipped
    alert_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    playbook_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Added in Phase 8: WHICH analyst (triggered_by says auto | analyst | system).
    username: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)


class User(Base):
    """An analyst account (Phase 8). Passwords are stored only as PBKDF2 hashes (auth/security.py)."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20))                     # viewer | analyst | admin
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Brute-force protection: 5 wrong passwords in a row lock the account for 5 minutes.
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
