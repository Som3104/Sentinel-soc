"""The audit log: one helper so every part of the app records actions the same way.

In a real SOC the audit trail answers "who did what, when, and why" - for
compliance, for post-incident reviews, and to catch automation misbehaving.
"""
from sqlalchemy.orm import Session

from ..auth.deps import current_username
from ..models import ResponseAction
from ..utils import utcnow


def audit(db: Session, *, category: str, action: str, target: str, actor: str, result: str,
          status: str = "success", incident_id: int | None = None, alert_id: int | None = None,
          playbook_id: str | None = None, details: dict | None = None,
          username: str | None = None) -> ResponseAction:
    """category: response | case | config | system | access      actor: auto | analyst | system
    username: who did it. For analyst actions it's taken from the signed-in user automatically."""
    if username is None and actor == "analyst":
        username = current_username.get()
    row = ResponseAction(
        category=category, action=action, target=str(target)[:200], triggered_by=actor, result=result,
        status=status, incident_id=incident_id, alert_id=alert_id, playbook_id=playbook_id,
        details=details or {}, created_at=utcnow(), username=username,
    )
    db.add(row)
    return row
