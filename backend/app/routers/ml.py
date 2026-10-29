"""ML Models API: training status, evaluation metrics, retraining."""
import logging
import os
import threading
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import SessionLocal, get_db
from ..detection.engine import OPEN_STATUSES
from ..ml.storage import load_bundle, load_metrics
from ..models import Alert, DetectionRule
from ..response.audit import audit
from ..utils import is_external

router = APIRouter(prefix="/api/ml", tags=["ml"])
log = logging.getLogger("uvicorn.error")

_state = {"training": False, "error": None}
_train_lock = threading.Lock()


def _run_training(scenarios: int = 40, include_db: bool = True) -> dict:
    from ..ml.train import train            # noqa: PLC0415  (scikit-learn loads only when needed)
    if not _train_lock.acquire(blocking=False):
        raise RuntimeError("Training is already running")
    _state.update(training=True, error=None)
    try:
        with SessionLocal() as db:
            metrics = train(n_scenarios=scenarios, include_db=include_db, db=db)
            audit(db, category="config", action="ml_retrained", target="ML-001", actor="system",
                  result=f"Models retrained: ML recall {metrics['ml_detector']['recall']:.0%}, "
                         f"precision {metrics['ml_detector']['precision']:.0%}, "
                         f"{metrics['dataset']['train_windows']} training windows")
            db.commit()
            return metrics
    except Exception as e:                  # noqa: BLE001  (show the error on the ML page)
        _state["error"] = str(e)
        raise
    finally:
        _state["training"] = False
        _train_lock.release()


def autotrain_if_needed() -> None:
    """On first start there's no model yet: train one in the background (takes ~10-30s)."""
    if os.getenv("SOC_AUTOTRAIN", "1") == "0" or load_bundle() is not None:
        return

    def job():
        log.info("No ML model found - training one now (first start only)...")
        try:
            _run_training()
        except Exception:                   # noqa: BLE001
            log.exception("Automatic ML training failed")

    threading.Thread(target=job, daemon=True).start()


@router.get("/status")
def status(db: Session = Depends(get_db)):
    metrics = load_metrics()
    rule = db.get(DetectionRule, "ML-001")

    # Live comparison: which ML detections did rules ALSO catch, and vice versa?
    # The two can name the same attack differently: for exfiltration, ML flags the internal
    # source 10.0.0.5 while rules name the host db-01 and the destination 192.0.2.77.
    # So an ML alert on an INTERNAL entity is linked to rule alerts on the same host.
    open_alerts = db.scalars(select(Alert).where(Alert.status.in_(OPEN_STATUSES))).all()
    ml_alerts = [a for a in open_alerts if a.detector == "ml"]
    rule_alerts = [a for a in open_alerts if a.detector != "ml"]

    def linked(m, r):
        return r.entity == m.entity or (not is_external(m.entity) and m.host and m.host in (r.host, r.entity))

    def group(alerts, other):
        out = defaultdict(lambda: {"ml": 0, "rule": 0, "linked": False})
        for a in alerts:
            g = out[a.entity]
            g["ml" if a.detector == "ml" else "rule"] += 1
            g["linked"] |= any(linked(a, o) if a.detector == "ml" else linked(o, a) for o in other)
        return [{"entity": k, **v} for k, v in out.items()]

    ml_groups, rule_groups = group(ml_alerts, rule_alerts), group(rule_alerts, ml_alerts)
    live = {
        "ml_alerts": len(ml_alerts),
        "rule_alerts": len(rule_alerts),
        "only_ml": [g for g in ml_groups if not g["linked"]],
        "both": [g for g in ml_groups if g["linked"]],
        "only_rules": [g for g in rule_groups if not g["linked"]],
    }

    return {
        "trained": metrics is not None,
        "training": _state["training"],
        "error": _state["error"],
        "enabled": bool(rule and rule.enabled),
        "params": rule.params if rule else {},
        "metrics": metrics,
        "live": live,
    }


@router.post("/train")
def retrain(scenarios: int = Query(default=40, ge=8, le=200), include_db: bool = True):
    """Retrain both models. Runs in FastAPI's thread pool, so the API stays responsive."""
    try:
        return _run_training(scenarios, include_db)
    except RuntimeError as e:
        raise HTTPException(409, str(e))
