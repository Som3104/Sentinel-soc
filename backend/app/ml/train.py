"""Train and evaluate the two models.

    python -m app.ml.train            (or the Retrain button on the ML Models page)

1. ISOLATION FOREST (unsupervised anomaly detection)
   Trained on NORMAL windows only. It learns what normal looks like and gives
   every new window an anomaly score: how easy it is to "isolate" that point
   from the rest. Weird points get isolated fast -> high score.
   It needs no attack labels, so it can flag attacks we've never seen.

2. RANDOM FOREST (supervised classification)
   Trained on labeled windows (normal / brute_force / port_scan / ...).
   It can't find brand-new attack types, but when something IS suspicious it
   names the most likely attack, which tells the analyst where to start.

Evaluation is done on held-out scenarios the models never saw during training.
We also run the 11 detection rules on the same held-out data, so we can
compare rules vs ML per attack type.
"""
import json
import logging
import time
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from ..utils import utcnow
from .dataset import generate_scenarios
from .features import (EVENT_FIELDS, FEATURE_NAMES, FEATURES, IF_FEATURES, Vocab, feature_matrix, if_transform,
                       make_windows, parse_ts)
from .storage import save_bundle

log = logging.getLogger("uvicorn.error")

FALSE_ALARM_BUDGET = 0.0002    # at most 0.02% of normal windows (1 in 5,000) above the anomaly threshold
RF_CONFIDENCE = 0.9            # Random Forest alone raises an alert only when this sure
IF_CONTAMINATION = 0.005       # share of attack windows the Isolation Forest is trained with


def _binary_metrics(y_true, y_pred) -> dict:
    tp = int(np.sum(y_true & y_pred))
    fp = int(np.sum(~y_true & y_pred))
    fn = int(np.sum(y_true & ~y_pred))
    tn = int(np.sum(~y_true & ~y_pred))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _rule_flags(scenario: list[dict]) -> set[int]:
    """Run the 11 rules on one scenario in a throwaway in-memory database.
    Returns the indexes of events that some rule flagged."""
    from ..database import Base                     # noqa: PLC0415  (avoid import cycles)
    from ..detection.rules import RULES             # noqa: PLC0415
    from ..models import Event                      # noqa: PLC0415

    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    flagged_ids = set()
    with Session(engine) as db:
        rows = []
        for e in scenario:
            data = {k: e.get(k) for k in EVENT_FIELDS if k != "id"}
            data["timestamp"] = parse_ts(data["timestamp"])
            rows.append(Event(**data))
        db.add_all(rows)
        db.flush()
        id_to_idx = {r.id: i for i, r in enumerate(rows)}
        times = [r.timestamp for r in rows]
        start, end = min(times) - timedelta(hours=1), max(times) + timedelta(hours=1)
        for rd in RULES:
            if rd.source == "ml":
                continue
            for m in rd.fn(db, rd.params, start, end):
                flagged_ids.update(e.id for e in m.events)
    engine.dispose()
    return {id_to_idx[i] for i in flagged_ids}


def train(n_scenarios: int = 40, seed: int = 42, include_db: bool = True, db: Session | None = None) -> dict:
    t0 = time.perf_counter()

    # ---------------------------------------------------------------- 1. data
    scenarios = generate_scenarios(n_scenarios, seed)
    db_events = []
    if include_db and db is not None:
        from ..models import Event                  # noqa: PLC0415
        since = utcnow() - timedelta(days=7)
        db_events = [e for e in db.scalars(select(Event).where(Event.timestamp >= since, Event.label.is_not(None))).all()]

    # Split by SCENARIO, not by window: windows from one scenario are correlated,
    # so mixing them across train/test would leak information and inflate scores.
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(scenarios))
    n_test = max(2, len(scenarios) // 4)
    test_sc = [scenarios[i] for i in order[:n_test]]
    train_sc = [scenarios[i] for i in order[n_test:]]

    train_events = [e for sc in train_sc for e in sc]
    vocab = Vocab.from_events(train_events + [e for e in db_events])

    train_windows = [w for sc in train_sc for w in make_windows(sc)] + make_windows(db_events)
    X_train = feature_matrix(train_windows, vocab)
    y_train = np.array([w.label for w in train_windows])

    # Test windows, plus which ones the rules caught (for the rules-vs-ML comparison).
    test_windows, test_rule_hit = [], []
    for sc in test_sc:
        flagged = _rule_flags(sc)
        for i, e in enumerate(sc):
            e["_idx"] = i
        for w in make_windows(sc):
            test_windows.append(w)
            test_rule_hit.append(any(e["_idx"] in flagged for e in w.events))
    X_test = feature_matrix(test_windows, vocab)
    y_test = np.array([w.label for w in test_windows])
    rule_hit = np.array(test_rule_hit)

    # ---------------------------------------------------------------- 2. Isolation Forest
    # Fit on ALL training windows WITHOUT labels - the true unsupervised setting.
    # Attacks are rare (~3% of windows), so they're easy to isolate. (Fitting on normal-only
    # data fails here: features like unseen_processes are always 0 in normal traffic, and an
    # Isolation Forest can only split on features that vary in its training data.)
    # Isolation Forest also ASSUMES anomalies are rare. Our training scenarios are attack-heavy
    # (so the Random Forest gets enough examples), which would let similar attacks cluster and
    # look "normal". So the forest sees a production-like mix: attacks ~0.5% of windows.
    normal_train = X_train[y_train == "normal"]
    attack_train = X_train[y_train != "normal"]
    n_attack = max(1, int(len(normal_train) * IF_CONTAMINATION))
    pick = rng.choice(len(attack_train), size=min(n_attack, len(attack_train)), replace=False)
    iforest = IsolationForest(n_estimators=300, max_samples=min(1024, len(normal_train)), random_state=seed)
    iforest.fit(if_transform(np.vstack([normal_train, attack_train[pick]])))
    train_scores = -iforest.score_samples(if_transform(normal_train))   # higher = more anomalous
    # Labels are used ONLY to pick the alert threshold: at most 0.02% of normal windows above it.
    threshold = float(np.quantile(train_scores, 1 - FALSE_ALARM_BUDGET))

    test_scores = -iforest.score_samples(if_transform(X_test))
    is_attack = y_test != "normal"
    if_flag = test_scores >= threshold

    # ---------------------------------------------------------------- 3. Random Forest
    rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, random_state=seed, n_jobs=-1)
    rf.fit(X_train, y_train)
    classes = list(rf.classes_)
    proba = rf.predict_proba(X_test)
    rf_pred = np.array(classes)[proba.argmax(axis=1)]
    normal_idx = classes.index("normal")
    rf_flag = (rf_pred != "normal") & (proba.max(axis=1) >= RF_CONFIDENCE)

    # The deployed ML detector: anomalous by Isolation Forest OR a confident Random Forest.
    ml_flag = if_flag | rf_flag

    # ---------------------------------------------------------------- 4. metrics
    p, r, f, s = precision_recall_fscore_support(y_test, rf_pred, labels=classes, zero_division=0)
    cm = confusion_matrix(y_test, rf_pred, labels=classes)

    by_variant = defaultdict(lambda: Counter())
    for w, rh, iff, rff, mlf in zip(test_windows, rule_hit, if_flag, rf_flag, ml_flag):
        if w.label == "normal":
            continue
        c = by_variant[w.variant]
        c["windows"] += 1
        c["rules"] += int(rh)
        c["iforest"] += int(iff)
        c["random_forest"] += int(rff)
        c["ml"] += int(mlf)
        c["combined"] += int(rh or mlf)

    # Score histogram (normal vs attack) for the chart on the ML page.
    hi = float(max(test_scores.max(), threshold) + 0.02)
    lo = float(min(test_scores.min(), train_scores.min()))
    edges = np.linspace(lo, hi, 31)
    hist_normal, _ = np.histogram(test_scores[~is_attack], bins=edges)
    hist_attack, _ = np.histogram(test_scores[is_attack], bins=edges)

    normal_stats = {
        "mean": normal_train.mean(axis=0).round(4).tolist(),
        "std": normal_train.std(axis=0).round(4).tolist(),
        "p99": np.quantile(normal_train, 0.99, axis=0).round(4).tolist(),
    }

    metrics = {
        "trained_at": utcnow().isoformat(),
        "duration_s": round(time.perf_counter() - t0, 1),
        "seed": seed,
        "features": [{"name": n, "description": d} for n, d in FEATURES],
        "dataset": {
            "scenarios_train": len(train_sc), "scenarios_test": len(test_sc),
            "db_events": len(db_events),
            "train_windows": int(len(train_windows)), "test_windows": int(len(test_windows)),
            "train_by_label": dict(Counter(y_train.tolist())), "test_by_label": dict(Counter(y_test.tolist())),
        },
        "isolation_forest": {
            **_binary_metrics(is_attack, if_flag),
            "features": IF_FEATURES,
            "contamination": IF_CONTAMINATION,
            "threshold": round(threshold, 4),
            "false_alarm_budget": FALSE_ALARM_BUDGET,
            "histogram": [{"score": round(float((edges[i] + edges[i + 1]) / 2), 3),
                           "normal": int(hist_normal[i]), "attack": int(hist_attack[i])} for i in range(len(edges) - 1)],
        },
        "random_forest": {
            "accuracy": round(float(np.mean(rf_pred == y_test)), 4),
            "macro_f1": round(float(np.mean(f)), 3),
            "classes": classes,
            "per_class": [{"label": c, "precision": round(float(p[i]), 3), "recall": round(float(r[i]), 3),
                           "f1": round(float(f[i]), 3), "support": int(s[i])} for i, c in enumerate(classes)],
            "confusion_matrix": cm.tolist(),
            "feature_importance": sorted(
                [{"feature": n, "importance": round(float(v), 4)} for n, v in zip(FEATURE_NAMES, rf.feature_importances_)],
                key=lambda d: d["importance"], reverse=True),
            "confidence_threshold": RF_CONFIDENCE,
        },
        "random_forest_detector": _binary_metrics(is_attack, rf_flag),
        "ml_detector": _binary_metrics(is_attack, ml_flag),
        "rules": _binary_metrics(is_attack, rule_hit),
        "combined": _binary_metrics(is_attack, rule_hit | ml_flag),
        "by_variant": {k: dict(v) for k, v in sorted(by_variant.items())},
    }

    save_bundle({
        "iforest": iforest, "rf": rf, "classes": classes, "normal_idx": normal_idx,
        "threshold": threshold, "rf_confidence": RF_CONFIDENCE, "vocab": vocab,
        "feature_names": FEATURE_NAMES, "normal_stats": normal_stats,
    }, metrics)
    log.info("ML models trained in %ss: IF recall %.2f, RF macro-F1 %.2f",
             metrics["duration_s"], metrics["isolation_forest"]["recall"], metrics["random_forest"]["macro_f1"])
    return metrics


if __name__ == "__main__":
    from ..database import SessionLocal               # noqa: PLC0415
    with SessionLocal() as session:
        m = train(db=session)
    print(json.dumps({k: m[k] for k in ("dataset", "ml_detector", "rules", "combined", "by_variant")}, indent=2))
