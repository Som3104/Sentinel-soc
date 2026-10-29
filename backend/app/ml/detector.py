"""Live ML detection: scores incoming activity with the trained models.

This is registered as rule ML-001 in detection/rules.py, so it runs inside the
same detection engine as the 11 rules: on every ingest batch and on re-scans,
with the same alert deduplication and triage workflow.

A window raises an ML alert when EITHER
  * the Isolation Forest finds it anomalous (score >= learned threshold), or
  * the Random Forest is very confident it's a known attack type.
"""
import numpy as np

from .features import FEATURE_NAMES, event_to_dict, feature_matrix, if_transform, make_windows
from .storage import load_bundle

# What the Random Forest's class names mean in ATT&CK terms.
CLASS_INFO = {
    "brute_force": ("Brute force", "Credential Access", "T1110"),
    "port_scan": ("Port scan", "Discovery", "T1046"),
    "suspicious_process": ("Suspicious process", "Execution", "T1059"),
    "exfiltration": ("Data exfiltration", "Exfiltration", "T1041"),
}


def _signals(x: np.ndarray, stats: dict, top: int = 4) -> list[dict]:
    """Explainability: which features are furthest from normal for this window?"""
    mean, std = np.array(stats["mean"]), np.array(stats["std"])
    z = (x - mean) / np.maximum(std, 0.05)
    order = np.argsort(-np.abs(z))
    return [
        {"feature": FEATURE_NAMES[i], "value": round(float(x[i]), 2), "normal": round(float(mean[i]), 2),
         "z": round(float(z[i]), 1)}
        for i in order[:top] if abs(z[i]) >= 2
    ]


def detect(db, p, start, end):
    from ..detection.rules import Match, fetch      # noqa: PLC0415  (avoid an import cycle)

    bundle = load_bundle()
    if bundle is None:
        return []                                   # not trained yet

    events = fetch(db, start, end)
    by_id = {e.id: e for e in events}
    windows = [w for w in make_windows(event_to_dict(e) for e in events) if len(w.events) >= p["min_events"]]
    if not windows:
        return []

    X = feature_matrix(windows, bundle["vocab"])
    anomaly = -bundle["iforest"].score_samples(if_transform(X))
    proba = bundle["rf"].predict_proba(X)
    classes = bundle["classes"]
    threshold = bundle["threshold"] * p["threshold_scale"]

    out = []
    for i, w in enumerate(windows):
        top = int(np.argmax(proba[i]))
        cls, conf = classes[top], float(proba[i][top])
        if_hit = anomaly[i] >= threshold
        rf_hit = cls != "normal" and conf >= p["rf_confidence"]
        if not (if_hit or rf_hit):
            continue

        # If the RF calls it "normal", name the most likely attack class instead (for context).
        attack_probs = {c: float(proba[i][j]) for j, c in enumerate(classes) if c != "normal"}
        guess = cls if cls != "normal" else max(attack_probs, key=attack_probs.get)
        guess_conf = conf if cls != "normal" else attack_probs[guess]
        name, tactic, technique = CLASS_INFO.get(guess, (guess, None, None))

        entity = w.entity.removeprefix("host:")
        confident = guess_conf >= 0.5
        if if_hit and rf_hit:
            why = f"anomalous AND classified as {name.lower()} ({guess_conf:.0%})"
        elif if_hit:
            why = (f"anomalous; closest known pattern is {name.lower()} ({guess_conf:.0%})" if confident
                   else "anomalous and doesn't match any known attack pattern")
        else:
            why = f"classified as {name.lower()} ({guess_conf:.0%})"

        # Score: how far past the threshold, plus a boost when both models agree.
        margin = float(np.clip((anomaly[i] - threshold) / 0.1, 0, 1)) if if_hit else 0.0
        score = 45 + 25 * margin + 20 * guess_conf * confident + (10 if if_hit and rf_hit else 0)
        if (if_hit and rf_hit) or (rf_hit and guess_conf >= 0.97):
            severity = "high"            # both models agree, or the classifier is near-certain
        elif if_hit and not rf_hit and margin < 0.5 and guess_conf < 0.6:
            # Grey zone: barely over the anomaly line and the classifier isn't sure either
            # (e.g. one user mistyping a password 3 times in a minute). Surface it, low priority.
            severity, score = "low", min(score, 39)
        else:
            severity = "medium"

        out.append(Match(
            entity=entity, host=w.host,
            events=[by_id[e["id"]] for e in w.events],
            summary=f"{entity}: one minute of activity is {why}",
            title=f"ML: {name if confident else 'Unusual activity'}" + ("" if confident else " (unclassified)"),
            technique=technique if confident else None,
            tactic=tactic if confident else None,
            severity=severity, score=round(min(100.0, score), 1),
            metrics={
                "anomaly_score": round(float(anomaly[i]), 3),
                "anomaly_threshold": round(float(threshold), 3),
                "isolation_forest": "anomalous" if if_hit else "normal",
                "random_forest": f"{cls} ({conf:.0%})",
                "class_probabilities": {c: round(float(proba[i][j]), 3) for j, c in enumerate(classes)},
                "signals": _signals(X[i], bundle["normal_stats"]),
                "window_start": w.start.isoformat(),
            },
        ))
    return out
