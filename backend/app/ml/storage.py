"""Where trained models live on disk, and loading them (cached until the file changes)."""
import json
import os
import threading
from pathlib import Path

import joblib

BUNDLE_FILE = "soc_models.joblib"
METRICS_FILE = "metrics.json"

_lock = threading.Lock()
_cache = {"mtime": None, "bundle": None}


def model_dir() -> Path:
    # Docker: /code/models (mounted to backend/models on your machine, so models survive restarts).
    d = Path(os.getenv("MODEL_DIR", Path(__file__).resolve().parents[2] / "models"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_bundle(bundle: dict, metrics: dict) -> None:
    d = model_dir()
    tmp = d / (BUNDLE_FILE + ".tmp")
    joblib.dump(bundle, tmp)
    tmp.replace(d / BUNDLE_FILE)            # atomic swap: detection never reads a half-written file
    (d / METRICS_FILE).write_text(json.dumps(metrics, indent=2))


def load_bundle() -> dict | None:
    path = model_dir() / BUNDLE_FILE
    if not path.exists():
        return None
    mtime = path.stat().st_mtime
    with _lock:
        if _cache["mtime"] != mtime:
            _cache["bundle"] = joblib.load(path)
            _cache["mtime"] = mtime
        return _cache["bundle"]


def load_metrics() -> dict | None:
    path = model_dir() / METRICS_FILE
    return json.loads(path.read_text()) if path.exists() else None
