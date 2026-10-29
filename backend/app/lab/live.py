"""Live traffic generator: a background thread that feeds the SOC continuously.

Every few seconds it sends a batch of normal activity (and, if enabled, a random
attack now and then) through the same ingest pipeline as everything else. With
WebSockets, you watch the dashboard react in real time.

It lives inside the API process, so restarting the backend stops it.
"""
import logging
import random
import threading
import time
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError
from sqlalchemy import select

from ..database import SessionLocal
from ..ml.dataset import load_simulator
from ..models import Containment
from ..realtime import hub
from ..schemas import EventIn
from ..utils import utcnow
from .scenarios import CATALOG, shift_to_end_at

log = logging.getLogger("uvicorn.error")
TICK_SECONDS = 5


class LiveTraffic:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.settings = {"rate_per_min": 20, "attacks": False, "attack_every_s": 45}
        self.stats = self._fresh_stats()

    @staticmethod
    def _fresh_stats() -> dict:
        return {"started_at": None, "ticks": 0, "events_sent": 0, "events_dropped": 0,
                "alerts_created": 0, "alerts_updated": 0, "incidents_created": 0, "attacks_launched": [], "last_error": None}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict:
        public = {k: v for k, v in self.stats.items() if not k.startswith("_")}
        return {"running": self.running, "tick_seconds": TICK_SECONDS, **self.settings, **public,
                "attacks_launched": self.stats["attacks_launched"][-10:]}

    def start(self, rate_per_min: int, attacks: bool, attack_every_s: int) -> dict:
        with self._lock:
            self.settings.update(rate_per_min=rate_per_min, attacks=attacks, attack_every_s=attack_every_s)
            if not self.running:
                self._stop.clear()
                self.stats = self._fresh_stats()
                self.stats["started_at"] = utcnow().isoformat()
                self._thread = threading.Thread(target=self._run, name="live-traffic", daemon=True)
                self._thread.start()
        self._announce()
        return self.status()

    def stop(self) -> dict:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=TICK_SECONDS + 5)
        self._announce()
        return self.status()

    def _announce(self) -> None:
        hub.publish({"type": "lab", "live": self.status()})

    def tick(self) -> None:
        """One batch. Public so tests can run a tick without waiting for the thread."""
        from ..routers.ingest import ingest_events     # noqa: PLC0415  (avoid an import cycle)

        sim = load_simulator(reload=False)
        now = datetime.now(timezone.utc)
        # A minute of traffic at the chosen rate, keeping only the last few seconds of it.
        since = now - timedelta(seconds=TICK_SECONDS)
        events = [e for e in sim.normal_events(now - timedelta(minutes=1), 1, self.settings["rate_per_min"])
                  if since < datetime.fromisoformat(e["timestamp"]) <= now]

        last_attack = self.stats.get("_last_attack_at", 0)
        if self.settings["attacks"] and time.monotonic() - last_attack >= self.settings["attack_every_s"]:
            name = self._pick_attack(sim)
            events += shift_to_end_at(sim.ATTACK_FUNCS[name](now), now)
            self.stats["_last_attack_at"] = time.monotonic()
            self.stats["attacks_launched"].append({"scenario": name, "at": now.isoformat()})

        try:
            batch = [EventIn(**e) for e in sorted(events, key=lambda e: e["timestamp"])]
        except ValidationError as e:                   # should never happen with our own simulator
            self.stats["last_error"] = str(e)[:300]
            return
        with SessionLocal() as db:
            r = ingest_events(db, batch, source="live")
        self.stats["ticks"] += 1
        self.stats["events_sent"] += r.received
        self.stats["events_dropped"] += r.dropped_blocked
        self.stats["alerts_created"] += r.alerts_created
        self.stats["alerts_updated"] += r.alerts_updated
        self.stats["incidents_created"] += r.incidents_created

    @staticmethod
    def _pick_attack(sim) -> str:
        """Random scenario, preferring attackers the firewall isn't already blocking
        (a blocked attacker's events are just dropped, which makes for a dull demo)."""
        with SessionLocal() as db:
            blocked = set(db.scalars(select(Containment.target).where(
                Containment.kind == "ip", Containment.active.is_(True))).all())
        ids = [c["id"] for c in CATALOG]
        fresh = [i for i in ids if sim.ATTACKERS.get(i) not in blocked]
        return random.choice(fresh or ids)

    def _run(self) -> None:
        log.info("Live traffic generator started")
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.tick()
                self.stats["last_error"] = None
            except Exception as e:                     # noqa: BLE001  (keep generating; show the error in the UI)
                log.exception("Live traffic tick failed")
                self.stats["last_error"] = str(e)[:300]
            self._announce()
            self._stop.wait(max(0.5, TICK_SECONDS - (time.monotonic() - started)))
        log.info("Live traffic generator stopped")


live = LiveTraffic()
