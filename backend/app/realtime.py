"""Real-time push to the dashboard over WebSockets.

Before Phase 7, every page asked the API "anything new?" every few seconds (polling).
Now the backend TELLS the browser the moment something changes:

    browser  --- opens ws://localhost:8000/ws --->  backend
    backend  --- {"type": "update", "feed": [...]} --->  every open tab, instantly

Messages are small notifications ("events arrived, 2 new alerts, INC-4 created"),
not the data itself. Each page then re-fetches what it shows. That keeps one source
of truth (the REST API) and a tiny, simple protocol.

Most of our endpoints are plain `def` functions that FastAPI runs in worker threads,
while WebSockets live on the asyncio event loop. `publish()` is the bridge: it's safe
to call from any thread and hands the message over to the loop.
"""
import asyncio
import json
import logging
import threading

from fastapi import WebSocket

from .utils import utcnow

log = logging.getLogger("uvicorn.error")


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.loop = asyncio.get_running_loop()
        with self._lock:
            self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        with self._lock:
            self.clients.discard(ws)

    async def _send_all(self, text: str) -> None:
        with self._lock:
            clients = list(self.clients)
        for ws in clients:
            try:
                await ws.send_text(text)
            except Exception:              # noqa: BLE001  (closed tab: just forget it)
                self.disconnect(ws)

    def publish(self, message: dict) -> None:
        """Send to every connected dashboard. Safe to call from any thread; never blocks or raises."""
        if self.loop is None or not self.clients:
            return
        message.setdefault("at", utcnow().isoformat())
        text = json.dumps(message, default=str)
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        try:
            if running is self.loop:
                self.loop.create_task(self._send_all(text))
            else:
                asyncio.run_coroutine_threadsafe(self._send_all(text), self.loop)
        except RuntimeError:               # loop closed (server shutting down)
            pass


hub = Hub()
