"""FastAPI entry point. Run: uvicorn app.main:app --reload"""
import logging

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from .auth.deps import authorize, user_from_token
from .database import Base, SessionLocal, engine
from .detection.correlation import correlate
from .detection.engine import seed_rules
from .migrate import add_missing_columns
from .realtime import hub
from .response.playbooks import seed_playbooks
from .routers import alerts, audit, auth, detection, events, incidents, ingest, lab, ml, response, stats

log = logging.getLogger("uvicorn.error")

# 1. Create any brand-new tables, 2. add new columns to existing ones, 3. load the rule library.
# (Fine for a lab project; production would use Alembic migrations.)
Base.metadata.create_all(bind=engine)
added = add_missing_columns(engine)
if added:
    log.info("Schema upgraded, added columns: %s", ", ".join(added))
with SessionLocal() as _db:
    seed_rules(_db)
    seed_playbooks(_db)
    if auth.seed_users(_db):
        log.info("Created demo accounts: admin / analyst / viewer (see README, Phase 8)")
    correlate(_db)          # group any existing alerts into incidents (e.g. after upgrading to Phase 5)
ml.autotrain_if_needed()

app = FastAPI(
    title="Mini SOC API",
    description="Log ingestion, threat detection and automated response for a lab environment.",
    version="0.8.0",
)

# Lets the React dashboard (port 5173) call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Public: sign-in. Log shippers: API key (see routers/ingest.py). Everything else: a signed-in
# user whose role allows that route (auth/permissions.py - the whole policy in one table).
app.include_router(auth.router)
app.include_router(ingest.router)
protected = [Depends(authorize)]
for r in (events.router, stats.router, alerts.router, detection.router, ml.router, incidents.router,
          response.router, audit.router, lab.router, auth.users_router):
    app.include_router(r, dependencies=protected)


@app.middleware("http")
async def announce_changes(request: Request, call_next):
    """After any change made through the API (ack an alert, approve an action, toggle a rule...),
    tell open dashboards to refresh. Ingest and lab endpoints announce themselves, with details."""
    response = await call_next(request)
    path = request.url.path
    if (request.method not in ("GET", "HEAD", "OPTIONS") and path.startswith("/api/")
            and not path.startswith(("/api/ingest", "/api/lab", "/api/auth")) and response.status_code < 400):
        hub.publish({"type": "update", "source": "api", "path": path})
    return response


@app.websocket("/ws")
async def websocket(ws: WebSocket):
    """Real-time channel. The server PUSHES small "something changed" messages; pages then
    re-fetch what they show. Clients don't need to send anything.
    Browsers can't set headers on WebSockets, so the token comes as ?token=... """
    if await run_in_threadpool(user_from_token, ws.query_params.get("token")) is None:
        await ws.close(code=4401)          # reject the handshake: not signed in
        return
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()        # keeps the connection open; we ignore what clients send
    except WebSocketDisconnect:
        pass
    finally:
        hub.disconnect(ws)


@app.get("/health")
def health():
    return {"status": "ok"}
