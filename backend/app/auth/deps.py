"""FastAPI dependencies that enforce authentication and the permission table.

    current_user  - "who is calling?" Reads the Bearer token, checks the signature and expiry,
                    then checks the account still exists and is enabled (so disabling a user or
                    changing their role takes effect immediately, not when their token expires).
    authorize     - "may they call THIS route?" Looks the route up in permissions.POLICY.
    require_ingest_key - log shippers (the simulator) use an API key instead of a user login.

The username is also put in a context variable, so the audit log records WHO did each
action without passing the user through every function.
"""
import contextvars
import hmac
import os
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from ..database import SessionLocal
from ..models import User
from .permissions import allows, required_role
from .security import decode_token

INGEST_API_KEY = os.getenv("INGEST_API_KEY", "lab-ingest-key")
current_username: contextvars.ContextVar[str | None] = contextvars.ContextVar("current_username", default=None)
bearer = HTTPBearer(auto_error=False, description="Paste the token from POST /api/auth/login")


@dataclass
class CurrentUser:
    id: int
    username: str
    display_name: str
    role: str


def user_from_token(token: str | None) -> CurrentUser | None:
    """Blocking (DB lookup): call from a thread. Also used by the WebSocket endpoint."""
    data = decode_token(token) if token else None
    if not data:
        return None
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == data.get("sub")))
        if u is None or not u.active:
            return None
        return CurrentUser(u.id, u.username, u.display_name, u.role)


async def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> CurrentUser:
    # async + run_in_threadpool: the DB lookup doesn't block the event loop, and the context
    # variable set here is visible to the (sync) endpoint that runs next.
    user = await run_in_threadpool(user_from_token, creds.credentials if creds else None)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in or session expired",
                            headers={"WWW-Authenticate": "Bearer"})
    current_username.set(user.username)
    return user


async def authorize(request: Request, user: CurrentUser = Depends(current_user)) -> CurrentUser:
    route = request.scope.get("route")
    needed = required_role(request.method, getattr(route, "path", request.url.path))
    if not allows(user.role, needed):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Your role ({user.role}) can't do this: it needs {needed}.")
    return user


def require_role(user: CurrentUser, role: str, what: str) -> None:
    """For checks that depend on the request body (e.g. lab reset 'full' needs admin)."""
    if not allows(user.role, role):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"{what} needs the {role} role (you are {user.role}).")


def require_ingest_key(x_api_key: str | None = Header(default=None)) -> None:
    if not x_api_key or not hmac.compare_digest(x_api_key, INGEST_API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or wrong X-API-Key header")
