"""Sign-in and user management (Phase 8).

    POST /api/auth/login          username + password -> signed token (8 h)
    GET  /api/auth/me             who am I?
    POST /api/auth/password       change my own password
    GET  /api/auth/permissions    the role/permission table (shown on the Users page)
    GET/POST/PATCH /api/users     admin: manage accounts

Every login attempt, success or failure, goes to the audit log (category "access"):
a SOC should be able to investigate attacks on itself.
"""
import os
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import CurrentUser, authorize, current_user
from ..auth.permissions import ROLES, policy_table
from ..auth.security import DUMMY_HASH, create_token, hash_password, verify_password
from ..database import get_db
from ..models import User
from ..response.audit import audit
from ..utils import aware, utcnow

router = APIRouter(prefix="/api/auth", tags=["auth"])
users_router = APIRouter(prefix="/api/users", tags=["users"])

MAX_FAILED = 5
LOCK_MINUTES = 5
Role = Literal["viewer", "analyst", "admin"]

# Demo accounts created on first start (lab only - change or disable them for anything real).
DEMO_USERS = [
    ("admin", "SOC Admin", "admin", os.getenv("DEMO_ADMIN_PASSWORD", "Admin@123")),
    ("analyst", "Priya (Tier-1 analyst)", "analyst", os.getenv("DEMO_ANALYST_PASSWORD", "Analyst@123")),
    ("viewer", "Rahul (SOC manager)", "viewer", os.getenv("DEMO_VIEWER_PASSWORD", "Viewer@123")),
]


def seed_users(db: Session) -> int:
    if db.scalar(select(func.count(User.id))):
        return 0
    for username, name, role, password in DEMO_USERS:
        db.add(User(username=username, display_name=name, role=role, password_hash=hash_password(password),
                    created_at=utcnow()))
    db.commit()
    return len(DEMO_USERS)


def user_dict(u: User) -> dict:
    return {"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role, "active": u.active,
            "locked_until": u.locked_until, "failed_attempts": u.failed_attempts,
            "last_login": u.last_login, "created_at": u.created_at}


# ------------------------------------------------------------------ sign-in
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=200)


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    username = body.username.strip().lower()
    u = db.scalar(select(User).where(User.username == username))
    now = utcnow()

    def fail(reason: str, message: str = "Wrong username or password"):
        audit(db, category="access", action="login_failed", target=username, actor="system", status="failed",
              result=f"Failed sign-in from {ip}: {reason}", details={"ip": ip, "reason": reason}, username=username)
        db.commit()
        raise HTTPException(401, message)

    if u is None:
        verify_password(body.password, DUMMY_HASH)          # same time as a real check
        fail("unknown user")
    if not u.active:
        verify_password(body.password, DUMMY_HASH)
        fail("account disabled")
    if u.locked_until and aware(u.locked_until) > now:
        mins = max(1, round((aware(u.locked_until) - now).total_seconds() / 60))
        fail("account locked", f"Too many failed attempts. Try again in {mins} min.")
    if not verify_password(body.password, u.password_hash):
        u.failed_attempts += 1
        if u.failed_attempts >= MAX_FAILED:
            u.locked_until = now + timedelta(minutes=LOCK_MINUTES)
            u.failed_attempts = 0
            audit(db, category="access", action="account_locked", target=username, actor="system", status="failed",
                  result=f"{username} locked for {LOCK_MINUTES} min after {MAX_FAILED} wrong passwords (last from {ip})",
                  details={"ip": ip}, username=username)
        fail("wrong password")

    u.failed_attempts = 0
    u.locked_until = None
    u.last_login = now
    token, exp = create_token(u.username, u.role)
    audit(db, category="access", action="login", target=username, actor="analyst", result=f"Signed in from {ip}",
          details={"ip": ip}, username=username)
    db.commit()
    return {"access_token": token, "token_type": "bearer", "expires_at": exp, "user": user_dict(u)}


@router.get("/me")
def me(user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    return user_dict(db.get(User, user.id))


class PasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=200)


@router.post("/password")
def change_password(body: PasswordIn, user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    u = db.get(User, user.id)
    if not verify_password(body.current_password, u.password_hash):
        raise HTTPException(400, "Current password is wrong")
    u.password_hash = hash_password(body.new_password)
    audit(db, category="access", action="password_changed", target=u.username, actor="analyst",
          result="Changed own password")
    db.commit()
    return {"ok": True}


@router.get("/permissions")
def permissions(user: CurrentUser = Depends(current_user)):
    return {"roles": ROLES, "policy": policy_table()}


# ------------------------------------------------------------------ user management (admin)
class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    display_name: str = Field(min_length=1, max_length=100)
    role: Role = "analyst"
    password: str = Field(min_length=8, max_length=200)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    role: Role | None = None
    active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=200)
    unlock: bool | None = None


@users_router.get("")
def list_users(db: Session = Depends(get_db)):
    return [user_dict(u) for u in db.scalars(select(User).order_by(User.id)).all()]


@users_router.post("", status_code=201)
def create_user(body: UserIn, db: Session = Depends(get_db)):
    username = body.username.lower()
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(409, f"User '{username}' already exists")
    u = User(username=username, display_name=body.display_name, role=body.role,
             password_hash=hash_password(body.password), created_at=utcnow())
    db.add(u)
    audit(db, category="access", action="user_created", target=username, actor="analyst",
          result=f"Created {body.role} account '{username}'")
    db.commit()
    return user_dict(u)


@users_router.patch("/{user_id}")
def update_user(user_id: int, body: UserUpdate, me: CurrentUser = Depends(authorize), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "No such user")
    changes = []
    removing_admin = u.role == "admin" and ((body.role and body.role != "admin") or body.active is False)
    if removing_admin:
        if u.id == me.id:
            raise HTTPException(400, "You can't remove your own admin access (ask another admin).")
        admins = db.scalar(select(func.count(User.id)).where(User.role == "admin", User.active.is_(True)))
        if admins <= 1:
            raise HTTPException(400, "There must always be at least one active admin.")
    if body.display_name is not None and body.display_name != u.display_name:
        u.display_name = body.display_name
        changes.append("name")
    if body.role is not None and body.role != u.role:
        changes.append(f"role {u.role} → {body.role}")
        u.role = body.role
    if body.active is not None and body.active != u.active:
        u.active = body.active
        changes.append("enabled" if body.active else "disabled")
    if body.password:
        u.password_hash = hash_password(body.password)
        changes.append("password reset")
    if body.unlock:
        u.locked_until, u.failed_attempts = None, 0
        changes.append("unlocked")
    if changes:
        audit(db, category="access", action="user_updated", target=u.username, actor="analyst",
              result=f"{u.username}: " + ", ".join(changes))
        db.commit()
    return user_dict(u)
