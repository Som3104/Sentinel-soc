"""Password hashing and signed login tokens, using only Python's standard library.

PASSWORDS are never stored. We store a PBKDF2-SHA256 hash:

    pbkdf2_sha256$600000$<salt>$<hash>

- salt: 16 random bytes per user, so two users with the same password get different
  hashes and precomputed "rainbow tables" are useless.
- 600,000 iterations (OWASP's 2023 recommendation): checking one guess takes ~0.3 s,
  which is nothing for a login but makes offline cracking of a stolen database very slow.
- The iteration count is stored in the hash, so it can be raised later without breaking
  old passwords.

TOKENS are JWTs (JSON Web Tokens) signed with HMAC-SHA256:

    base64(header) . base64(payload) . base64(signature)

The payload ({"sub": "alice", "role": "analyst", "exp": ...}) is readable by anyone, but
only the server knows SECRET_KEY, so nobody can change it without breaking the signature.
The server stays stateless: no session table, just verify the signature and expiry.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

log = logging.getLogger("uvicorn.error")

DEV_SECRET = "dev-only-secret-change-me"
SECRET_KEY = os.getenv("SECRET_KEY", DEV_SECRET)
if SECRET_KEY == DEV_SECRET:
    log.warning("SECRET_KEY not set: using the development default. Set it in docker-compose.yml for anything real.")

TOKEN_HOURS = float(os.getenv("TOKEN_HOURS", "8"))           # one analyst shift
ITERATIONS = int(os.getenv("PASSWORD_HASH_ITERATIONS", "600000"))


# ------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, expected = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
    # compare_digest takes the same time whether the first or last byte differs,
    # so an attacker can't learn the hash byte by byte from response times.
    return hmac.compare_digest(digest.hex(), expected)


# A real hash of a random password: used when the username doesn't exist, so a login for an
# unknown user takes as long as one for a real user (no "does this account exist?" timing leak).
DUMMY_HASH = hash_password(secrets.token_hex(8))


# ------------------------------------------------------------------ tokens (JWT, HS256)
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(message: bytes) -> str:
    return _b64(hmac.new(SECRET_KEY.encode(), message, hashlib.sha256).digest())


def create_token(username: str, role: str, hours: float = TOKEN_HOURS) -> tuple[str, int]:
    now = int(time.time())
    exp = now + int(hours * 3600)
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps({"sub": username, "role": role, "iat": now, "exp": exp}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_sign(signing_input)}", exp


def decode_token(token: str) -> dict | None:
    """The payload if the token is genuine and not expired, else None."""
    try:
        header, payload, signature = token.split(".")
        if not hmac.compare_digest(signature, _sign(f"{header}.{payload}".encode())):
            return None
        if json.loads(_unb64(header)).get("alg") != "HS256":    # refuse "alg: none" tricks
            return None
        data = json.loads(_unb64(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("exp", 0) < time.time():
        return None
    return data
