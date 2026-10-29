"""Small helpers shared across the backend."""
import ipaddress
from datetime import datetime, timezone


def aware(ts: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC so comparisons work everywhere."""
    if ts is None:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# RFC 5737 documentation ranges. Python flags them "private", but in our lab
# they play the role of internet attackers, so we treat them as external.
_SIMULATED_INTERNET = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(addr in net for net in _SIMULATED_INTERNET):
        return True
    return not addr.is_private
