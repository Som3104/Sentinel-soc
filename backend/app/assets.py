"""Asset inventory: what each monitored machine is, and how much it matters.

Real SOCs keep a CMDB (configuration management database) for this. Risk depends
on WHAT is attacked: the same malware is far worse on the customer database than
on a test laptop. The incident risk score uses `criticality` below.
"""

ASSETS = {
    "db-01": {"role": "Customer database", "criticality": "critical", "owner": "Data team"},
    "web-01": {"role": "Public web server", "criticality": "high", "owner": "Platform team"},
    "web-02": {"role": "Public web server", "criticality": "high", "owner": "Platform team"},
    "dev-laptop-07": {"role": "Developer laptop", "criticality": "medium", "owner": "R&D"},
}

CRITICALITY_POINTS = {"critical": 10, "high": 5, "medium": 0, "low": 0}


def asset(host: str | None) -> dict:
    return ASSETS.get(host or "", {"role": "Unknown asset", "criticality": "medium", "owner": "—"})
