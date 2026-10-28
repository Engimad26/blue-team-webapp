from collections import Counter
from urllib.parse import unquote

from .common import make_alert


TRAVERSAL_PATTERNS = [
    "/etc/passwd",
    "../",
    "..\\",
    "/proc/",
    "/boot/",
    "/windows/",
]

SQL_KEYWORDS = [
    "' OR",
    "UNION",
    "SELECT",
    "--",
    "DROP",
    "INSERT",
    "UPDATE",
    "DELETE",
]


def detect_directory_traversal(events):
    alerts = []
    seen = set()

    for e in events:

        if e.get("source") != "apache":
            continue

        path = (e.get("path") or "").lower()

        if not any(p.lower() in path for p in TRAVERSAL_PATTERNS):
            continue

        key = (
            e.get("ip", ""),
            path,
        )

        if key in seen:
            continue

        seen.add(key)

        alerts.append(
            make_alert(
                timestamp=e.get("timestamp", ""),
                source="Apache",
                rule="Directory Traversal",
                mitre="T1190",
                tactic="Initial Access",
                technique="Exploit Public-Facing Application",
                score=82,
                message=f"Possible directory traversal from {e.get('ip')} -> {e.get('path')}",
                ip=e.get("ip", ""),
                evidence={"path": e.get("path", "")},
            )
        )

    return alerts


def detect_web_scan(events, threshold=3):
    counter = Counter()
    last_ts = {}

    for e in events:

        if e.get("source") != "apache":
            continue

        if int(e.get("status", 0)) != 404:
            continue

        ip = e.get("ip", "Unknown")

        counter[ip] += 1
        last_ts[ip] = e.get("timestamp", "")

    alerts = []

    for ip, count in counter.items():

        if count < threshold:
            continue

        alerts.append(
            make_alert(
                timestamp=last_ts[ip],
                source="Apache",
                rule="Web Scanning",
                mitre="T1046",
                tactic="Discovery",
                technique="Network Service Scanning",
                score=60,
                message=f"Possible web scanning from {ip} ({count} HTTP 404 requests)",
                ip=ip,
                evidence={"404_requests": count},
            )
        )

    return alerts


def detect_sql_injection(events):
    alerts = []
    seen = set()

    for e in events:

        if e.get("source") != "apache":
            continue

        decoded = unquote(e.get("path", "")).upper()

        if not any(k.upper() in decoded for k in SQL_KEYWORDS):
            continue

        key = (
            e.get("ip", ""),
            decoded,
        )

        if key in seen:
            continue

        seen.add(key)

        alerts.append(
            make_alert(
                timestamp=e.get("timestamp", ""),
                source="Apache",
                rule="SQL Injection",
                mitre="T1190",
                tactic="Initial Access",
                technique="Exploit Public-Facing Application",
                score=95,
                message=f"Possible SQL injection from {e.get('ip')} -> {decoded}",
                ip=e.get("ip", ""),
                evidence={"path": e.get("path", "")},
            )
        )

    return alerts