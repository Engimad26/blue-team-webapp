from __future__ import annotations

from collections import defaultdict
from uuid import uuid4


def group_key(alert: dict) -> str:
    if alert.get("ip"):
        return f"ip:{alert['ip']}"
    if alert.get("user"):
        return f"user:{alert['user']}"
    if alert.get("host"):
        return f"host:{alert['host']}"
    return f"source:{alert.get('source','unknown')}"


def correlate_incidents(alerts: list[dict]) -> list[dict]:
    buckets = defaultdict(list)
    for alert in alerts:
        buckets[group_key(alert)].append(alert)

    incidents = []
    for key, items in buckets.items():
        items = sorted(items, key=lambda x: x.get("score", 0), reverse=True)
        score = min(100, sum(a.get("score", 0) for a in items))
        sources = sorted(set(a.get("source", "") for a in items if a.get("source")))
        rules = sorted(set(a.get("rule", "") for a in items if a.get("rule")))
        timestamps = [a.get("timestamp", "") for a in items if a.get("timestamp")]
        first_seen = timestamps[0] if timestamps else ""
        last_seen = timestamps[-1] if timestamps else ""

        title = _incident_title(items, sources)
        incidents.append({
            "id": str(uuid4())[:8],
            "key": key,
            "title": title,
            "score": score,
            "severity": _severity(score),
            "sources": sources,
            "rules": rules,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "alert_count": len(items),
            "alerts": items,
        })

    incidents.sort(key=lambda x: x["score"], reverse=True)
    return incidents


def _incident_title(items: list[dict], sources: list[str]) -> str:
    if not items:
        return "Incident"

    top = items[0]
    if len(sources) > 1:
        return f"Multi-source incident: {top.get('rule', 'Detection')}"
    if len(items) > 1:
        return f"{top.get('rule', 'Detection')} ({len(items)} alerts)"
    return top.get("rule", "Incident")


def _severity(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"
