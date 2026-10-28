from __future__ import annotations
from uuid import uuid4

def clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def make_alert(
    *,
    timestamp="",
    source="",
    rule="",
    mitre="",
    tactic="",
    technique="",
    score=0,
    message="",
    ip="",
    user="",
    host="",
    evidence=None,
):
    score = clamp_score(score)
    return {
        "id": str(uuid4()),
        "timestamp": timestamp,
        "source": source,
        "rule": rule,
        "mitre": mitre,
        "tactic": tactic,
        "technique": technique,
        "score": score,
        "severity": severity_from_score(score),
        "message": message,
        "ip": ip,
        "user": user,
        "host": host,
        "evidence": evidence or {},
    }