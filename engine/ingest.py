from __future__ import annotations

from collections import Counter
from pathlib import Path
from .correlator import correlate_incidents
from .parsers import parse_uploaded_file
from .rules import (
    detect_admin_login,
    detect_bruteforce,
    detect_directory_traversal,
    detect_firewall_port_scan,
    detect_firewall_repeated_blocks,
    detect_firewall_suspicious_ports,
    detect_invalid_user,
    detect_log_cleared,
    detect_sql_injection,
    detect_ssh_service_stop,
    detect_success_after_fail,
    detect_web_scan,
    detect_windows_failed_login,
    detect_windows_success_login,
    detect_dns_suspicious_domain,
    detect_dns_beaconing,
)
from .sigma import run_sigma
from .ioc import detect_iocs
from .database import save_alerts

DETECTION_PIPELINE = (
    detect_bruteforce,
    detect_success_after_fail,
    detect_invalid_user,
    detect_ssh_service_stop,
    detect_directory_traversal,
    detect_web_scan,
    detect_sql_injection,
    detect_windows_failed_login,
    detect_windows_success_login,
    detect_admin_login,
    detect_log_cleared,
    detect_firewall_port_scan,
    detect_firewall_repeated_blocks,
    detect_firewall_suspicious_ports,
    detect_dns_suspicious_domain,
    detect_dns_beaconing,
)

MITRE_RULES = [
    ("sql injection", ("Initial Access", "Exploit Public-Facing Application", "T1190")),
    ("directory traversal", ("Initial Access", "Exploit Public-Facing Application", "T1190")),
    ("brute force", ("Credential Access", "Brute Force", "T1110")),
    ("success after fail", ("Credential Access", "Brute Force", "T1110")),
    ("invalid user", ("Credential Access", "Brute Force", "T1110")),
    ("log cleared", ("Defense Evasion", "Indicator Removal on Host", "T1070")),
    ("admin", ("Privilege Escalation", "Abuse Elevation Control Mechanism", "T1548")),
    ("web scanning", ("Discovery", "Network Service Scanning", "T1046")),
    ("port scan", ("Discovery", "Network Service Scanning", "T1046")),
    ("blocked connections", ("Discovery", "Network Service Scanning", "T1046")),
    ("powershell", ("Execution", "Command and Scripting Interpreter", "T1059")),
]


def score_to_severity(score: int | float) -> str:
    score = float(score or 0)
    if score >= 90:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def infer_mitre_fields(alert: dict) -> tuple[str, str, str]:
    blob = " ".join(
        [
            str(alert.get("source", "")),
            str(alert.get("rule", "")),
            str(alert.get("message", "")),
            str(alert.get("mitre", "")),
        ]
    ).lower()

    for needle, mapping in MITRE_RULES:
        if needle in blob:
            return mapping

    return ("Unknown tactic", "Unknown technique", str(alert.get("mitre", "TBD")))


def normalize_alert(alert: dict) -> dict:
    normalized = dict(alert) if isinstance(alert, dict) else {"message": str(alert)}

    score = int(normalized.get("score", 0) or 0)
    normalized["score"] = score
    normalized["severity"] = normalized.get("severity") or score_to_severity(score)

    if "message" not in normalized:
        normalized["message"] = normalized.get("detail", str(alert))

    if "rule" not in normalized:
        normalized["rule"] = "Unknown rule"

    if "source" not in normalized:
        normalized["source"] = "Unknown"

    tactic, technique, mitre_id = infer_mitre_fields(normalized)
    normalized["tactic"] = normalized.get("tactic") or tactic
    normalized["technique"] = normalized.get("technique") or technique
    normalized["mitre"] = normalized.get("mitre") or mitre_id

    normalized.setdefault("timestamp", "")
    normalized.setdefault("ip", "")
    normalized.setdefault("user", "")
    normalized.setdefault("evidence", {})
    return normalized


def run_detections(events: list[dict]) -> list[dict]:
    alerts: list[dict] = []

    # Built-in detection rules
    for detector in DETECTION_PIPELINE:
        for alert in detector(events):
            alerts.append(normalize_alert(alert))

    # Sigma detection rules
    for alert in run_sigma(events):
        alerts.append(normalize_alert(alert))

    alerts.sort(
        key=lambda a: (a.get("score", 0), a.get("timestamp", "")),
        reverse=True,
    )

    return alerts

def ingest_files(paths: list[Path]):

    events: list[dict] = []
    sources: list[str] = []

    print("\n" + "=" * 70)
    print("INGEST START")
    print("=" * 70)

    for path in paths:
        sources.append(path.name)

        parsed = parse_uploaded_file(path)

        print(f"\nFile: {path.name}")
        print(f"Parsed events: {len(parsed)}")

        if parsed:
            print("First parsed event:")
            print(parsed[0])
        else:
            print("NO EVENTS PARSED!")

        events.extend(parsed)

    print("\nTOTAL EVENTS:", len(events))

    alerts = run_detections(events)

    print("RULE ALERTS:", len(alerts))

    ioc_alerts = detect_iocs(events)

    print("IOC ALERTS:", len(ioc_alerts))

    for alert in ioc_alerts:
        alerts.append(normalize_alert(alert))

    print("TOTAL ALERTS:", len(alerts))

    save_alerts(alerts)

    incidents = correlate_incidents(alerts)

    print("INCIDENTS:", len(incidents))
    print("=" * 70)

    stats = summarize(alerts, incidents)

    return alerts, incidents, stats, sources

def summarize(alerts, incidents):
    alert_counts = Counter(a.get("severity", "LOW") for a in alerts)
    rule_counts = Counter(a.get("rule", "Unknown") for a in alerts)
    source_counts = Counter(a.get("source", "Unknown") for a in alerts)
    ip_counts = Counter(
        a.get("ip", "")
        for a in alerts
        if a.get("ip") and a.get("ip") not in {"Unknown", "unknown", "-"}
    )
    user_counts = Counter(
        a.get("user", "")
        for a in alerts
        if a.get("user") and a.get("user") not in {"Unknown", "unknown", "-"}
    )
    avg_score = round(sum(a.get("score", 0) for a in alerts) / len(alerts), 1) if alerts else 0.0

    def top_items(counter: Counter, limit: int = 5):
        return [
            {"name": name, "count": count}
            for name, count in counter.most_common(limit)
            if name and name not in {"Unknown", "unknown", "-"}
        ]

    return {
        "alerts": len(alerts),
        "incidents": len(incidents),
        "critical": alert_counts.get("CRITICAL", 0),
        "high": alert_counts.get("HIGH", 0),
        "medium": alert_counts.get("MEDIUM", 0),
        "low": alert_counts.get("LOW", 0),
        "average_score": avg_score,
        "top_rules": top_items(rule_counts),
        "top_sources": top_items(source_counts),
        "top_ips": top_items(ip_counts),
        "top_users": top_items(user_counts),
    }
