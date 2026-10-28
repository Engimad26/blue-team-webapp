from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path


def build_report(
    *,
    scan_id: str,
    alerts: list[dict],
    incidents: list[dict],
    stats: dict,
    sources: list[str],
    label: str = "Scan",
) -> str:
    mitre_counts = Counter(
        f"{a.get('mitre', 'TBD')} | {a.get('tactic', 'Unknown tactic')} | {a.get('technique', 'Unknown technique')}"
        for a in alerts
        if a.get("mitre") or a.get("tactic") or a.get("technique")
    )

    lines: list[str] = []
    lines.append("BLUE TEAM DETECTION REPORT")
    lines.append(f"Label: {label}")
    lines.append(f"Scan ID: {scan_id}")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")

    lines.append("SUMMARY")
    lines.append(f"Sources: {', '.join(sources) if sources else 'None'}")
    lines.append(f"Alerts: {stats['alerts']}")
    lines.append(f"Incidents: {stats['incidents']}")
    lines.append(f"Average score: {stats['average_score']}/100")
    lines.append(f"CRITICAL: {stats['critical']}")
    lines.append(f"HIGH: {stats['high']}")
    lines.append(f"MEDIUM: {stats['medium']}")
    lines.append(f"LOW: {stats['low']}")
    lines.append("")

    lines.append("TOP RULES")
    for item in stats.get("top_rules", []):
        lines.append(f"- {item['name']}: {item['count']}")
    lines.append("")

    lines.append("TOP SOURCES")
    for item in stats.get("top_sources", []):
        lines.append(f"- {item['name']}: {item['count']}")
    lines.append("")

    lines.append("TOP IPs")
    for item in stats.get("top_ips", []):
        lines.append(f"- {item['name']}: {item['count']}")
    lines.append("")

    lines.append("TOP USERS")
    for item in stats.get("top_users", []):
        lines.append(f"- {item['name']}: {item['count']}")
    lines.append("")

    lines.append("TOP MITRE TECHNIQUES")
    for item, count in mitre_counts.most_common(10):
        lines.append(f"- {item}: {count}")
    lines.append("")

    lines.append("INCIDENTS")
    for inc in incidents:
        lines.append(
            f"- [{inc['severity']}] {inc['title']} | Score {inc['score']}/100 | Alerts {inc['alert_count']} | Key {inc['key']}"
        )
        if inc.get("first_seen") or inc.get("last_seen"):
            lines.append(f"  Time: {inc.get('first_seen', '')} -> {inc.get('last_seen', '')}")
        if inc.get("sources"):
            lines.append(f"  Sources: {', '.join(inc['sources'])}")
        if inc.get("rules"):
            lines.append(f"  Rules: {', '.join(inc['rules'])}")

        reasons = []
        if inc.get("key", "").startswith("ip:"):
            reasons.append(f"shared IP {inc['key'][3:]}")
        elif inc.get("key", "").startswith("user:"):
            reasons.append(f"shared user {inc['key'][5:]}")
        elif inc.get("key", "").startswith("host:"):
            reasons.append(f"shared host {inc['key'][5:]}")
        if len(inc.get("sources", [])) > 1:
            reasons.append("multiple log sources")
        if len(inc.get("rules", [])) > 2:
            reasons.append("multiple rules in the same cluster")
        if reasons:
            lines.append(f"  Correlation reason: {', '.join(reasons)}")

        for alert in inc["alerts"]:
            lines.append(
                f"  - [{alert['severity']}] {alert['source']} | {alert['rule']} | {alert['message']} | "
                f"MITRE {alert['mitre']} | Score {alert['score']}"
            )
            if alert.get("tactic") or alert.get("technique"):
                lines.append(
                    f"    Technique: {alert.get('tactic', 'Unknown tactic')} / {alert.get('technique', 'Unknown technique')}"
                )

    return "\n".join(lines)


def save_report(report: str, *, scan_id: str, output_dir: Path) -> Path:
    output_dir.mkdir(exist_ok=True)
    path = output_dir / f"final_report_{scan_id}.txt"
    path.write_text(report, encoding="utf-8")
    return path