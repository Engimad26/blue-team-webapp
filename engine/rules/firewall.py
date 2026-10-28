from __future__ import annotations

from collections import Counter, defaultdict

from engine.rules import make_alert


BLOCK_ACTIONS = {
    "DROP",
    "DENY",
    "BLOCK",
    "BLOCKED",
    "CLOSE",
    "CLOSED",
}


def detect_firewall_port_scan(events, threshold=5):
    scanned_ports = defaultdict(set)
    last_ts = {}

    for e in events:
        if e.get("source") != "firewall":
            continue

        action = str(e.get("action", "")).upper()

        if action not in BLOCK_ACTIONS:
            continue

        src_ip = e.get("src_ip", "unknown")

        scanned_ports[src_ip].add(str(e.get("dst_port", "")))
        last_ts[src_ip] = e.get("timestamp", "")

    alerts = []

    for src_ip, ports in scanned_ports.items():
        if len(ports) >= threshold:
            alerts.append(
                make_alert(
                    timestamp=last_ts.get(src_ip, ""),
                    source="Firewall",
                    rule="Port scan",
                    mitre="T1046",
                    tactic="Discovery",
                    technique="Network Service Scanning",
                    score=min(85, 50 + len(ports) * 6),
                    message=f"Possible port scan from {src_ip} ({len(ports)} ports)",
                    ip=src_ip,
                    evidence={"ports": sorted(ports)},
                )
            )

    return alerts


def detect_firewall_repeated_blocks(events, threshold=10):
    counter = Counter()
    last_ts = {}

    for e in events:
        if e.get("source") != "firewall":
            continue

        action = str(e.get("action", "")).upper()

        if action not in BLOCK_ACTIONS:
            continue

        src_ip = e.get("src_ip", "unknown")

        counter[src_ip] += 1
        last_ts[src_ip] = e.get("timestamp", "")

    alerts = []

    for src_ip, count in counter.items():
        if count >= threshold:
            alerts.append(
                make_alert(
                    timestamp=last_ts.get(src_ip, ""),
                    source="Firewall",
                    rule="Repeated blocked connections",
                    mitre="T1046",
                    tactic="Discovery",
                    technique="Network Service Scanning",
                    score=min(80, 45 + count),
                    message=f"{count} blocked firewall connections from {src_ip}",
                    ip=src_ip,
                    evidence={"count": count},
                )
            )

    return alerts


def detect_firewall_suspicious_ports(events):
    suspicious_ports = {
        "21",
        "22",
        "23",
        "135",
        "137",
        "138",
        "139",
        "445",
        "1433",
        "3306",
        "3389",
        "4444",
        "5555",
        "5900",
        "8080",
        "8443",
        "1337",
        "31337",
    }

    alerts = []
    seen = set()

    for e in events:
        if e.get("source") != "firewall":
            continue

        port = str(e.get("dst_port", ""))

        if port not in suspicious_ports:
            continue

        key = (
            e.get("src_ip", ""),
            e.get("dst_ip", ""),
            port,
        )

        if key in seen:
            continue

        seen.add(key)

        alerts.append(
            make_alert(
                timestamp=e.get("timestamp", ""),
                source="Firewall",
                rule="Suspicious destination port",
                mitre="T1046",
                tactic="Discovery",
                technique="Network Service Scanning",
                score=75,
                message=f"Traffic to suspicious port {port} ({e.get('src_ip')} -> {e.get('dst_ip')})",
                ip=e.get("src_ip", ""),
                evidence={
                    "destination_port": port,
                    "destination_ip": e.get("dst_ip", ""),
                },
            )
        )

    return alerts