from collections import Counter

from .common import make_alert


SUSPICIOUS_DOMAINS = [
    "bad-domain.xyz",
    "c2-server.attacker.net",
    "malware",
    "beacon",
    "update-check",
]


def detect_dns_suspicious_domain(events):
    alerts = []
    seen = set()

    for e in events:

        if e.get("source") != "dns":
            continue

        domain = (e.get("domain") or "").lower()

        if not any(x.lower() in domain for x in SUSPICIOUS_DOMAINS):
            continue

        key = (
            e.get("ip", ""),
            domain,
        )

        if key in seen:
            continue

        seen.add(key)

        alerts.append(
            make_alert(
                timestamp=e.get("timestamp", ""),
                source="DNS",
                rule="Suspicious DNS Query",
                mitre="T1071.004",
                tactic="Command and Control",
                technique="DNS",
                score=88,
                message=f"Suspicious domain queried: {domain}",
                ip=e.get("ip", ""),
                evidence={
                    "domain": domain,
                    "raw": e.get("raw", ""),
                },
            )
        )

    return alerts


def detect_dns_beaconing(events):
    counter = Counter()
    last_ts = {}

    for e in events:

        if e.get("source") != "dns":
            continue

        key = (
            e.get("ip", ""),
            e.get("domain", "").lower(),
        )

        counter[key] += 1
        last_ts[key] = e.get("timestamp", "")

    alerts = []

    for (ip, domain), count in counter.items():

        if count < 3:
            continue

        alerts.append(
            make_alert(
                timestamp=last_ts[(ip, domain)],
                source="DNS",
                rule="DNS Beaconing",
                mitre="T1071.004",
                tactic="Command and Control",
                technique="DNS",
                score=90,
                message=f"Repeated DNS queries for {domain} from {ip} ({count} queries)",
                ip=ip,
                evidence={
                    "domain": domain,
                    "queries": count,
                },
            )
        )

    return alerts