from collections import Counter
from .common import make_alert


def detect_bruteforce(events, threshold=3):
    counter = Counter()
    last_ts = {}

    for e in events:
        if e.get("source") != "ssh":
            continue

        if e.get("status") != "Failed password":
            continue

        ip = e.get("ip", "Unknown")

        counter[ip] += 1
        last_ts[ip] = e.get("timestamp", "")

    alerts = []

    for ip, count in counter.items():
        if count >= threshold:

            alerts.append(
                make_alert(
                    timestamp=last_ts[ip],
                    source="SSH",
                    rule="Brute Force",
                    mitre="T1110",
                    tactic="Credential Access",
                    technique="Brute Force",
                    score=85,
                    message=f"Brute force detected from {ip} ({count} failed logins)",
                    ip=ip,
                    evidence={"failed_logins": count},
                )
            )

    return alerts


def detect_success_after_fail(events, threshold=3):
    failed = Counter()
    alerts = []

    for e in events:

        if e.get("source") != "ssh":
            continue

        key = (
            e.get("ip", "Unknown"),
            e.get("user", "Unknown"),
        )

        if e.get("status") == "Failed password":
            failed[key] += 1

        elif e.get("status") == "Accepted password":

            if failed[key] >= threshold:

                alerts.append(
                    make_alert(
                        timestamp=e.get("timestamp", ""),
                        source="SSH",
                        rule="Success After Failures",
                        mitre="T1078/T1110",
                        tactic="Credential Access",
                        technique="Valid Accounts / Brute Force",
                        score=92,
                        message=f"Successful login for {e.get('user')} after {failed[key]} failed attempts",
                        ip=e.get("ip", ""),
                        user=e.get("user", ""),
                        evidence={"failed_before_success": failed[key]},
                    )
                )

    return alerts


def detect_invalid_user(events):
    alerts = []
    seen = set()

    for e in events:

        if e.get("source") != "ssh":
            continue

        if e.get("status") != "Invalid user":
            continue

        key = (
            e.get("ip", ""),
            e.get("user", ""),
        )

        if key in seen:
            continue

        seen.add(key)

        alerts.append(
            make_alert(
                timestamp=e.get("timestamp", ""),
                source="SSH",
                rule="Invalid User",
                mitre="T1110",
                tactic="Credential Access",
                technique="Brute Force",
                score=58,
                message=f"Invalid user '{e.get('user')}' attempted from {e.get('ip')}",
                ip=e.get("ip", ""),
                user=e.get("user", ""),
                evidence={"raw": e.get("raw", "")},
            )
        )

    return alerts


def detect_ssh_service_stop(events):
    alerts = []

    for e in events:

        if e.get("source") != "ssh":
            continue

        if e.get("status") != "SSH Stopped":
            continue

        alerts.append(
            make_alert(
                timestamp=e.get("timestamp", ""),
                source="SSH",
                rule="SSH Service Stopped",
                mitre="T1562.001",
                tactic="Defense Evasion",
                technique="Impair Defenses",
                score=88,
                message="SSH service was stopped",
                evidence={"raw": e.get("raw", "")},
            )
        )

    return alerts