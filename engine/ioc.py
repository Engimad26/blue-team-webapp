from __future__ import annotations

from pathlib import Path

from .rules.common import make_alert


IOC_FOLDER = Path(__file__).parent.parent / "ioc"
print("IOC folder:", IOC_FOLDER)
print("Exists:", IOC_FOLDER.exists())

if IOC_FOLDER.exists():
    print("Files:", list(IOC_FOLDER.iterdir()))

def load_list(filename):
    path = IOC_FOLDER / filename

    if not path.exists():
        return set()

    with open(path, "r", encoding="utf-8") as f:
        return {
            line.strip().lower()
            for line in f
            if line.strip() and not line.startswith("#")
        }


MALICIOUS_IPS = load_list("malicious_ips.txt")
MALICIOUS_DOMAINS = load_list("malicious_domains.txt")
MALICIOUS_HASHES = load_list("malicious_hashes.txt")
WHITELIST = load_list("whitelist.txt")


def detect_iocs(events):

    alerts = []

    for event in events:

        ip = str(event.get("ip", "")).lower()

        domain = (
            str(event.get("domain", "")) or
            str(event.get("query", "")) or
            str(event.get("host", ""))
        ).lower()

        file_hash = (
            str(event.get("hash", "")) or
            str(event.get("sha256", "")) or
            str(event.get("md5", ""))
        ).lower()

        timestamp = event.get("timestamp", "")

        source = event.get("source", "Unknown")

        user = event.get("user", "")

        host = event.get("host", "")

        # -------------------------
        # Malicious IP
        # -------------------------

        if ip and ip not in WHITELIST and ip in MALICIOUS_IPS:

            alerts.append(

                make_alert(

                    timestamp=timestamp,

                    source="IOC",

                    rule="Malicious IP",

                    mitre="T1071",

                    tactic="Command and Control",

                    technique="Application Layer Protocol",

                    score=100,

                    message=f"Known malicious IP detected: {ip}",

                    ip=ip,

                    user=user,

                    host=host,

                    evidence=event,
                )
            )

        # -------------------------
        # Malicious Domain
        # -------------------------

        if domain and domain not in WHITELIST:

            for bad in MALICIOUS_DOMAINS:

                if bad in domain:

                    alerts.append(

                        make_alert(

                            timestamp=timestamp,

                            source="IOC",

                            rule="Malicious Domain",

                            mitre="T1071.004",

                            tactic="Command and Control",

                            technique="DNS",

                            score=100,

                            message=f"Known malicious domain detected: {domain}",

                            ip=ip,

                            user=user,

                            host=host,

                            evidence=event,
                        )
                    )

                    break

        # -------------------------
        # Malicious Hash
        # -------------------------

        if file_hash and file_hash in MALICIOUS_HASHES:

            alerts.append(

                make_alert(

                    timestamp=timestamp,

                    source="IOC",

                    rule="Malicious Hash",

                    mitre="T1204",

                    tactic="Execution",

                    technique="User Execution",

                    score=100,

                    message=f"Known malicious file hash detected: {file_hash}",

                    ip=ip,

                    user=user,

                    host=host,

                    evidence=event,
                )
            )

    return alerts