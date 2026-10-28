from collections import Counter
from .common import make_alert


def detect_windows_failed_login(events, threshold=3):
    counter = Counter()
    last_ts = {}

    for e in events:
        if e.get("source") == "windows" and str(e.get("event_id")) == "4625":
            user = e.get("user", "Unknown")
            counter[user] += 1
            last_ts[user] = e.get("timestamp", "")

    alerts = []

    for user, count in counter.items():
        if count >= threshold:
            alerts.append(
                make_alert(
                    timestamp=last_ts[user],
                    source="Windows",
                    rule="Failed login burst",
                    mitre="T1110",
                    tactic="Credential Access",
                    technique="Brute Force",
                    score=90,
                    message=f"{count} failed logins for {user}",
                    user=user,
                )
            )

    return alerts


def detect_windows_success_login(events):
    counter = Counter()
    last_ts = {}

    for e in events:
        if e.get("source") == "windows" and str(e.get("event_id")) == "4624":
            user = e.get("user", "Unknown")
            counter[user] += 1
            last_ts[user] = e.get("timestamp", "")

    alerts = []

    for user, count in counter.items():
        alerts.append(
            make_alert(
                timestamp=last_ts[user],
                source="Windows",
                rule="Successful login",
                mitre="T1078",
                tactic="Credential Access",
                technique="Valid Accounts",
                score=30,
                message=f"{user} logged in successfully ({count} times)",
                user=user,
            )
        )

    return alerts


def detect_admin_login(events):
    alerts = []

    for e in events:
        if e.get("source") == "windows" and str(e.get("event_id")) == "4672":

            alerts.append(
                make_alert(
                    timestamp=e.get("timestamp", ""),
                    source="Windows",
                    rule="Special privileges assigned",
                    mitre="T1078",
                    tactic="Privilege Escalation",
                    technique="Valid Accounts",
                    score=85,
                    message=f"Administrative privileges assigned to {e.get('user','Unknown')}",
                    user=e.get("user", ""),
                )
            )

    return alerts


def detect_log_cleared(events):
    alerts = []

    for e in events:
        if e.get("source") == "windows" and str(e.get("event_id")) == "1102":

            alerts.append(
                make_alert(
                    timestamp=e.get("timestamp", ""),
                    source="Windows",
                    rule="Security Log Cleared",
                    mitre="T1070.001",
                    tactic="Defense Evasion",
                    technique="Clear Windows Event Logs",
                    score=100,
                    message="Windows Security Log was cleared",
                    host=e.get("host", ""),
                )
            )

    return alerts


def detect_new_user(events):
    alerts = []

    for e in events:
        if e.get("source") == "windows" and str(e.get("event_id")) == "4720":

            alerts.append(
                make_alert(
                    timestamp=e.get("timestamp", ""),
                    source="Windows",
                    rule="New User Created",
                    mitre="T1136",
                    tactic="Persistence",
                    technique="Create Account",
                    score=80,
                    message=f"New account created: {e.get('user','Unknown')}",
                    user=e.get("user", ""),
                )
            )

    return alerts


def detect_process_creation(events):
    suspicious = [
        "powershell",
        "cmd.exe",
        "certutil",
        "rundll32",
        "regsvr32",
        "wmic",
        "mshta",
        "bitsadmin",
        "cscript",
        "wscript",
        "mimikatz",
    ]

    alerts = []

    for e in events:
        if str(e.get("event_id")) != "4688":
            continue

        process = (e.get("process") or "").lower()
        command = (e.get("command") or "").lower()

        if any(x in process for x in suspicious) or any(x in command for x in suspicious):

            alerts.append(
                make_alert(
                    timestamp=e.get("timestamp", ""),
                    source="Windows",
                    rule="Suspicious Process",
                    mitre="T1059",
                    tactic="Execution",
                    technique="Command and Scripting Interpreter",
                    score=90,
                    message=f"Suspicious process: {process}",
                    host=e.get("host", ""),
                    user=e.get("user", ""),
                )
            )

    return alerts