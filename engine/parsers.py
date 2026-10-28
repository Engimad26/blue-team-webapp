from __future__ import annotations

import re
import csv
from pathlib import Path
import xml.etree.ElementTree as ET


SSH_FAILED_RE = re.compile(
    r"^(?P<ts>\w+\s+\d+\s+[\d:]+).*(Failed password).*from\s+(?P<ip>[\da-fA-F:.]+).*(?:for(?: invalid user)?\s+(?P<user>\S+))?",
    re.I,
)

SSH_ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w+\s+\d+\s+[\d:]+).*(Accepted password).*from\s+(?P<ip>[\da-fA-F:.]+).*(?:for\s+(?P<user>\S+))?",
    re.I,
)

SSH_INVALID_RE = re.compile(
    r"^(?P<ts>\w+\s+\d+\s+[\d:]+).*(Invalid user)\s+(?P<user>\S+)\s+from\s+(?P<ip>[\da-fA-F:.]+)",
    re.I,
)

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>.*?)\s+HTTP/[^\"]+"\s+(?P<status>\d{3})\s+(?P<size>\S+)',
    re.I,
)

FW_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<action>DROP|ACCEPT)\s+(?P<proto>\S+)\s+(?P<src_ip>\S+)\s+(?P<dst_ip>\S+)\s+(?P<src_port>\d+)\s+(?P<dst_port>\d+)',
    re.I,
)

DNS_RE = re.compile(
    r'^(?P<ts>\S+)\s+query\s+(?P<domain>\S+)\s+from\s+(?P<ip>\S+)$',
    re.I,
)

POWERSHELL_RE = re.compile(
    r"(?P<timestamp>\S+)\s+Host=(?P<host>\S+)\s+User=(?P<user>\S+)\s+EventID=(?P<eventid>\d+)\s+CommandLine=(?P<command>.+)"
)


def parse_auth_line(line: str):
    line = line.strip()

    if not line:
        return None

    if "Invalid user" in line:
        m = SSH_INVALID_RE.search(line)
        if m:
            return {
                "source": "ssh",
                "timestamp": m.group("ts"),
                "status": "Invalid user",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "raw": line,
            }

    if "Failed password" in line:
        m = SSH_FAILED_RE.search(line)
        if m:
            return {
                "source": "ssh",
                "timestamp": m.group("ts"),
                "status": "Failed password",
                "user": m.group("user") or "Unknown",
                "ip": m.group("ip"),
                "raw": line,
            }

    if "Accepted password" in line:
        m = SSH_ACCEPTED_RE.search(line)
        if m:
            return {
                "source": "ssh",
                "timestamp": m.group("ts"),
                "status": "Accepted password",
                "user": m.group("user") or "Unknown",
                "ip": m.group("ip"),
                "raw": line,
            }

    if "Stopped ssh.service" in line:
        return {
            "source": "ssh",
            "timestamp": " ".join(line.split()[:3]),
            "status": "SSH Stopped",
            "user": "",
            "ip": "",
            "raw": line,
        }

    return None


def parse_apache_line(line: str):
    line = line.strip()

    if not line or '"' not in line:
        return None

    m = APACHE_RE.search(line)

    if not m:
        return None

    return {
        "source": "apache",
        "timestamp": m.group("ts"),
        "ip": m.group("ip"),
        "method": m.group("method"),
        "path": m.group("path"),
        "status": int(m.group("status")),
        "raw": line,
    }


def parse_firewall_line(line: str):
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    m = FW_RE.search(line)

    if not m:
        return None

    return {
        "source": "firewall",
        "timestamp": f"{m.group('date')} {m.group('time')}",
        "action": m.group("action").upper(),
        "protocol": m.group("proto"),
        "src_ip": m.group("src_ip"),
        "dst_ip": m.group("dst_ip"),
        "src_port": m.group("src_port"),
        "dst_port": m.group("dst_port"),
        "raw": line,
    }


def parse_dns_line(line: str):
    line = line.strip()

    if not line:
        return None

    m = DNS_RE.search(line)

    if not m:
        return None

    return {
        "source": "dns",
        "timestamp": m.group("ts"),
        "domain": m.group("domain"),
        "ip": m.group("ip"),
        "raw": line,
    }


def parse_powershell_line(line):
    m = POWERSHELL_RE.match(line.strip())

    if not m:
        return None

    return {
        "source": "windows",
        "timestamp": m.group("timestamp"),
        "host": m.group("host"),
        "user": m.group("user"),
        "event_id": m.group("eventid"),
        "command": m.group("command"),
        "raw": line.strip(),
    }


def parse_windows_event(xml: str):
    root = ET.fromstring(xml)

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    event_id = root.find("e:System/e:EventID", ns)

    if event_id is None:
        return None

    event = {
        "source": "windows",
        "event_id": event_id.text or "",
        "raw": xml,
    }

    time_created = root.find("e:System/e:TimeCreated", ns)

    if time_created is not None:
        event["timestamp"] = time_created.attrib.get("SystemTime", "")

    computer = root.find("e:System/e:Computer", ns)

    if computer is not None:
        event["host"] = computer.text or ""

    data = root.find("e:EventData", ns)

    if data is not None:
        for item in data.findall("e:Data", ns):
            key = item.attrib.get("Name")
            if key:
                event[key] = item.text or ""

    return event


# ---------- NEW ----------
def parse_dns_csv(path: Path):
    events = []

    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for row in reader:
            domain = (
                row.get("query")
                or row.get("query{}")
                or row.get("name")
                or row.get("name{}")
                or ""
            )

            ip = (
                row.get("src_ip")
                or row.get("src")
                or ""
            )

            events.append({
                "source": "dns",
                "timestamp": row.get("_time", ""),
                "domain": str(domain),
                "ip": ip,
                "raw": str(row),
            })

    return events

def parse_firewall_csv(path: Path):
    events = []

    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for row in reader:
            events.append({
                "source": "firewall",
                "timestamp": row.get("_time", ""),
                "action": (
            row.get("vendor_action")
            or row.get("action")
            or row.get("Action")
            or ""
        ).upper(),
                "src_ip": row.get("src_ip") or row.get("src") or "",
                "dst_ip": row.get("dest_ip") or row.get("dest") or "",
                "src_port": row.get("src_port") or "",
                "dst_port": row.get("dest_port") or row.get("dst_port") or "",
                "protocol": row.get("transport") or row.get("protocol") or "",
                "raw": str(row),
            })

    return events
def parse_windows_csv(path: Path):
    events = []

    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for row in reader:
            events.append({
                "source": "windows",
                "timestamp": row.get("_time", ""),
                "event_id": row.get("EventCode", ""),
                "user": row.get("Account_Name")
                        or row.get("Target_User_Name")
                        or row.get("User_Name", ""),
                "host": row.get("ComputerName")
                        or row.get("host", ""),
                "ip": row.get("Source_Network_Address")
                        or row.get("Client_Address")
                        or row.get("src_ip", ""),
                "process": row.get("Process_Name")
                        or row.get("New_Process_Name", ""),
                "command": row.get("Process_Command_Line", ""),
                "message": row.get("Message", ""),
                "raw": str(row),
            })

    return events

def parse_uploaded_file(path: Path):
    name = path.name.lower()

    # EVTX
    if name.endswith(".evtx"):
        try:
            from Evtx.Evtx import Evtx
        except ModuleNotFoundError as exc:
            raise ModuleNotFoundError(
                "python-evtx is required to parse EVTX files"
            ) from exc

        events = []

        with Evtx(str(path)) as log:
            for record in log.records():
                evt = parse_windows_event(record.xml())
                if evt:
                    events.append(evt)

        return events

    # CSV files
    if name.endswith(".csv"):
        if "dns" in name:
            return parse_dns_csv(path)

        elif "firewall" in name:
            return parse_firewall_csv(path)

        else:
            return parse_windows_csv(path)

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        lines = fh.readlines()

    events = []

    if "dns" in name:
        for line in lines:
            evt = parse_dns_line(line)
            if evt:
                events.append(evt)

    elif "auth.log" in name:
        for line in lines:
            evt = parse_auth_line(line)
            if evt:
                events.append(evt)

    elif "access.log" in name or "apache" in name:
        for line in lines:
            evt = parse_apache_line(line)
            if evt:
                events.append(evt)

    elif "firewall" in name:
        for line in lines:
            evt = parse_firewall_line(line)
            if evt:
                events.append(evt)

    elif "powershell" in name:
        for line in lines:
            evt = parse_powershell_line(line)
            if evt:
                events.append(evt)

    else:
        for line in lines:
            for parser in (
                parse_dns_line,
                parse_auth_line,
                parse_apache_line,
                parse_firewall_line,
            ):
                evt = parser(line)
                if evt:
                    events.append(evt)
                    break

    return events
