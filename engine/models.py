from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    timestamp: str = ""
    source: str = ""
    host: str = ""
    user: str = ""
    ip: str = ""
    action: str = ""
    severity: str = ""
    score: int = 0
    rule: str = ""
    mitre: str = ""
    message: str = ""
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    id: str
    timestamp: str
    source: str
    rule: str
    mitre: str
    score: int
    severity: str
    message: str
    ip: str = ""
    user: str = ""
    host: str = ""
    incident_id: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
