from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
import uuid


AUTH_FAILURE = "auth_failure"
AUTH_SUCCESS = "auth_success"
PORT_OPEN = "port_open"

VALID_EVENT_TYPES = {AUTH_FAILURE, AUTH_SUCCESS, PORT_OPEN}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source: str
    event_type: str
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    user: Optional[str] = None
    severity_raw: Optional[str] = None
    raw_data: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        if not self.source:
            raise ValueError("source is required")
        if not self.event_type:
            raise ValueError("event_type is required")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware (UTC)")
        if self.dest_port is not None and not (0 <= self.dest_port <= 65535):
            raise ValueError(f"invalid port: {self.dest_port}")
        if self.severity_raw is not None and self.severity_raw.lower() not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity_raw}")

    def to_dict(self) -> dict:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data