import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

from engine.event import VALID_SEVERITIES

MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    description: str
    event_ids: tuple
    mitre_technique: Optional[str] = None
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        if not self.rule_id:
            raise ValueError("rule_id is required")
        if not self.rule_name:
            raise ValueError("rule_name is required")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware (UTC)")
        if not self.event_ids:
            raise ValueError("an alert needs at least one event as evidence")
        if self.mitre_technique is not None and not MITRE_PATTERN.match(self.mitre_technique):
            raise ValueError(f"invalid MITRE technique id: {self.mitre_technique}")

    def to_dict(self) -> dict:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_ids"] = list(self.event_ids)
        return data