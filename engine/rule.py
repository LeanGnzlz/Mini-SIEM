from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from engine.alert import MITRE_PATTERN
from engine.event import VALID_EVENT_TYPES, VALID_SEVERITIES

RULE_TYPES = {"signature", "threshold", "sequence"}
GROUP_FIELDS = {"src_ip", "dest_ip", "user"}
DISTINCT_FIELDS = {"src_ip", "dest_ip", "dest_port", "user"}
TYPE_SPECIFIC_FIELDS = (
    "event_type",
    "group_by",
    "window_seconds",
    "threshold",
    "distinct",
    "dest_ports",
    "steps",
)
YAML_FIELDS = {
    "id": "rule_id",
    "name": "name",
    "type": "rule_type",
    "severity": "severity",
    "description": "description",
    "mitre": "mitre_technique",
    "enabled": "enabled",
    "event_type": "event_type",
    "group_by": "group_by",
    "window_seconds": "window_seconds",
    "threshold": "threshold",
    "distinct": "distinct",
    "dest_ports": "dest_ports",
    "steps": "steps",
}
REQUIRED_YAML_FIELDS = ("id", "name", "type", "severity")


def is_positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def is_valid_port(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def is_one_of(value, valid) -> bool:
    return isinstance(value, str) and value in valid


@dataclass(frozen=True)
class SequenceStep:
    event_type: str
    count: int = 1

    def __post_init__(self):
        if not is_one_of(self.event_type, VALID_EVENT_TYPES):
            raise ValueError(f"unknown event type in step: {self.event_type}")
        if not is_positive_int(self.count):
            raise ValueError("step count must be a positive integer")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    rule_type: str
    severity: str
    description: str = ""
    mitre_technique: Optional[str] = None
    enabled: bool = True
    event_type: Optional[str] = None
    group_by: Optional[str] = None
    window_seconds: Optional[int] = None
    threshold: Optional[int] = None
    distinct: Optional[str] = None
    dest_ports: tuple = ()
    steps: tuple = ()

    def __post_init__(self):
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise ValueError("rule id is required")
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("rule name is required")
        if not is_one_of(self.rule_type, RULE_TYPES):
            raise ValueError(f"unknown rule type: {self.rule_type}")
        if not is_one_of(self.severity, VALID_SEVERITIES):
            raise ValueError(f"invalid severity: {self.severity}")
        if self.mitre_technique is not None and not (
            isinstance(self.mitre_technique, str) and MITRE_PATTERN.match(self.mitre_technique)
        ):
            raise ValueError(f"invalid MITRE technique id: {self.mitre_technique}")
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be true or false")
        validators = {
            "signature": self._validate_signature,
            "threshold": self._validate_threshold,
            "sequence": self._validate_sequence,
        }
        validators[self.rule_type]()

    def _check_unused(self, allowed):
        for name in TYPE_SPECIFIC_FIELDS:
            if name not in allowed and getattr(self, name) not in (None, ()):
                raise ValueError(f"field '{name}' does not apply to {self.rule_type} rules")

    def _require_event_type(self):
        if not is_one_of(self.event_type, VALID_EVENT_TYPES):
            raise ValueError(f"unknown event type: {self.event_type}")

    def _require_group_by(self):
        if not is_one_of(self.group_by, GROUP_FIELDS):
            raise ValueError(f"group_by must be one of {sorted(GROUP_FIELDS)}")

    def _require_window(self):
        if not is_positive_int(self.window_seconds):
            raise ValueError("window_seconds must be a positive integer")

    def _validate_signature(self):
        self._check_unused({"event_type", "dest_ports"})
        self._require_event_type()
        if not isinstance(self.dest_ports, tuple):
            raise ValueError("dest_ports must be a tuple")
        for port in self.dest_ports:
            if not is_valid_port(port):
                raise ValueError(f"invalid port in dest_ports: {port}")

    def _validate_threshold(self):
        self._check_unused({"event_type", "group_by", "window_seconds", "threshold", "distinct"})
        self._require_event_type()
        self._require_group_by()
        self._require_window()
        if not is_positive_int(self.threshold):
            raise ValueError("threshold must be a positive integer")
        if self.distinct is not None:
            if not is_one_of(self.distinct, DISTINCT_FIELDS):
                raise ValueError(f"distinct must be one of {sorted(DISTINCT_FIELDS)}")
            if self.distinct == self.group_by:
                raise ValueError("distinct must differ from group_by")

    def _validate_sequence(self):
        self._check_unused({"group_by", "window_seconds", "steps"})
        self._require_group_by()
        self._require_window()
        if not isinstance(self.steps, tuple) or len(self.steps) < 2:
            raise ValueError("a sequence rule needs at least 2 steps")
        if not all(isinstance(step, SequenceStep) for step in self.steps):
            raise ValueError("steps must be SequenceStep objects")


def as_list(value, name):
    if not isinstance(value, list):
        raise ValueError(f"'{name}' must be a list")
    return value


def build_step(entry) -> SequenceStep:
    if not isinstance(entry, dict):
        raise ValueError("each step must be a mapping of fields")
    unknown = set(entry) - {"event_type", "count"}
    if unknown:
        raise ValueError(f"unknown field(s) in step: {', '.join(sorted(map(str, unknown)))}")
    if "event_type" not in entry:
        raise ValueError("step is missing 'event_type'")
    return SequenceStep(**entry)


def build_rule(entry) -> Rule:
    if not isinstance(entry, dict):
        raise ValueError("each rule must be a mapping of fields")
    unknown = set(entry) - set(YAML_FIELDS)
    if unknown:
        raise ValueError(f"unknown field(s) in rule: {', '.join(sorted(map(str, unknown)))}")
    missing = [key for key in REQUIRED_YAML_FIELDS if key not in entry]
    if missing:
        raise ValueError(f"missing field(s) in rule: {', '.join(missing)}")
    kwargs = {YAML_FIELDS[key]: value for key, value in entry.items()}
    if "dest_ports" in kwargs:
        kwargs["dest_ports"] = tuple(as_list(kwargs["dest_ports"], "dest_ports"))
    if "steps" in kwargs:
        kwargs["steps"] = tuple(build_step(step) for step in as_list(kwargs["steps"], "steps"))
    return Rule(**kwargs)


def load_rules(path) -> list[Rule]:
    with open(Path(path), encoding="utf-8") as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as error:
            raise ValueError(f"invalid YAML in rules file: {error}") from error
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("rules file must contain a 'rules' list")
    rules = []
    seen = set()
    for position, entry in enumerate(data["rules"], start=1):
        try:
            rule = build_rule(entry)
        except ValueError as error:
            raise ValueError(f"rule #{position}: {error}") from error
        if rule.rule_id in seen:
            raise ValueError(f"duplicate rule id: {rule.rule_id}")
        seen.add(rule.rule_id)
        rules.append(rule)
    return rules