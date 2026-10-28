import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from engine.alert import Alert


def make_alert(**overrides):
    base = dict(
        rule_id="R001",
        rule_name="Brute force",
        severity="high",
        timestamp=datetime(2026, 6, 26, 13, 1, 25, tzinfo=timezone.utc),
        description="5 failed logins from the same IP",
        event_ids=("event-1", "event-2"),
        mitre_technique="T1110.001",
    )
    base.update(overrides)
    return Alert(**base)


def test_valid_alert_is_created():
    alert = make_alert()
    assert alert.rule_id == "R001"
    assert alert.severity == "high"
    assert alert.alert_id


def test_mitre_technique_is_optional():
    assert make_alert(mitre_technique=None).mitre_technique is None


@pytest.mark.parametrize("technique", ["T1110", "T1110.001", "T1110.003"])
def test_valid_mitre_ids_are_accepted(technique):
    assert make_alert(mitre_technique=technique).mitre_technique == technique


@pytest.mark.parametrize("technique", ["1110", "T111", "T1110.1", "t1110", "T1110.0011"])
def test_invalid_mitre_ids_are_rejected(technique):
    with pytest.raises(ValueError):
        make_alert(mitre_technique=technique)


@pytest.mark.parametrize("severity", ["HIGH", "gigantic", ""])
def test_invalid_severity_is_rejected(severity):
    with pytest.raises(ValueError):
        make_alert(severity=severity)


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError):
        make_alert(timestamp=datetime(2026, 6, 26, 13, 1, 25))


def test_alert_without_evidence_is_rejected():
    with pytest.raises(ValueError):
        make_alert(event_ids=())


def test_missing_rule_id_is_rejected():
    with pytest.raises(ValueError):
        make_alert(rule_id="")


def test_alert_is_immutable():
    alert = make_alert()
    with pytest.raises(FrozenInstanceError):
        alert.severity = "low"


def test_to_dict_is_json_friendly():
    data = make_alert().to_dict()
    assert data["timestamp"] == "2026-06-26T13:01:25+00:00"
    assert data["event_ids"] == ["event-1", "event-2"]
    assert isinstance(data["event_ids"], list)
    json.dumps(data)