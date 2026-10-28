from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from engine.event import Event, AUTH_FAILURE


def make_event(**overrides):
    base = dict(
        timestamp=datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc),
        source="login_failure_detector",
        event_type=AUTH_FAILURE,
        src_ip="192.168.1.50",
    )
    base.update(overrides)
    return Event(**base)


def test_valid_event_is_created():
    event = make_event()
    assert event.src_ip == "192.168.1.50"
    assert event.event_id


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError):
        make_event(timestamp=datetime(2026, 10, 28, 12, 0))


def test_invalid_port_is_rejected():
    with pytest.raises(ValueError):
        make_event(dest_port=70000)


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError):
        make_event(severity_raw="gigantic")


def test_event_is_immutable():
    event = make_event()
    with pytest.raises(FrozenInstanceError):
        event.src_ip = "10.0.0.1"


def test_to_dict_serializes_timestamp():
    assert make_event().to_dict()["timestamp"] == "2026-10-28T12:00:00+00:00"