from datetime import datetime, timezone

import pytest

from adapters.network_scanner_adapter import parse_scan_report
from engine.event import Event, AUTH_FAILURE, PORT_OPEN
from engine.evaluator import evaluate_signature
from engine.rule import Rule


def make_event(**overrides):
    base = dict(
        timestamp=datetime(2026, 6, 26, 15, 30, tzinfo=timezone.utc),
        source="network_scanner",
        event_type=PORT_OPEN,
        dest_ip="127.0.0.1",
        dest_port=445,
    )
    base.update(overrides)
    return Event(**base)


def make_rule(**overrides):
    base = dict(
        rule_id="R001",
        name="Sensitive port open",
        rule_type="signature",
        severity="high",
        mitre_technique="T1133",
        event_type=PORT_OPEN,
        dest_ports=(3389, 445),
    )
    base.update(overrides)
    return Rule(**base)


def test_matching_event_creates_one_alert():
    alerts = evaluate_signature(make_rule(), [make_event()])
    assert len(alerts) == 1


def test_alert_takes_rule_data_and_event_timestamp():
    event = make_event()
    alert = evaluate_signature(make_rule(), [event])[0]
    assert alert.rule_id == "R001"
    assert alert.rule_name == "Sensitive port open"
    assert alert.severity == "high"
    assert alert.mitre_technique == "T1133"
    assert alert.timestamp == event.timestamp
    assert alert.event_ids == (event.event_id,)


def test_event_with_other_type_is_ignored():
    event = make_event(event_type=AUTH_FAILURE, src_ip="10.0.0.5", dest_port=None)
    assert evaluate_signature(make_rule(), [event]) == []


@pytest.mark.parametrize(
    "port, expected",
    [(3389, 1), (445, 1), (22, 0), (None, 0)],
    ids=["listed-3389", "listed-445", "not-listed", "no-port"],
)
def test_port_filter(port, expected):
    alerts = evaluate_signature(make_rule(), [make_event(dest_port=port)])
    assert len(alerts) == expected


def test_rule_without_ports_matches_any_port():
    events = [make_event(dest_port=22), make_event(dest_port=None)]
    alerts = evaluate_signature(make_rule(dest_ports=()), events)
    assert len(alerts) == 2


def test_each_matching_event_gets_its_own_alert():
    events = [
        make_event(dest_port=445),
        make_event(dest_port=22),
        make_event(dest_port=3389),
    ]
    alerts = evaluate_signature(make_rule(), events)
    assert len(alerts) == 2
    assert alerts[0].event_ids == (events[0].event_id,)
    assert alerts[1].event_ids == (events[2].event_id,)


def test_evidence_is_an_immutable_tuple():
    alert = evaluate_signature(make_rule(), [make_event()])[0]
    assert isinstance(alert.event_ids, tuple)


def test_description_falls_back_to_rule_name():
    alert = evaluate_signature(make_rule(), [make_event()])[0]
    assert alert.description == "Sensitive port open"


def test_description_from_the_rule_is_used():
    rule = make_rule(description="Remote access port exposed")
    alert = evaluate_signature(rule, [make_event()])[0]
    assert alert.description == "Remote access port exposed"


def test_empty_event_list_returns_no_alerts():
    assert evaluate_signature(make_rule(), []) == []


def test_non_signature_rule_is_rejected():
    threshold_rule = Rule(
        rule_id="R002",
        name="Brute force",
        rule_type="threshold",
        severity="medium",
        event_type=AUTH_FAILURE,
        group_by="src_ip",
        window_seconds=300,
        threshold=5,
    )
    with pytest.raises(ValueError, match="not a signature rule"):
        evaluate_signature(threshold_rule, [make_event()])


REAL_SCAN_REPORT = {
    "target": "127.0.0.1",
    "scan_duration": 21.21,
    "completed": "2026-06-25 13:58:39",
    "open_ports": [
        {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
        {"port": 445, "service": "SMB", "banner": "Not applicable"},
    ],
}


def test_signature_rule_on_real_scanner_report():
    events = parse_scan_report(REAL_SCAN_REPORT)
    rule = make_rule(dest_ports=(445, 3389))
    alerts = evaluate_signature(rule, events)
    assert len(alerts) == 1
    assert alerts[0].event_ids == (events[1].event_id,)
    assert alerts[0].timestamp == events[1].timestamp


def test_signature_rule_with_no_match_on_real_scanner_report():
    events = parse_scan_report(REAL_SCAN_REPORT)
    rule = make_rule(dest_ports=(3389,))
    assert evaluate_signature(rule, events) == []