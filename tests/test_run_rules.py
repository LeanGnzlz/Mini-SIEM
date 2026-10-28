import json
from datetime import datetime, timedelta, timezone

from engine.evaluator import EVALUATORS, run_rules
from engine.event import Event, AUTH_FAILURE, AUTH_SUCCESS, PORT_OPEN
from engine.ingest import ingest
from engine.rule import RULE_TYPES, Rule, SequenceStep, load_rules

BASE_TIME = datetime(2026, 6, 26, 10, 0, 0, tzinfo=timezone.utc)
IP_A = "185.23.44.10"


def make_event(seconds, **overrides):
    base = dict(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source="login_failure_detector",
        event_type=AUTH_FAILURE,
        src_ip=IP_A,
        user="admin",
    )
    base.update(overrides)
    return Event(**base)


def port_event(seconds):
    return make_event(
        seconds,
        source="network_scanner",
        event_type=PORT_OPEN,
        src_ip=None,
        user=None,
        dest_ip="127.0.0.1",
        dest_port=445,
    )


def attack(offset=0):
    events = [make_event(offset + seconds) for seconds in (0, 2, 4, 6, 8)]
    events.append(make_event(offset + 10, event_type=AUTH_SUCCESS))
    return events


def signature_rule(**overrides):
    base = dict(
        rule_id="R001",
        name="Sensitive port open",
        rule_type="signature",
        severity="high",
        event_type=PORT_OPEN,
        dest_ports=(445,),
    )
    base.update(overrides)
    return Rule(**base)


def threshold_rule(**overrides):
    base = dict(
        rule_id="R002",
        name="Brute force",
        rule_type="threshold",
        severity="medium",
        mitre_technique="T1110.001",
        event_type=AUTH_FAILURE,
        group_by="src_ip",
        window_seconds=300,
        threshold=5,
    )
    base.update(overrides)
    return Rule(**base)


def sequence_rule(**overrides):
    base = dict(
        rule_id="R003",
        name="Successful brute force",
        rule_type="sequence",
        severity="high",
        mitre_technique="T1110",
        group_by="src_ip",
        window_seconds=300,
        steps=(SequenceStep(AUTH_FAILURE, 5), SequenceStep(AUTH_SUCCESS)),
    )
    base.update(overrides)
    return Rule(**base)


def test_each_rule_type_is_dispatched_to_its_evaluator():
    events = attack() + [port_event(30)]
    rules = [signature_rule(), threshold_rule(), sequence_rule()]
    alerts = run_rules(rules, events)
    assert sorted(alert.rule_id for alert in alerts) == ["R001", "R002", "R003"]


def test_disabled_rules_are_skipped():
    rules = [threshold_rule(enabled=False), sequence_rule()]
    alerts = run_rules(rules, attack())
    assert [alert.rule_id for alert in alerts] == ["R003"]


def test_only_disabled_rules_produce_no_alerts():
    assert run_rules([threshold_rule(enabled=False)], attack()) == []


def test_alerts_from_different_rules_are_sorted_by_time():
    late_failures = [make_event(seconds) for seconds in (100, 102, 104, 106, 108)]
    events = late_failures + [port_event(5)]
    alerts = run_rules([threshold_rule(), signature_rule()], events)
    assert [alert.rule_id for alert in alerts] == ["R001", "R002"]


def test_the_same_events_can_trigger_several_rules():
    alerts = run_rules([threshold_rule(), sequence_rule()], attack())
    assert [alert.rule_id for alert in alerts] == ["R002", "R003"]
    assert set(alerts[0].event_ids) < set(alerts[1].event_ids)


def test_alerts_at_the_same_time_keep_the_rule_order():
    rules = [signature_rule(rule_id="R009"), signature_rule(rule_id="R001")]
    alerts = run_rules(rules, [port_event(0)])
    assert [alert.rule_id for alert in alerts] == ["R009", "R001"]


def test_no_rules_produce_no_alerts():
    assert run_rules([], attack()) == []


def test_no_events_produce_no_alerts():
    rules = [signature_rule(), threshold_rule(), sequence_rule()]
    assert run_rules(rules, []) == []


def test_every_rule_type_has_an_evaluator():
    assert set(EVALUATORS) == RULE_TYPES


REAL_SCAN_REPORT = {
    "target": "127.0.0.1",
    "scan_duration": 21.21,
    "completed": "2026-06-25 13:58:39",
    "open_ports": [
        {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
        {"port": 445, "service": "SMB", "banner": "Not applicable"},
    ],
}

AUTH_LOG_WITH_COMPROMISE = [
    "2026-06-26 10:00:01 | SUCCESS_LOGIN | leandro | 192.168.1.20",
    "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:22 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:25 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:02:00 | SUCCESS_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:05:10 | SUCCESS_LOGIN | maria | 192.168.1.30",
    "2026-06-26 11:00:01 | FAILED_LOGIN | admin | 10.0.0.50",
    "2026-06-26 11:00:03 | FAILED_LOGIN | maria | 10.0.0.50",
    "2026-06-26 11:00:05 | FAILED_LOGIN | juan | 10.0.0.50",
    "2026-06-26 11:00:07 | FAILED_LOGIN | pedro | 10.0.0.50",
    "2026-06-26 11:00:09 | FAILED_LOGIN | carlos | 10.0.0.50",
]


def rules_yaml(sequence_enabled=True):
    enabled = "true" if sequence_enabled else "false"
    return f"""
rules:
  - id: R001
    name: Sensitive port open
    type: signature
    severity: high
    event_type: port_open
    dest_ports: [445, 3389]
  - id: R002
    name: Brute force
    type: threshold
    severity: medium
    mitre: T1110.001
    event_type: auth_failure
    group_by: src_ip
    window_seconds: 300
    threshold: 5
  - id: R003
    name: Successful brute force
    type: sequence
    severity: high
    mitre: T1110
    group_by: src_ip
    window_seconds: 300
    enabled: {enabled}
    steps:
      - event_type: auth_failure
        count: 5
      - event_type: auth_success
  - id: R004
    name: Password spraying
    type: threshold
    severity: medium
    mitre: T1110.003
    event_type: auth_failure
    group_by: src_ip
    window_seconds: 300
    threshold: 5
    distinct: user
"""


def run_pipeline(tmp_path, sequence_enabled=True):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(REAL_SCAN_REPORT), encoding="utf-8")
    log = tmp_path / "auth.log"
    log.write_text("\n".join(AUTH_LOG_WITH_COMPROMISE), encoding="utf-8")
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(rules_yaml(sequence_enabled), encoding="utf-8")
    events, rejected = ingest(scan_report_paths=[scan], auth_log_paths=[log])
    alerts = run_rules(load_rules(rules_file), events)
    return events, rejected, alerts


def test_end_to_end_all_rules_fire_in_time_order(tmp_path):
    events, rejected, alerts = run_pipeline(tmp_path)
    assert rejected == []
    assert len(events) == 15
    assert [alert.rule_id for alert in alerts] == ["R001", "R002", "R003", "R002", "R004"]


def test_end_to_end_alert_details(tmp_path):
    events, rejected, alerts = run_pipeline(tmp_path)
    smb_event = [event for event in events if event.dest_port == 445][0]
    assert alerts[0].event_ids == (smb_event.event_id,)
    assert alerts[0].timestamp == smb_event.timestamp
    assert alerts[2].severity == "high"
    assert "185.23.44.10" in alerts[2].description
    assert len(alerts[2].event_ids) == 6
    assert alerts[4].mitre_technique == "T1110.003"
    assert "10.0.0.50" in alerts[4].description


def test_end_to_end_a_rule_disabled_in_the_yaml_does_not_fire(tmp_path):
    events, rejected, alerts = run_pipeline(tmp_path, sequence_enabled=False)
    assert [alert.rule_id for alert in alerts] == ["R001", "R002", "R002", "R004"]