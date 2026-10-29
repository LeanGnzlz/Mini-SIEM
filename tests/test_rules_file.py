from pathlib import Path

from adapters.login_detector_adapter import parse_auth_log
from adapters.network_scanner_adapter import parse_scan_report
from engine.evaluator import run_rules
from engine.rule import load_rules

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"

SCAN_WITH_SMB = {
    "target": "127.0.0.1",
    "scan_duration": 21.21,
    "completed": "2026-06-25 13:58:39",
    "open_ports": [
        {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
        {"port": 445, "service": "SMB", "banner": "Not applicable"},
    ],
}

SCAN_WITHOUT_SENSITIVE_PORTS = {
    "target": "127.0.0.1",
    "scan_duration": 5.0,
    "completed": "2026-06-25 13:58:39",
    "open_ports": [
        {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
    ],
}

LOG_WITH_COMPROMISE = [
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

NORMAL_LOG = [
    "2026-06-26 10:00:01 | SUCCESS_LOGIN | leandro | 192.168.1.20",
    "2026-06-26 10:05:10 | SUCCESS_LOGIN | maria | 192.168.1.30",
]

FOUR_FAILURES_LOG = [
    "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:22 | FAILED_LOGIN | admin | 185.23.44.10",
]


def shipped_rules():
    return load_rules(RULES_PATH)


def build_events(scan_report=None, log_lines=()):
    events = []
    if scan_report is not None:
        events.extend(parse_scan_report(scan_report))
    parsed, rejected = parse_auth_log(log_lines)
    assert rejected == []
    events.extend(parsed)
    return events


def test_rules_file_contains_the_four_expected_rules():
    assert [rule.rule_id for rule in shipped_rules()] == ["R001", "R002", "R003", "R004"]


def test_all_shipped_rules_are_enabled():
    assert all(rule.enabled for rule in shipped_rules())


def test_rule_types():
    types = {rule.rule_id: rule.rule_type for rule in shipped_rules()}
    assert types == {
        "R001": "signature",
        "R002": "threshold",
        "R003": "sequence",
        "R004": "threshold",
    }


def test_rule_severities():
    severities = {rule.rule_id: rule.severity for rule in shipped_rules()}
    assert severities == {
        "R001": "high",
        "R002": "medium",
        "R003": "high",
        "R004": "medium",
    }


def test_mitre_mapping_and_the_port_rule_has_none():
    techniques = {rule.rule_id: rule.mitre_technique for rule in shipped_rules()}
    assert techniques == {
        "R001": None,
        "R002": "T1110.001",
        "R003": "T1110",
        "R004": "T1110.003",
    }


def test_full_scenario_triggers_every_rule_in_time_order():
    events = build_events(SCAN_WITH_SMB, LOG_WITH_COMPROMISE)
    alerts = run_rules(shipped_rules(), events)
    assert [alert.rule_id for alert in alerts] == ["R001", "R002", "R003", "R002", "R004"]


def test_normal_activity_triggers_no_alerts():
    events = build_events(SCAN_WITHOUT_SENSITIVE_PORTS, NORMAL_LOG)
    assert run_rules(shipped_rules(), events) == []


def test_four_failures_stay_below_every_threshold():
    events = build_events(log_lines=FOUR_FAILURES_LOG)
    assert run_rules(shipped_rules(), events) == []