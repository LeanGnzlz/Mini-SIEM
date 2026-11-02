import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from engine.alert import Alert
from engine.evaluator import run_rules
from engine.identity import assign_stable_alert_ids, stable_alert_id
from engine.ingest import ingest
from engine.rule import load_rules

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"
HEX_DIGITS = set("0123456789abcdef")

SCAN_REPORT = {
    "target": "127.0.0.1",
    "scan_duration": 21.21,
    "completed": "2026-06-25 13:58:39",
    "open_ports": [
        {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
        {"port": 445, "service": "SMB", "banner": "Not applicable"},
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

FIVE_FAILURES = [
    "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:22 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:25 | FAILED_LOGIN | admin | 185.23.44.10",
]

FIVE_FAILURES_THEN_SUCCESS = FIVE_FAILURES + [
    "2026-06-26 10:02:00 | SUCCESS_LOGIN | admin | 185.23.44.10",
]


def make_alert(**overrides):
    base = dict(
        rule_id="R002",
        rule_name="Brute force",
        severity="medium",
        timestamp=datetime(2026, 6, 26, 13, 1, 25, tzinfo=timezone.utc),
        description="5 failed logins",
        event_ids=("event-1", "event-2"),
        mitre_technique="T1110.001",
    )
    base.update(overrides)
    return Alert(**base)


def ids(alerts):
    return [alert.alert_id for alert in alerts]


def analyze(tmp_path, name, log_lines, with_scan=False):
    folder = tmp_path / name
    folder.mkdir()
    log = folder / "auth.log"
    log.write_text("\n".join(log_lines), encoding="utf-8")
    scans = []
    if with_scan:
        scan = folder / "scan.json"
        scan.write_text(json.dumps(SCAN_REPORT), encoding="utf-8")
        scans.append(str(scan))
    events, rejected = ingest(scan_report_paths=scans, auth_log_paths=[str(log)])
    assert rejected == []
    return run_rules(load_rules(RULES_PATH), events)


def test_stable_alert_id_is_a_sha256_hex_digest():
    value = stable_alert_id("R002", ("event-1", "event-2"))
    assert len(value) == 64
    assert set(value) <= HEX_DIGITS


def test_same_rule_and_evidence_give_the_same_id():
    assert stable_alert_id("R002", ("a", "b")) == stable_alert_id("R002", ("a", "b"))


def test_a_different_rule_changes_the_id():
    assert stable_alert_id("R002", ("a", "b")) != stable_alert_id("R004", ("a", "b"))


def test_different_evidence_changes_the_id():
    assert stable_alert_id("R002", ("a", "b")) != stable_alert_id("R002", ("a", "c"))


def test_the_order_of_the_evidence_matters():
    assert stable_alert_id("R002", ("a", "b")) != stable_alert_id("R002", ("b", "a"))


def test_separator_characters_cannot_make_two_alerts_collide():
    assert stable_alert_id("R002", ("a", "b")) != stable_alert_id("R002", ("a,b",))
    assert stable_alert_id("a", ("b",)) != stable_alert_id("a,b", ())


def test_assign_replaces_the_random_id():
    original = make_alert()
    result = assign_stable_alert_ids([original])[0]
    assert result.alert_id != original.alert_id
    assert result.alert_id == stable_alert_id("R002", ("event-1", "event-2"))


def test_original_alerts_are_not_modified():
    original = make_alert()
    before = original.alert_id
    assign_stable_alert_ids([original])
    assert original.alert_id == before


def test_all_other_fields_are_preserved():
    original = make_alert()
    result = assign_stable_alert_ids([original])[0]
    assert replace(result, alert_id=original.alert_id) == original


def test_equal_alerts_get_the_same_id_even_if_their_random_ids_differ():
    first, second = make_alert(), make_alert()
    assert first.alert_id != second.alert_id
    result = assign_stable_alert_ids([first, second])
    assert result[0].alert_id == result[1].alert_id


def test_different_alerts_get_different_ids():
    alerts = [make_alert(), make_alert(event_ids=("event-3",))]
    result = assign_stable_alert_ids(alerts)
    assert result[0].alert_id != result[1].alert_id


def test_severity_and_description_are_not_part_of_the_identity():
    first = assign_stable_alert_ids([make_alert(severity="low", description="one")])[0]
    second = assign_stable_alert_ids([make_alert(severity="high", description="two")])[0]
    assert first.alert_id == second.alert_id


def test_the_order_of_the_alerts_is_preserved():
    alerts = [
        make_alert(event_ids=("a",)),
        make_alert(event_ids=("b",)),
        make_alert(event_ids=("c",)),
    ]
    result = assign_stable_alert_ids(alerts)
    assert [alert.event_ids for alert in result] == [("a",), ("b",), ("c",)]


def test_empty_list():
    assert assign_stable_alert_ids([]) == []


def test_the_same_analysis_gives_the_same_alert_ids(tmp_path):
    first = analyze(tmp_path, "first", LOG_WITH_COMPROMISE, with_scan=True)
    second = analyze(tmp_path, "second", LOG_WITH_COMPROMISE, with_scan=True)
    assert len(first) == 5
    assert ids(first) == ids(second)


def test_every_alert_of_a_run_has_a_different_id(tmp_path):
    alerts = analyze(tmp_path, "run", LOG_WITH_COMPROMISE, with_scan=True)
    assert len(alerts) == 5
    assert len(set(ids(alerts))) == 5
    assert all(len(value) == 64 for value in ids(alerts))


def test_two_alerts_of_the_same_rule_get_different_ids(tmp_path):
    alerts = analyze(tmp_path, "run", LOG_WITH_COMPROMISE)
    brute_force = [alert for alert in alerts if alert.rule_id == "R002"]
    assert len(brute_force) == 2
    assert brute_force[0].alert_id != brute_force[1].alert_id


def test_the_same_evidence_under_two_rules_gives_different_ids(tmp_path):
    alerts = analyze(tmp_path, "run", LOG_WITH_COMPROMISE)
    spraying = [alert for alert in alerts if alert.rule_id == "R004"][0]
    brute_force = [
        alert
        for alert in alerts
        if alert.rule_id == "R002" and alert.event_ids == spraying.event_ids
    ]
    assert len(brute_force) == 1
    assert brute_force[0].alert_id != spraying.alert_id


def test_a_growing_log_keeps_the_ids_of_the_old_alerts(tmp_path):
    first = analyze(tmp_path, "first", FIVE_FAILURES)
    second = analyze(tmp_path, "second", FIVE_FAILURES_THEN_SUCCESS)
    assert [alert.rule_id for alert in first] == ["R002"]
    assert [alert.rule_id for alert in second] == ["R002", "R003"]
    assert first[0].alert_id == second[0].alert_id