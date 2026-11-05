import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.alert import Alert
from engine.evaluator import run_rules
from engine.event import Event
from engine.ingest import ingest
from engine.rule import load_rules
from storage.db import connect
from storage.repository import load_alerts, load_events, parse_utc, save_run

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"
BASE_TIME = datetime(2026, 6, 26, 10, 0, 0, tzinfo=timezone.utc)

HOSTILE_VALUES = [
    "x'; DROP TABLE events; --",
    "' OR '1'='1",
    'Robert"); DROP TABLE alerts; --',
]

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

EVENT_DAMAGE = [
    ("timestamp", "2026-06-26T10:00:00", "timezone-aware"),
    ("timestamp", "not a date", ""),
    ("source", "", "source is required"),
    ("event_type", "", "event_type is required"),
    ("severity_raw", "gigantic", "invalid severity"),
]

ALERT_DAMAGE = [
    ("timestamp", "2026-06-26T10:00:30", "timezone-aware"),
    ("rule_id", "", "rule_id is required"),
    ("rule_name", "", "rule_name is required"),
    ("mitre_technique", "XYZ", "invalid MITRE"),
]


@pytest.fixture
def db():
    connection = connect(":memory:")
    yield connection
    connection.close()


def make_event(event_id, seconds=0, **overrides):
    base = dict(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source="login_failure_detector",
        event_type="auth_failure",
        src_ip="185.23.44.10",
        user="admin",
        raw_data="original line",
    )
    base.update(overrides)
    return Event(**base)


def make_alert(alert_id, event_ids, seconds=30, **overrides):
    base = dict(
        alert_id=alert_id,
        rule_id="R002",
        rule_name="Brute force",
        severity="medium",
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        description="5 failed logins",
        event_ids=tuple(event_ids),
        mitre_technique="T1110.001",
    )
    base.update(overrides)
    return Alert(**base)


def raw_event(connection, event_id="e1", **overrides):
    values = dict(
        event_id=event_id,
        timestamp="2026-06-26T10:00:00+00:00",
        source="login_failure_detector",
        event_type="auth_failure",
        src_ip="185.23.44.10",
        dest_ip=None,
        dest_port=None,
        user="admin",
        severity_raw=None,
        raw_data="original line",
    )
    values.update(overrides)
    connection.execute(
        "INSERT INTO events (event_id, timestamp, source, event_type, src_ip, "
        "dest_ip, dest_port, user, severity_raw, raw_data) "
        "VALUES (:event_id, :timestamp, :source, :event_type, :src_ip, "
        ":dest_ip, :dest_port, :user, :severity_raw, :raw_data)",
        values,
    )


def raw_alert(connection, alert_id="a1", **overrides):
    values = dict(
        alert_id=alert_id,
        rule_id="R002",
        rule_name="Brute force",
        severity="medium",
        timestamp="2026-06-26T10:00:30+00:00",
        description="5 failed logins",
        mitre_technique="T1110.001",
    )
    values.update(overrides)
    connection.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_name, severity, timestamp, "
        "description, mitre_technique) "
        "VALUES (:alert_id, :rule_id, :rule_name, :severity, :timestamp, "
        ":description, :mitre_technique)",
        values,
    )


def raw_link(connection, alert_id, event_id, position=0):
    connection.execute(
        "INSERT INTO alert_events (alert_id, event_id, position) VALUES (?, ?, ?)",
        (alert_id, event_id, position),
    )


def counts(connection):
    return tuple(
        connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("events", "alerts", "alert_events")
    )


def event_ids(events):
    return [event.event_id for event in events]


def alert_ids(alerts):
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
    return events, run_rules(load_rules(RULES_PATH), events)


def test_parse_utc_reads_the_stored_text():
    moment = parse_utc("2026-06-26T10:00:00+00:00")
    assert moment == BASE_TIME
    assert moment.tzinfo is not None


def test_empty_database_returns_nothing(db):
    assert load_events(db) == []
    assert load_alerts(db) == []


def test_event_round_trip(db):
    event = make_event("e1", dest_ip="127.0.0.1", dest_port=445, severity_raw="high")
    save_run(db, [event], [])
    assert load_events(db) == [event]


def test_event_with_missing_values_round_trips(db):
    event = make_event("e1", src_ip=None, user=None)
    save_run(db, [event], [])
    assert load_events(db) == [event]


def test_alert_round_trip(db):
    events = [make_event("e1"), make_event("e2", 1)]
    alert = make_alert("a1", ["e1", "e2"])
    save_run(db, events, [alert])
    assert load_alerts(db) == [alert]


def test_alert_without_mitre_round_trips(db):
    alert = make_alert("a1", ["e1"], mitre_technique=None)
    save_run(db, [make_event("e1")], [alert])
    assert load_alerts(db) == [alert]


def test_loaded_times_are_timezone_aware_utc(db):
    save_run(db, [make_event("e1")], [make_alert("a1", ["e1"])])
    assert load_events(db)[0].timestamp.utcoffset() == timedelta(0)
    assert load_alerts(db)[0].timestamp.utcoffset() == timedelta(0)


def test_other_time_zones_come_back_as_the_same_moment(db):
    argentina = timezone(timedelta(hours=-3))
    moment = datetime(2026, 6, 26, 7, 0, 0, tzinfo=argentina)
    save_run(db, [make_event("e1", timestamp=moment)], [])
    loaded = load_events(db)[0]
    assert loaded.timestamp == moment
    assert loaded.timestamp.utcoffset() == timedelta(0)


def test_events_are_returned_in_time_order(db):
    late, early, mid = make_event("late", 10), make_event("early", 0), make_event("mid", 5)
    save_run(db, [late, early, mid], [])
    assert event_ids(load_events(db)) == ["early", "mid", "late"]


def test_events_with_the_same_time_keep_the_saving_order(db):
    save_run(db, [make_event("zzz", 0), make_event("aaa", 0)], [])
    assert event_ids(load_events(db)) == ["zzz", "aaa"]


def test_alerts_are_returned_in_time_order(db):
    late = make_alert("late", ["e1"], seconds=40)
    early = make_alert("early", ["e1"], seconds=20)
    save_run(db, [make_event("e1")], [late, early])
    assert alert_ids(load_alerts(db)) == ["early", "late"]


def test_alerts_with_the_same_time_keep_the_saving_order(db):
    first = make_alert("zzz", ["e1"])
    second = make_alert("aaa", ["e1"])
    save_run(db, [make_event("e1")], [first, second])
    assert alert_ids(load_alerts(db)) == ["zzz", "aaa"]


def test_evidence_keeps_the_order_of_the_alert(db):
    events = [make_event("e1", 0), make_event("e2", 1), make_event("e3", 2)]
    save_run(db, events, [make_alert("a1", ["e3", "e1", "e2"])])
    assert load_alerts(db)[0].event_ids == ("e3", "e1", "e2")


def test_each_alert_gets_only_its_own_evidence(db):
    events = [make_event(f"e{number}", number) for number in range(1, 5)]
    first = make_alert("a1", ["e1", "e2"], seconds=30)
    second = make_alert("a2", ["e2", "e3", "e4"], seconds=31)
    save_run(db, events, [first, second])
    loaded = {alert.alert_id: alert for alert in load_alerts(db)}
    assert loaded["a1"].event_ids == ("e1", "e2")
    assert loaded["a2"].event_ids == ("e2", "e3", "e4")


@pytest.mark.parametrize("hostile", HOSTILE_VALUES)
def test_hostile_values_round_trip(db, hostile):
    event = make_event("e1", user=hostile, raw_data=hostile)
    alert = make_alert("a1", ["e1"], description=hostile, rule_name=hostile)
    save_run(db, [event], [alert])
    assert load_events(db) == [event]
    assert load_alerts(db) == [alert]


def test_data_survives_reopening_the_database_file(tmp_path):
    path = tmp_path / "siem.db"
    events = [make_event("e1"), make_event("e2", 1)]
    alerts = [make_alert("a1", ["e1", "e2"])]
    first = connect(path)
    save_run(first, events, alerts)
    first.close()
    second = connect(path)
    assert load_events(second) == events
    assert load_alerts(second) == alerts
    second.close()


def test_loading_does_not_change_the_database(db):
    save_run(db, [make_event("e1")], [make_alert("a1", ["e1"])])
    before = counts(db)
    load_events(db)
    load_alerts(db)
    assert counts(db) == before


def test_a_real_analysis_round_trips(db, tmp_path):
    events, alerts = analyze(tmp_path, "run", LOG_WITH_COMPROMISE, with_scan=True)
    assert len(events) == 15
    assert len(alerts) == 5
    save_run(db, events, alerts)
    assert load_events(db) == events
    assert load_alerts(db) == alerts


def test_a_growing_log_loads_everything(db, tmp_path):
    first = analyze(tmp_path, "first", FIVE_FAILURES)
    second = analyze(tmp_path, "second", FIVE_FAILURES_THEN_SUCCESS)
    save_run(db, *first)
    save_run(db, *second)
    assert len(load_events(db)) == 6
    assert len(load_alerts(db)) == 2
    assert load_events(db) == second[0]
    assert load_alerts(db) == second[1]


@pytest.mark.parametrize(
    "field, value, message",
    EVENT_DAMAGE,
    ids=["naive-timestamp", "garbage-timestamp", "empty-source", "empty-type", "bad-severity"],
)
def test_a_damaged_event_is_rejected_when_read(db, field, value, message):
    raw_event(db, "e1", **{field: value})
    with pytest.raises(ValueError) as info:
        load_events(db)
    text = str(info.value)
    assert "event e1 in the database is invalid" in text
    assert message in text


@pytest.mark.parametrize(
    "field, value, message",
    ALERT_DAMAGE,
    ids=["naive-timestamp", "empty-rule-id", "empty-rule-name", "bad-mitre"],
)
def test_a_damaged_alert_is_rejected_when_read(db, field, value, message):
    raw_event(db, "e1")
    raw_alert(db, "a1", **{field: value})
    raw_link(db, "a1", "e1")
    with pytest.raises(ValueError) as info:
        load_alerts(db)
    text = str(info.value)
    assert "alert a1 in the database is invalid" in text
    assert message in text


def test_an_alert_without_evidence_is_rejected_when_read(db):
    raw_event(db, "e1")
    raw_alert(db, "a1")
    with pytest.raises(ValueError) as info:
        load_alerts(db)
    assert "at least one event" in str(info.value)


def test_one_damaged_event_fails_the_whole_read_and_is_named(db):
    raw_event(db, "e1")
    raw_event(db, "e2", source="")
    raw_event(db, "e3")
    with pytest.raises(ValueError) as info:
        load_events(db)
    assert "event e2 in the database is invalid" in str(info.value)


def test_one_damaged_alert_fails_the_whole_read_and_is_named(db):
    raw_event(db, "e1")
    raw_alert(db, "a1")
    raw_link(db, "a1", "e1")
    raw_alert(db, "a2", rule_id="", timestamp="2026-06-26T10:00:31+00:00")
    raw_link(db, "a2", "e1")
    with pytest.raises(ValueError) as info:
        load_alerts(db)
    assert "alert a2 in the database is invalid" in str(info.value)