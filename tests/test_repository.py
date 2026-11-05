import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.alert import Alert
from engine.evaluator import run_rules
from engine.event import Event
from engine.ingest import ingest
from engine.rule import load_rules
from storage.db import connect
from storage.repository import SaveResult, save_run, utc_text

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


def make_alert(alert_id, event_ids, **overrides):
    base = dict(
        alert_id=alert_id,
        rule_id="R002",
        rule_name="Brute force",
        severity="medium",
        timestamp=BASE_TIME + timedelta(seconds=30),
        description="5 failed logins",
        event_ids=tuple(event_ids),
        mitre_technique="T1110.001",
    )
    base.update(overrides)
    return Alert(**base)


def count(connection, table):
    return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def counts(connection):
    return (
        count(connection, "events"),
        count(connection, "alerts"),
        count(connection, "alert_events"),
    )


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


def test_utc_text_keeps_utc():
    assert utc_text(BASE_TIME) == "2026-06-26T10:00:00+00:00"


def test_utc_text_converts_other_time_zones():
    argentina = timezone(timedelta(hours=-3))
    moment = datetime(2026, 6, 26, 7, 0, 0, tzinfo=argentina)
    assert utc_text(moment) == "2026-06-26T10:00:00+00:00"


def test_saving_nothing_changes_nothing(db):
    result = save_run(db, [], [])
    assert result == SaveResult(0, 0, 0, 0)
    assert counts(db) == (0, 0, 0)


def test_first_save_counts_everything_as_new(db):
    events = [make_event("e1"), make_event("e2", 1)]
    result = save_run(db, events, [make_alert("a1", ["e1", "e2"])])
    assert result == SaveResult(
        events_new=2, events_existing=0, alerts_new=1, alerts_existing=0
    )
    assert counts(db) == (2, 1, 2)


def test_event_fields_are_stored(db):
    event = make_event("e1", dest_ip="127.0.0.1", dest_port=445, severity_raw="high")
    save_run(db, [event], [])
    row = db.execute("SELECT * FROM events WHERE event_id = ?", ("e1",)).fetchone()
    assert row["timestamp"] == "2026-06-26T10:00:00+00:00"
    assert row["source"] == "login_failure_detector"
    assert row["event_type"] == "auth_failure"
    assert row["src_ip"] == "185.23.44.10"
    assert row["dest_ip"] == "127.0.0.1"
    assert row["dest_port"] == 445
    assert row["user"] == "admin"
    assert row["severity_raw"] == "high"
    assert row["raw_data"] == "original line"


def test_missing_values_are_stored_as_null(db):
    save_run(db, [make_event("e1", src_ip=None, user=None)], [])
    row = db.execute("SELECT src_ip, user, dest_port FROM events").fetchone()
    assert row["src_ip"] is None
    assert row["user"] is None
    assert row["dest_port"] is None


def test_other_time_zones_are_stored_in_utc(db):
    argentina = timezone(timedelta(hours=-3))
    moment = datetime(2026, 6, 26, 7, 0, 0, tzinfo=argentina)
    save_run(db, [make_event("e1", timestamp=moment)], [])
    stored = db.execute("SELECT timestamp FROM events").fetchone()["timestamp"]
    assert stored == "2026-06-26T10:00:00+00:00"


def test_alert_fields_are_stored(db):
    save_run(db, [make_event("e1")], [make_alert("a1", ["e1"])])
    row = db.execute("SELECT * FROM alerts WHERE alert_id = ?", ("a1",)).fetchone()
    assert row["rule_id"] == "R002"
    assert row["rule_name"] == "Brute force"
    assert row["severity"] == "medium"
    assert row["timestamp"] == "2026-06-26T10:00:30+00:00"
    assert row["description"] == "5 failed logins"
    assert row["mitre_technique"] == "T1110.001"


def test_alert_without_mitre_is_stored_as_null(db):
    alert = make_alert("a1", ["e1"], mitre_technique=None)
    save_run(db, [make_event("e1")], [alert])
    stored = db.execute("SELECT mitre_technique FROM alerts").fetchone()
    assert stored["mitre_technique"] is None


def test_evidence_keeps_the_order_of_the_alert(db):
    events = [make_event("e1", 0), make_event("e2", 1), make_event("e3", 2)]
    save_run(db, events, [make_alert("a1", ["e3", "e1", "e2"])])
    rows = db.execute(
        "SELECT event_id, position FROM alert_events "
        "WHERE alert_id = ? ORDER BY position",
        ("a1",),
    ).fetchall()
    assert [(row["event_id"], row["position"]) for row in rows] == [
        ("e3", 0),
        ("e1", 1),
        ("e2", 2),
    ]


def test_saving_the_same_run_twice_does_not_duplicate(db):
    events = [make_event("e1"), make_event("e2", 1)]
    alerts = [make_alert("a1", ["e1", "e2"])]
    save_run(db, events, alerts)
    result = save_run(db, events, alerts)
    assert result == SaveResult(
        events_new=0, events_existing=2, alerts_new=0, alerts_existing=1
    )
    assert counts(db) == (2, 1, 2)


def test_a_second_run_counts_only_what_is_new(db):
    e1, e2, e3 = make_event("e1"), make_event("e2", 1), make_event("e3", 2)
    a1 = make_alert("a1", ["e1", "e2"])
    a2 = make_alert("a2", ["e2", "e3"], rule_id="R004")
    save_run(db, [e1, e2], [a1])
    result = save_run(db, [e1, e2, e3], [a1, a2])
    assert result == SaveResult(
        events_new=1, events_existing=2, alerts_new=1, alerts_existing=1
    )
    assert counts(db) == (3, 2, 4)


def test_the_same_event_twice_in_one_run_is_saved_once(db):
    event = make_event("e1")
    result = save_run(db, [event, event], [])
    assert result == SaveResult(
        events_new=1, events_existing=1, alerts_new=0, alerts_existing=0
    )
    assert counts(db) == (1, 0, 0)


def test_the_same_alert_twice_in_one_run_is_saved_once(db):
    events = [make_event("e1"), make_event("e2", 1)]
    alert = make_alert("a1", ["e1", "e2"])
    result = save_run(db, events, [alert, alert])
    assert result == SaveResult(
        events_new=2, events_existing=0, alerts_new=1, alerts_existing=1
    )
    assert counts(db) == (2, 1, 2)


def test_an_existing_alert_keeps_its_first_version(db):
    events = [make_event("e1")]
    first = make_alert("a1", ["e1"], severity="low", description="first")
    second = make_alert("a1", ["e1"], severity="high", description="second")
    save_run(db, events, [first])
    save_run(db, events, [second])
    row = db.execute("SELECT severity, description FROM alerts").fetchone()
    assert row["severity"] == "low"
    assert row["description"] == "first"


def test_unknown_evidence_is_rejected_and_everything_is_rolled_back(db):
    events = [make_event("e1"), make_event("e2", 1)]
    alerts = [make_alert("a1", ["e1"]), make_alert("a2", ["e1", "missing"])]
    with pytest.raises(sqlite3.IntegrityError):
        save_run(db, events, alerts)
    assert counts(db) == (0, 0, 0)


def test_a_failed_run_keeps_the_data_of_previous_runs(db):
    save_run(db, [make_event("e1")], [make_alert("a1", ["e1"])])
    with pytest.raises(sqlite3.IntegrityError):
        save_run(db, [make_event("e2", 1)], [make_alert("a2", ["missing"])])
    assert counts(db) == (1, 1, 1)
    assert db.execute("SELECT event_id FROM events").fetchone()["event_id"] == "e1"


def test_the_connection_is_usable_after_a_failed_run(db):
    with pytest.raises(sqlite3.IntegrityError):
        save_run(db, [make_event("e1")], [make_alert("a1", ["missing"])])
    result = save_run(db, [make_event("e1")], [make_alert("a1", ["e1"])])
    assert result == SaveResult(
        events_new=1, events_existing=0, alerts_new=1, alerts_existing=0
    )
    assert counts(db) == (1, 1, 1)


@pytest.mark.parametrize("hostile", HOSTILE_VALUES)
def test_hostile_values_are_stored_as_plain_text(db, hostile):
    event = make_event("e1", user=hostile, raw_data=hostile)
    alert = make_alert("a1", ["e1"], description=hostile, rule_name=hostile)
    save_run(db, [event], [alert])
    tables = {
        row["name"]
        for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {"events", "alerts", "alert_events"} <= tables
    stored_event = db.execute("SELECT user, raw_data FROM events").fetchone()
    stored_alert = db.execute("SELECT description, rule_name FROM alerts").fetchone()
    assert stored_event["user"] == hostile
    assert stored_event["raw_data"] == hostile
    assert stored_alert["description"] == hostile
    assert stored_alert["rule_name"] == hostile


def test_a_real_analysis_is_saved(db, tmp_path):
    events, alerts = analyze(tmp_path, "run", LOG_WITH_COMPROMISE, with_scan=True)
    result = save_run(db, events, alerts)
    assert result == SaveResult(
        events_new=15, events_existing=0, alerts_new=5, alerts_existing=0
    )
    assert counts(db) == (15, 5, 22)


def test_analyzing_the_same_files_again_adds_nothing(db, tmp_path):
    first = analyze(tmp_path, "first", LOG_WITH_COMPROMISE, with_scan=True)
    second = analyze(tmp_path, "second", LOG_WITH_COMPROMISE, with_scan=True)
    save_run(db, *first)
    result = save_run(db, *second)
    assert result == SaveResult(
        events_new=0, events_existing=15, alerts_new=0, alerts_existing=5
    )
    assert counts(db) == (15, 5, 22)


def test_a_growing_log_only_adds_what_is_new(db, tmp_path):
    first = analyze(tmp_path, "first", FIVE_FAILURES)
    second = analyze(tmp_path, "second", FIVE_FAILURES_THEN_SUCCESS)
    save_run(db, *first)
    result = save_run(db, *second)
    assert result == SaveResult(
        events_new=1, events_existing=5, alerts_new=1, alerts_existing=1
    )
    assert counts(db) == (6, 2, 11)


def test_a_hostile_username_in_a_real_log_line_is_stored_as_text(db, tmp_path):
    hostile = "x'; DROP TABLE events; --"
    line = f"2026-06-26 10:01:15 | FAILED_LOGIN | {hostile} | 185.23.44.10"
    events, alerts = analyze(tmp_path, "run", [line])
    save_run(db, events, alerts)
    assert count(db, "events") == 1
    assert db.execute("SELECT user FROM events").fetchone()["user"] == hostile