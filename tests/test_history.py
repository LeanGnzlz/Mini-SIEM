from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.alert import Alert
from engine.evaluator import run_rules
from engine.event import Event
from engine.ingest import ingest, merge_events
from engine.rule import load_rules
from storage.db import connect
from storage.repository import (
    load_alert_ids,
    load_alerts,
    load_events,
    save_run,
)

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"
BASE_TIME = datetime(2026, 6, 26, 10, 0, 0, tzinfo=timezone.utc)

FIVE_FAILURES = [
    "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:22 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:25 | FAILED_LOGIN | admin | 185.23.44.10",
]

SUCCESS_LINE = "2026-06-26 10:02:00 | SUCCESS_LOGIN | admin | 185.23.44.10"

FIVE_FAILURES_THEN_SUCCESS = FIVE_FAILURES + [SUCCESS_LINE]


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


def make_alert(alert_id, event_ids, seconds=30):
    return Alert(
        alert_id=alert_id,
        rule_id="R002",
        rule_name="Brute force",
        severity="medium",
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        description="5 failed logins",
        event_ids=tuple(event_ids),
        mitre_technique="T1110.001",
    )


def ids(items):
    return [getattr(item, "event_id", None) or item.alert_id for item in items]


def rule_ids(alerts):
    return [alert.rule_id for alert in alerts]


def counts(connection):
    return tuple(
        connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("events", "alerts", "alert_events")
    )


def ingest_file(tmp_path, name, lines):
    folder = tmp_path / name
    folder.mkdir()
    log = folder / "auth.log"
    log.write_text("\n".join(lines), encoding="utf-8")
    events, rejected = ingest(auth_log_paths=[str(log)])
    assert rejected == []
    return events


def run_cycle(db, tmp_path, name, lines):
    new_events = ingest_file(tmp_path, name, lines)
    events = merge_events(load_events(db), new_events)
    alerts = run_rules(load_rules(RULES_PATH), events)
    known = load_alert_ids(db)
    fresh = [alert for alert in alerts if alert.alert_id not in known]
    save_run(db, new_events, alerts)
    return events, alerts, fresh


def test_merging_nothing_gives_nothing():
    assert merge_events([], []) == []


def test_without_history_the_new_events_are_returned_sorted():
    late, early = make_event("late", 10), make_event("early", 0)
    assert ids(merge_events([], [late, early])) == ["early", "late"]


def test_without_new_events_the_history_is_returned():
    history = [make_event("e1", 0), make_event("e2", 5)]
    assert merge_events(history, []) == history


def test_the_result_is_a_new_list():
    history = [make_event("e1")]
    assert merge_events(history, []) is not history


def test_an_event_in_both_lists_is_kept_once():
    result = merge_events([make_event("e1", 0)], [make_event("e1", 0), make_event("e2", 5)])
    assert ids(result) == ["e1", "e2"]


def test_the_history_version_wins():
    old = make_event("e1", 0, raw_data="from history")
    new = make_event("e1", 0, raw_data="from this run")
    result = merge_events([old], [new])
    assert len(result) == 1
    assert result[0].raw_data == "from history"


def test_repeated_events_inside_the_new_list_are_kept_once():
    event = make_event("e1")
    assert ids(merge_events([], [event, event])) == ["e1"]


def test_events_are_sorted_across_both_lists():
    history = [make_event("h1", 0), make_event("h2", 20)]
    new = [make_event("n1", 10), make_event("n2", 30)]
    assert ids(merge_events(history, new)) == ["h1", "n1", "h2", "n2"]


def test_events_with_the_same_time_put_the_history_first():
    history = [make_event("zzz", 5)]
    new = [make_event("aaa", 5)]
    assert ids(merge_events(history, new)) == ["zzz", "aaa"]


def test_the_input_lists_are_not_modified():
    history = [make_event("h1", 20)]
    new = [make_event("n1", 0), make_event("h1", 20)]
    merge_events(history, new)
    assert ids(history) == ["h1"]
    assert ids(new) == ["n1", "h1"]


def test_an_empty_database_knows_no_alerts(db):
    assert load_alert_ids(db) == set()


def test_saved_alert_ids_are_returned(db):
    events = [make_event("e1"), make_event("e2", 1)]
    alerts = [make_alert("a1", ["e1"]), make_alert("a2", ["e2"], seconds=31)]
    save_run(db, events, alerts)
    assert load_alert_ids(db) == {"a1", "a2"}


def test_event_ids_are_not_mixed_in(db):
    save_run(db, [make_event("e1")], [make_alert("a1", ["e1"])])
    assert "e1" not in load_alert_ids(db)


def test_the_result_is_a_set_of_text(db):
    save_run(db, [make_event("e1")], [make_alert("a1", ["e1"])])
    result = load_alert_ids(db)
    assert isinstance(result, set)
    assert all(isinstance(item, str) for item in result)


def test_looking_up_the_ids_does_not_change_the_database(db):
    save_run(db, [make_event("e1")], [make_alert("a1", ["e1"])])
    before = counts(db)
    load_alert_ids(db)
    assert counts(db) == before


def test_the_first_run_finds_everything_new(db, tmp_path):
    events, alerts, fresh = run_cycle(db, tmp_path, "day1", FIVE_FAILURES)
    assert len(events) == 5
    assert rule_ids(alerts) == ["R002"]
    assert ids(fresh) == ids(alerts)
    assert counts(db) == (5, 1, 5)


def test_repeating_the_same_file_finds_nothing_new(db, tmp_path):
    run_cycle(db, tmp_path, "day1", FIVE_FAILURES)
    events, alerts, fresh = run_cycle(db, tmp_path, "day2", FIVE_FAILURES)
    assert len(events) == 5
    assert rule_ids(alerts) == ["R002"]
    assert fresh == []
    assert counts(db) == (5, 1, 5)


def test_a_growing_log_marks_only_the_new_alert(db, tmp_path):
    run_cycle(db, tmp_path, "day1", FIVE_FAILURES)
    events, alerts, fresh = run_cycle(db, tmp_path, "day2", FIVE_FAILURES_THEN_SUCCESS)
    assert len(events) == 6
    assert rule_ids(alerts) == ["R002", "R003"]
    assert rule_ids(fresh) == ["R003"]
    assert counts(db) == (6, 2, 11)


def test_a_pattern_across_two_files_needs_the_history(db, tmp_path):
    run_cycle(db, tmp_path, "day1", FIVE_FAILURES)
    events, alerts, fresh = run_cycle(db, tmp_path, "day2", [SUCCESS_LINE])
    assert rule_ids(alerts) == ["R002", "R003"]
    assert rule_ids(fresh) == ["R003"]
    assert len(fresh[0].event_ids) == 6
    assert counts(db) == (6, 2, 11)


def test_the_new_file_alone_triggers_nothing(tmp_path):
    new_events = ingest_file(tmp_path, "day2", [SUCCESS_LINE])
    assert run_rules(load_rules(RULES_PATH), new_events) == []


def test_repeating_the_pattern_file_finds_nothing_new(db, tmp_path):
    run_cycle(db, tmp_path, "day1", FIVE_FAILURES)
    run_cycle(db, tmp_path, "day2", [SUCCESS_LINE])
    events, alerts, fresh = run_cycle(db, tmp_path, "day3", [SUCCESS_LINE])
    assert len(events) == 6
    assert rule_ids(alerts) == ["R002", "R003"]
    assert fresh == []
    assert counts(db) == (6, 2, 11)


def test_the_database_matches_the_last_run(db, tmp_path):
    run_cycle(db, tmp_path, "day1", FIVE_FAILURES)
    events, alerts, fresh = run_cycle(db, tmp_path, "day2", FIVE_FAILURES_THEN_SUCCESS)
    assert load_events(db) == events
    assert load_alerts(db) == alerts