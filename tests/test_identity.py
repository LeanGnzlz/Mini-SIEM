import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from engine.event import Event, AUTH_FAILURE, AUTH_SUCCESS
from engine.identity import assign_stable_ids, content_text, stable_event_id
from engine.ingest import ingest

BASE_TIME = datetime(2026, 6, 26, 10, 0, 0, tzinfo=timezone.utc)
HEX_DIGITS = set("0123456789abcdef")

LINE_A = "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10"
LINE_B = "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10"
LINE_C = "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10"

SCAN_REPORT = {
    "target": "127.0.0.1",
    "scan_duration": 1.0,
    "completed": "2026-06-26 10:00:00",
    "open_ports": [
        {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
        {"port": 445, "service": "SMB", "banner": "Not applicable"},
    ],
}


def make_event(seconds=0, **overrides):
    base = dict(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source="login_failure_detector",
        event_type=AUTH_FAILURE,
        src_ip="185.23.44.10",
        user="admin",
        raw_data="original line",
    )
    base.update(overrides)
    return Event(**base)


def ids(events):
    return [event.event_id for event in events]


def write_log(path, lines):
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def write_scan(path):
    path.write_text(json.dumps(SCAN_REPORT), encoding="utf-8")
    return str(path)


def test_stable_event_id_is_a_sha256_hex_digest():
    value = stable_event_id("some content", 1)
    assert len(value) == 64
    assert set(value) <= HEX_DIGITS


def test_same_content_and_occurrence_give_the_same_id():
    assert stable_event_id("some content", 1) == stable_event_id("some content", 1)


def test_different_occurrence_changes_the_id():
    assert stable_event_id("some content", 1) != stable_event_id("some content", 2)


def test_different_content_changes_the_id():
    assert stable_event_id("some content", 1) != stable_event_id("other content", 1)


def test_content_text_ignores_the_event_id():
    assert content_text(make_event()) == content_text(make_event())


@pytest.mark.parametrize(
    "override",
    [
        {"source": "network_scanner"},
        {"event_type": AUTH_SUCCESS},
        {"src_ip": "10.0.0.50"},
        {"dest_ip": "127.0.0.1"},
        {"dest_port": 445},
        {"user": "maria"},
        {"severity_raw": "high"},
        {"raw_data": "another line"},
        {"timestamp": BASE_TIME + timedelta(seconds=1)},
    ],
    ids=[
        "source",
        "event_type",
        "src_ip",
        "dest_ip",
        "dest_port",
        "user",
        "severity_raw",
        "raw_data",
        "timestamp",
    ],
)
def test_every_field_is_part_of_the_content(override):
    assert content_text(make_event(**override)) != content_text(make_event())


def test_the_same_moment_in_another_time_zone_gives_the_same_content():
    argentina = timezone(timedelta(hours=-3))
    same_moment = datetime(2026, 6, 26, 7, 0, 0, tzinfo=argentina)
    assert content_text(make_event(timestamp=same_moment)) == content_text(make_event())


def test_separator_characters_cannot_make_two_events_collide():
    first = make_event(source="a|b", event_type="c")
    second = make_event(source="a", event_type="b|c")
    assert content_text(first) != content_text(second)


def test_missing_value_and_empty_text_are_different():
    assert content_text(make_event(user=None)) != content_text(make_event(user=""))


def test_assign_replaces_the_random_ids():
    events = [make_event()]
    result = assign_stable_ids(events)
    assert result[0].event_id != events[0].event_id
    assert len(result[0].event_id) == 64


def test_original_events_are_not_modified():
    original = make_event()
    before = original.event_id
    assign_stable_ids([original])
    assert original.event_id == before


def test_all_other_fields_are_preserved():
    original = make_event(dest_port=445, severity_raw="high")
    result = assign_stable_ids([original])[0]
    assert replace(result, event_id=original.event_id) == original


def test_the_same_events_get_the_same_ids_every_time():
    first = assign_stable_ids([make_event(0), make_event(5)])
    second = assign_stable_ids([make_event(0), make_event(5)])
    assert ids(first) == ids(second)


def test_identical_events_get_different_ids():
    result = assign_stable_ids([make_event(0), make_event(0)])
    assert len(set(ids(result))) == 2


def test_identical_events_ids_are_repeatable():
    first = assign_stable_ids([make_event(0), make_event(0)])
    second = assign_stable_ids([make_event(0), make_event(0)])
    assert ids(first) == ids(second)


def test_a_longer_list_keeps_the_ids_of_the_first_events():
    first = assign_stable_ids([make_event(0), make_event(0), make_event(5)])
    longer = assign_stable_ids(
        [make_event(0), make_event(0), make_event(5), make_event(9)]
    )
    assert ids(longer)[:3] == ids(first)


def test_empty_list():
    assert assign_stable_ids([]) == []


def test_ingesting_the_same_file_twice_gives_the_same_ids(tmp_path):
    log = write_log(tmp_path / "auth.log", [LINE_A, LINE_B, LINE_C])
    first, rejected = ingest(auth_log_paths=[log])
    second, rejected_again = ingest(auth_log_paths=[log])
    assert rejected == [] and rejected_again == []
    assert ids(first) == ids(second)
    assert len(set(ids(first))) == 3


def test_a_growing_log_keeps_the_ids_of_its_old_lines(tmp_path):
    path = tmp_path / "auth.log"
    first, rejected = ingest(auth_log_paths=[write_log(path, [LINE_A, LINE_B])])
    second, rejected_again = ingest(auth_log_paths=[write_log(path, [LINE_A, LINE_B, LINE_C])])
    assert len(second) == 3
    assert ids(second)[:2] == ids(first)


def test_identical_log_lines_are_kept_as_separate_events(tmp_path):
    log = write_log(tmp_path / "auth.log", [LINE_A, LINE_A, LINE_B])
    events, rejected = ingest(auth_log_paths=[log])
    assert rejected == []
    assert len(events) == 3
    assert len(set(ids(events))) == 3


def test_ids_do_not_depend_on_the_file_name(tmp_path):
    first_log = write_log(tmp_path / "first.log", [LINE_A, LINE_B])
    second_log = write_log(tmp_path / "second.log", [LINE_A, LINE_B])
    first, rejected = ingest(auth_log_paths=[first_log])
    second, rejected_again = ingest(auth_log_paths=[second_log])
    assert ids(first) == ids(second)


def test_the_same_event_in_two_files_is_ingested_once(tmp_path):
    first = write_log(tmp_path / "a.log", [LINE_A, LINE_B])
    second = write_log(tmp_path / "b.log", [LINE_B, LINE_C])
    events, rejected = ingest(auth_log_paths=[first, second])
    assert len(events) == 3
    assert len(rejected) == 1
    assert rejected[0].startswith("b.log: 1 duplicate event(s) skipped")


def test_a_file_given_twice_is_ingested_once(tmp_path):
    log = write_log(tmp_path / "auth.log", [LINE_A, LINE_B, LINE_C])
    events, rejected = ingest(auth_log_paths=[log, log])
    assert len(events) == 3
    assert len(rejected) == 1
    assert rejected[0].startswith("auth.log: 3 duplicate event(s) skipped")


def test_identical_scan_reports_are_ingested_once(tmp_path):
    first = write_scan(tmp_path / "scan_1.json")
    second = write_scan(tmp_path / "scan_2.json")
    events, rejected = ingest(scan_report_paths=[first, second])
    assert len(events) == 2
    assert len(rejected) == 1
    assert rejected[0].startswith("scan_2.json: 2 duplicate event(s) skipped")


def test_every_ingested_event_has_a_unique_stable_id(tmp_path):
    scan = write_scan(tmp_path / "scan.json")
    log = write_log(tmp_path / "auth.log", [LINE_A, LINE_B, LINE_C])
    events, rejected = ingest(scan_report_paths=[scan], auth_log_paths=[log])
    assert len(events) == 5
    assert len(set(ids(events))) == 5
    assert all(len(value) == 64 for value in ids(events))