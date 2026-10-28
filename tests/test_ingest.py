import json

import pytest

from engine.ingest import ingest

FIRST_LINE = "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10"
SECOND_LINE = "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10"


def write_scan(path, completed, ports=(135, 445)):
    report = {
        "target": "127.0.0.1",
        "scan_duration": 1.0,
        "completed": completed,
        "open_ports": [
            {"port": port, "service": "TEST", "banner": "Not applicable"}
            for port in ports
        ],
    }
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def write_log(path, lines):
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def test_events_from_both_sources_are_interleaved_by_time(tmp_path):
    scan = write_scan(tmp_path / "scan.json", "2026-06-26 10:01:16")
    log = write_log(tmp_path / "auth.log", [FIRST_LINE, SECOND_LINE])
    events, rejected = ingest(scan_report_paths=[scan], auth_log_paths=[log])
    assert rejected == []
    assert [event.source for event in events] == [
        "login_failure_detector",
        "network_scanner",
        "network_scanner",
        "login_failure_detector",
    ]


def test_events_are_sorted_even_if_the_log_is_out_of_order(tmp_path):
    log = write_log(tmp_path / "auth.log", [SECOND_LINE, FIRST_LINE])
    events, rejected = ingest(auth_log_paths=[log])
    timestamps = [event.timestamp for event in events]
    assert timestamps == sorted(timestamps)
    assert len(events) == 2


def test_same_timestamp_keeps_original_order(tmp_path):
    scan = write_scan(tmp_path / "scan.json", "2026-06-26 10:01:16", ports=(445, 135))
    events, rejected = ingest(scan_report_paths=[scan])
    assert [event.dest_port for event in events] == [445, 135]


def test_rejected_log_lines_include_the_file_name(tmp_path):
    log = write_log(tmp_path / "auth.log", [FIRST_LINE, "this is not a log line"])
    events, rejected = ingest(auth_log_paths=[log])
    assert len(events) == 1
    assert len(rejected) == 1
    assert rejected[0].startswith("auth.log: line 2")


def test_broken_scan_report_is_rejected_but_logs_are_still_ingested(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{ not json", encoding="utf-8")
    log = write_log(tmp_path / "auth.log", [FIRST_LINE])
    events, rejected = ingest(scan_report_paths=[broken], auth_log_paths=[log])
    assert len(events) == 1
    assert len(rejected) == 1
    assert rejected[0].startswith("broken.json:")


def test_multiple_files_per_source_are_all_read(tmp_path):
    first = write_scan(tmp_path / "scan_1.json", "2026-06-26 10:00:00")
    second = write_scan(tmp_path / "scan_2.json", "2026-06-26 11:00:00")
    events, rejected = ingest(scan_report_paths=[first, second])
    assert len(events) == 4
    assert rejected == []


def test_no_inputs_returns_nothing():
    assert ingest() == ([], [])


def test_missing_file_is_not_hidden(tmp_path):
    with pytest.raises(FileNotFoundError):
        ingest(auth_log_paths=[tmp_path / "does_not_exist.log"])